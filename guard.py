#!/usr/bin/env python3
"""The Outwit guard: vets every payment an AI agent proposes, on-chain.

Agents connect their Outwit vault and propose payments with a key that cannot
pay. The guard watches each connected vault, judges every pending proposal with
the firewall against the vault's on-chain payees, invoices and history (plus
any conversation the agent sent along), and calls `approve` or `reject` on the
vault, so each verdict and its reason are recorded on NEAR.

    python3 guard.py --config outwit.json      # guard API on :8787

HTTP API (also mounted by arena.py):
    POST /v1/connect   {"vault_id"}                       start guarding a vault (it must list us as a guard)
    POST /v1/context   {"ref", "vault_id", "context", "requester"?}
                       what led to a payment; sent before proposing, matched by the [ref:...] in its memo
    POST /v1/check     {"vault_id", "receiver_id", "amount_near" | "amount", "invoice_id"?, "context"?, "requester"?}
                       a dry run: the verdict a proposal would get, nothing on-chain
    GET  /v1/decisions?vault_id=...                       recent verdicts with their findings
    GET  /v1/health
"""
import argparse
import json
import os
import re
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import firewall
import vault as vaultlib

HERE = Path(__file__).resolve().parent
REF_RX = re.compile(r"\[ref:([A-Za-z0-9_-]{6,32})\]")
CONTEXT_WAIT_MS = 4000   # how long to wait for a proposal's context before judging without it


def strip_ref(memo):
    return REF_RX.sub("", memo or "").strip()


class Guard:
    def __init__(self, chain, account, key, vaults=(), log_path=None, open_vault=None):
        self.chain = chain
        self.account = account
        self.key = key
        self.open_vault = open_vault or (lambda vid: vaultlib.Vault(chain, vid))
        self.vaults = OrderedDict()
        self.lock = threading.RLock()
        self.run_lock = threading.Lock()
        self.contexts = OrderedDict()         # ref -> {"context", "requester", "vault_id", "t"}
        self.decisions = deque(maxlen=500)
        self.decided = set()                   # (vault_id, proposal id)
        self.log_path = log_path
        if log_path and Path(log_path).exists():
            for line in Path(log_path).read_text().splitlines():
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                self.decisions.append(d)
                self.decided.add((d["vault_id"], d["id"]))
        for vid in vaults:
            self.vaults[vid] = self.open_vault(vid)

    # ----- connecting vaults -----
    def connect(self, vault_id):
        v = self.open_vault(vault_id)
        cfg = v.config()
        if self.account not in cfg["guards"]:
            raise ValueError("%s does not list %s as a guard; call set_guards on the vault first" % (vault_id, self.account))
        with self.lock:
            self.vaults[vault_id] = v
        return {"vault_id": vault_id, "guard": self.account, "owner": cfg["owner"]}

    def add_context(self, ref, vault_id, context, requester=None):
        with self.lock:
            self.contexts[ref] = {"context": str(context or "")[:6000], "requester": requester, "vault_id": vault_id, "t": time.time()}
            while len(self.contexts) > 5000:
                self.contexts.popitem(last=False)

    # ----- judging -----
    def world(self, v):
        """The firewall's view of a vault, read from the chain."""
        cfg = v.config()
        invoices = [{"id": str(i["id"]), "vendor": i["payee"], "amount": i["amount"],
                     "status": i["status"].lower(), "memo": i["memo"]} for i in v.invoices(100)]
        paid = [(p["decided_ms"] / 1000, p["receiver_id"], int(p["amount"]))
                for p in v.proposals(100) if p["status"] == "Paid" and p.get("decided_ms")]
        return {"balance": int(cfg["available"]), "vendors": {p["account_id"]: p["label"] for p in v.payees()},
                "invoices": invoices, "recent": paid}

    def judge(self, v, receiver_id, amount, invoice_id=None, context="", requester=None, memo="", world=None):
        w = world or self.world(v)
        ctx = firewall.Context(v.id, w["balance"], vendors=w["vendors"], invoices=w["invoices"],
                               recent=w["recent"], requester=requester, untrusted="\n".join(x for x in (context, memo) if x))
        proposal = {"receiver_id": receiver_id, "actions": [{"type": "Transfer", "deposit": str(int(amount))}]}
        if invoice_id is not None:
            proposal["invoice"] = str(invoice_id)
        return firewall.check(proposal, ctx)

    def check(self, vault_id, receiver_id, amount, invoice_id=None, context="", requester=None):
        return self.judge(self.open_vault(vault_id), receiver_id, amount, invoice_id, context, requester)

    def decide(self, v, p):
        ref = (REF_RX.search(p.get("memo") or "") or [None, None])[1]
        with self.lock:
            c = self.contexts.get(ref) if ref else None
        memo = strip_ref(p.get("memo"))
        verdict = self.judge(v, p["receiver_id"], int(p["amount"]), p.get("invoice_id"),
                             (c or {}).get("context", ""), (c or {}).get("requester"), memo)
        rules = sorted({f["rule"].split(":")[0] for f in verdict["findings"] if f["severity"] in firewall.BLOCKING})
        if verdict["allow"]:
            reason = "Outwit: allowed. " + " ".join(verdict["explain"])
            res = v.approve(self.account, self.key, p["id"], reason)
        else:
            reason = "Outwit blocked [%s]: %s" % (", ".join(rules), verdict["summary"].replace("Blocked: ", "", 1))
            res = v.reject(self.account, self.key, p["id"], reason)
        record = {"vault_id": v.id, "id": p["id"], "agent": p["agent"], "receiver_id": p["receiver_id"],
                  "amount": p["amount"], "invoice_id": p.get("invoice_id"), "memo": memo,
                  "allow": verdict["allow"], "risk": verdict["risk"], "summary": verdict["summary"],
                  "explain": verdict["explain"], "findings": verdict["findings"], "rules": rules,
                  "had_context": bool(c), "ok": res.get("ok"), "error": res.get("error"),
                  "result": res.get("result"), "tx": res.get("tx"), "tx_url": self.chain.tx_url(res.get("tx")),
                  "t": time.time()}
        with self.lock:
            self.decided.add((v.id, p["id"]))
            self.decisions.append(record)
            if self.log_path:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(record) + "\n")
        print("[%s] %s #%d %-8s %s" % (time.strftime("%H:%M:%S"), v.id, p["id"], "APPROVED" if verdict["allow"] else "REJECTED",
                                       verdict["summary"][:100]), flush=True)
        return record

    def run_once(self):
        # The loop thread and in-process clients both call this; one at a time,
        # so a proposal is never decided twice.
        with self.run_lock:
            self._run_once()

    def _run_once(self):
        now_ms = time.time() * 1000
        with self.lock:
            vaults = list(self.vaults.values())
        for v in vaults:
            try:
                pending = v.pending()
            except Exception as e:  # one flaky vault must not stop the others
                print("guard: %s: %s" % (v.id, e), flush=True)
                continue
            for p in pending:
                if (v.id, p["id"]) in self.decided:
                    continue
                ref = (REF_RX.search(p.get("memo") or "") or [None, None])[1]
                with self.lock:
                    has_context = ref in self.contexts
                if ref and not has_context and now_ms - p["created_ms"] < CONTEXT_WAIT_MS:
                    continue
                self.decide(v, p)

    def loop(self, interval=1.5):
        while True:
            self.run_once()
            time.sleep(interval)

    def decisions_for(self, vault_id, limit=50):
        with self.lock:
            return [d for d in reversed(self.decisions) if d["vault_id"] == vault_id][:limit]


def route(guard, method, path, body):
    """The guard's HTTP API. Returns (status, json) or None when the path is not ours."""
    url = urlparse(path)
    if not url.path.startswith("/v1/"):
        return None
    try:
        if method == "GET" and url.path == "/v1/health":
            return 200, {"ok": True, "guard": guard.account, "vaults": list(guard.vaults)}
        if method == "GET" and url.path == "/v1/decisions":
            vid = (parse_qs(url.query).get("vault_id") or [""])[0]
            return 200, {"decisions": guard.decisions_for(vid)}
        if method != "POST":
            return 404, {"error": "not found"}
        if url.path == "/v1/connect":
            return 200, guard.connect(str(body["vault_id"]))
        if url.path == "/v1/context":
            ref = str(body.get("ref") or "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{6,32}", ref):
                return 400, {"error": "ref must be 6-32 letters, digits, _ or -"}
            guard.add_context(ref, str(body.get("vault_id") or ""), body.get("context"), body.get("requester"))
            return 200, {"ok": True}
        if url.path == "/v1/check":
            amount = int(body["amount"]) if body.get("amount") is not None else vaultlib.to_yocto(body.get("amount_near", 0))
            v = guard.check(str(body["vault_id"]), str(body["receiver_id"]).lower(), amount, body.get("invoice_id"),
                            str(body.get("context") or ""), body.get("requester"))
            return 200, v
    except (KeyError, ValueError, TypeError) as e:
        return 400, {"error": str(e)}
    except RuntimeError as e:
        return 502, {"error": "chain: %s" % e}
    return 404, {"error": "not found"}


def make_handler(guard):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Outwit-Guard/0.1"

        def log_message(self, fmt, *args):
            pass

        def send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > 20000:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n)) if n else {}

        def do_GET(self):
            self.send(*(route(guard, "GET", self.path, {}) or (404, {"error": "not found"})))

        def do_POST(self):
            try:
                body = self.body()
            except ValueError:
                return self.send(400, {"error": "invalid JSON"})
            self.send(*(route(guard, "POST", self.path, body) or (404, {"error": "not found"})))

    return Handler


def load(config_path):
    """Read outwit.json, or the OUTWIT_CONFIG environment variable on a host where secrets live in the environment."""
    raw = os.environ.get("OUTWIT_CONFIG")
    cfg = json.loads(raw) if raw else json.loads(Path(config_path).read_text())
    chain = vaultlib.Chain(cfg.get("rpc", "https://test.rpc.fastnear.com"), cfg.get("explorer", "https://testnet.nearblocks.io"))
    return cfg, chain


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=str(HERE / "outwit.json"))
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    cfg, chain = load(args.config)
    guard = Guard(chain, cfg["guard"]["account"], cfg["guard"]["key"], [v["vault"] for v in cfg.get("vaults", [])],
                  log_path=str(HERE / "decisions.jsonl"))
    threading.Thread(target=guard.loop, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(guard))
    print("Outwit guard %s on http://%s:%d, guarding %s" % (guard.account, args.host, args.port, ", ".join(guard.vaults) or "no vaults yet"), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
