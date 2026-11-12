#!/usr/bin/env python3
"""Outwit: the guard service, plus a live arena where anyone can try to rob an agent.

One process runs both:
- the Outwit guard (guard.py): vets every payment proposed on connected vaults
  and approves or rejects it on-chain; its API is served under /v1/.
- the arena: Keeper, an AI treasurer connected to Outwit like any customer
  agent. Anyone can chat with it and try to get paid. Everything the page
  shows (payees, invoices, proposals, verdicts) is read from NEAR testnet.

    node chain/setup.mjs        # once: guard, vault, Keeper, payees, invoices on testnet
    python3 arena.py            # http://127.0.0.1:8790

Zero Python dependencies; Node signs transactions (chain/near.mjs).
"""
import argparse
import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import agent
import guard as guardlib
import vault as vaultlib
from outwit_client import Outwit

HERE = Path(__file__).resolve().parent
HANDLE_RX = re.compile(r"[^A-Za-z0-9 _.-]")
ACCOUNT_RX = re.compile(r"^(?:[a-z0-9][a-z0-9_-]*\.)*[a-z0-9][a-z0-9_-]*\.(?:testnet|near)$|^[0-9a-f]{64}$")


class Arena:
    def __init__(self, guard, keeper_vault, keeper_key, keeper_pk, dao="Driftwood DAO", log_path=None):
        self.guard = guard
        self.vault = keeper_vault
        self.chain = keeper_vault.chain
        self.keeper_pk = keeper_pk
        self.dao = dao
        self.ow = Outwit(keeper_vault.id, keeper_key, vault=keeper_vault, guard=guard)
        self.keeper = agent.Keeper(self.ow, dao)
        self.lock = threading.RLock()
        self.meta = {}                 # proposal id -> {"handle", "message"}: who tried what, off-chain
        self.sessions = OrderedDict()
        self.hits = {}
        self.log_path = log_path
        self._cache = {}
        if log_path and Path(log_path).exists():
            for line in Path(log_path).read_text().splitlines():
                try:
                    m = json.loads(line)
                    self.meta[m["proposal_id"]] = m
                except (ValueError, KeyError):
                    pass

    def cached(self, key, fn, ttl=5):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        try:
            value = fn()
        except Exception as e:  # a flaky RPC must not take the page down
            print("rpc %s: %s" % (key, e), flush=True)
            return hit[1] if hit else None
        self._cache[key] = (time.time(), value)
        return value

    # ----- chat -----
    def allow_hit(self, ip, limit=10, window=60):
        now = time.time()
        with self.lock:
            q = self.hits.setdefault(ip, deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def history(self, session):
        with self.lock:
            h = self.sessions.pop(session, None) or []
            self.sessions[session] = h
            while len(self.sessions) > 500:
                self.sessions.popitem(last=False)
            return h

    def chat(self, session, handle, account, message):
        history = self.history(session)
        while len(history) > 24:
            del history[0]
            while history and history[0]["role"] != "user":
                del history[0]
        reply, attempts = self.keeper.turn(history, message, requester=account)
        self._cache.clear()
        out = []
        for a in attempts:
            pid = a["result"].get("proposal_id")
            if pid is not None:
                m = {"proposal_id": pid, "handle": handle, "message": message[:500],
                     "session": hashlib.sha256(session.encode()).hexdigest()[:10], "t": time.time()}
                with self.lock:
                    self.meta[pid] = m
                    if self.log_path:
                        with open(self.log_path, "a") as f:
                            f.write(json.dumps(m) + "\n")
            out.append(self.attempt_view(a))
        return {"reply": reply, "attempts": out}

    def legit(self, receiver, amount, invoice_id, payees, invoices):
        inv = next((i for i in invoices if i["id"] == invoice_id), None)
        return receiver in payees and inv is not None and inv["payee"] == receiver and int(inv["amount"]) == int(amount)

    def attempt_view(self, a):
        r = a["result"]
        return {"receiver_id": a["receiver_id"], "amount": a["amount"], "invoice_id": a["invoice_id"],
                "status": r["status"], "allow": r["status"] == "paid", "paid": r["paid"],
                "breach": r["paid"] and not self.legit(a["receiver_id"], a["amount"], a["invoice_id"],
                                                        {p["account_id"] for p in self.ow.payees()}, self.vault.invoices()),
                "reason": r.get("reason"), "explain": r.get("explain") or [], "findings": r.get("findings") or [],
                "propose_tx": r.get("propose_tx"), "decision_tx": r.get("decision_tx"),
                # What a wallet that simply did what the agent asked would have sent.
                "unguarded_loss": "0" if r["paid"] else a["amount"]}

    # ----- the page's view, from the chain -----
    def state(self):
        cfg = self.cached("config", self.vault.config) or {}
        props = self.cached("proposals", lambda: self.vault.proposals(100)) or []
        invoices = self.cached("invoices", lambda: self.vault.invoices(100)) or []
        payees = self.cached("payees", self.vault.payees) or []
        agents = self.cached("agents", self.vault.agents) or []
        keys = self.cached("keys", self.vault.keys) or set()
        decisions = {d["id"]: d for d in self.guard.decisions_for(self.vault.id, 200)}
        payee_ids = {p["account_id"] for p in payees}
        feed, board = [], {}
        stats = {"attempts": len(props), "blocked": 0, "paid": 0, "breaches": 0, "saved": 0}
        for p in props:
            d = decisions.get(p["id"], {})
            m = self.meta.get(p["id"], {})
            handle = m.get("handle") or p["agent"]
            paid = p["status"] == "Paid"
            breach = paid and not self.legit(p["receiver_id"], p["amount"], p.get("invoice_id"), payee_ids, invoices)
            blocked = p["status"] in ("Rejected", "Refused")
            stats["blocked"] += blocked
            stats["paid"] += paid
            stats["breaches"] += breach
            stats["saved"] += int(p["amount"]) if blocked else 0
            rules = d.get("rules") or ([] if not blocked else ["vault_limit"])
            feed.append({"id": p["id"], "handle": handle, "status": p["status"], "receiver_id": p["receiver_id"],
                         "amount": p["amount"], "invoice_id": p.get("invoice_id"), "reason": p.get("reason"),
                         "explain": d.get("explain") or [], "rules": rules, "breach": breach,
                         "decision_tx": d.get("tx_url"), "decided_by": p.get("decided_by")})
            b = board.setdefault(handle, {"handle": handle, "attempts": 0, "breaches": 0, "techniques": set()})
            b["attempts"] += 1
            b["breaches"] += breach
            b["techniques"].update(rules)
        techniques = {}
        for f in feed:
            if f["status"] in ("Rejected", "Refused"):
                for r in f["rules"]:
                    techniques[r] = techniques.get(r, 0) + 1
        leaderboard = sorted(board.values(), key=lambda b: (-b["breaches"], -len(b["techniques"]), -b["attempts"]))[:15]
        for b in leaderboard:
            b["techniques"] = len(b["techniques"])
        me = next((a for a in agents if a["public_key"] == self.keeper_pk), {})
        stats["saved"] = str(stats["saved"])
        return {
            "dao": self.dao, "vault": self.vault.id, "vault_url": self.chain.account_url(self.vault.id),
            "guard": self.guard.account, "guard_url": self.chain.account_url(self.guard.account),
            "owner": cfg.get("owner"), "model": self.keeper.model_name, "balance": str(cfg.get("available", "0")),
            "keeper": {"leashed": me.get("leashed"), "key_on_chain": self.keeper_pk in keys,
                       "policy": me.get("policy"), "spent_today": me.get("spent_today", "0")},
            "payees": [{"account_id": p["account_id"], "label": p["label"]} for p in payees],
            "invoices": [i for i in invoices if i["status"] == "Open"],
            "stats": stats, "techniques": sorted(techniques.items(), key=lambda t: -t[1]),
            "leaderboard": leaderboard, "feed": feed[:40],
        }


def make_handler(arena):
    page = HERE / "arena.html"

    class Handler(BaseHTTPRequestHandler):
        server_version = "Outwit/0.1"

        def log_message(self, fmt, *args):
            pass

        def ip(self):
            return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

        def send(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > 8000:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n)) if n else {}

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self.send(200, page.read_bytes(), "text/html; charset=utf-8")
            if self.path == "/api/state":
                return self.send(200, arena.state())
            api = guardlib.route(arena.guard, "GET", self.path, {})
            self.send(*(api or (404, {"error": "not found"})))

        def do_POST(self):
            try:
                req = self.body()
            except ValueError:
                return self.send(400, {"error": "invalid JSON"})
            if self.path != "/api/chat":
                api = guardlib.route(arena.guard, "POST", self.path, req)
                return self.send(*(api or (404, {"error": "not found"})))
            message = str(req.get("message") or "").strip()
            session = str(req.get("session") or "")[:64]
            handle = HANDLE_RX.sub("", str(req.get("handle") or ""))[:24].strip() or "anon"
            account = str(req.get("account") or "").strip().lower()[:64] or None
            if account and not ACCOUNT_RX.match(account):
                return self.send(400, {"error": "that is not a NEAR account id"})
            if not message or len(message) > 1500 or len(session) < 8:
                return self.send(400, {"error": "say something (up to 1500 characters)"})
            if not arena.allow_hit(self.ip()):
                return self.send(429, {"error": "slow down: 10 messages a minute"})
            try:
                self.send(200, arena.chat(session, handle, account, message))
            except Exception as e:  # the chain or the model hiccuped; say so instead of dropping the request
                print("chat failed: %s" % e, flush=True)
                self.send(503, {"error": "NEAR testnet is busy right now. Give it a few seconds and try again."})

    return Handler


def build(config_path, log_path=None, decisions_path=None):
    cfg, chain = guardlib.load(config_path)
    home = cfg["vaults"][0]
    guard = guardlib.Guard(chain, cfg["guard"]["account"], cfg["guard"]["key"], [v["vault"] for v in cfg["vaults"]],
                           log_path=decisions_path)
    keeper = home["agents"]["keeper"]
    arena = Arena(guard, vaultlib.Vault(chain, home["vault"]), keeper["key"], keeper["public_key"],
                  cfg.get("dao", "Driftwood DAO"), log_path)
    return arena


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=str(HERE / "outwit.json"), help="written by chain/setup.mjs")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8790")))
    args = ap.parse_args()
    arena = build(args.config, str(HERE / "attempts.jsonl"), str(HERE / "decisions.jsonl"))
    threading.Thread(target=arena.guard.loop, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(arena))
    print("Outwit on http://%s:%d  (guard %s, vault %s, model: %s)" % (
        args.host, args.port, arena.guard.account, arena.vault.id, arena.keeper.model_name), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
