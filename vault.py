"""Talk to an Outwit vault on NEAR.

`Chain` reads through NEAR RPC and signs through chain/near.mjs (Python's
standard library has no ed25519). `Vault` wraps one vault contract. `SimVault`
is an in-memory copy of contract/src/lib.rs for the test suite only; everything
the product shows comes from the chain.

Writes return the bridge's shape: {"ok", "tx", "result", "logs"} or {"ok": False, "error"}.
"""
import base64
import json
import os
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
YOCTO = 10 ** 24
MINUTE_MS = 60_000
DAY_MS = 86_400_000
PROPOSAL_TTL_MS = 15 * MINUTE_MS


def to_yocto(near):
    """'0.25' (NEAR) -> 250000000000000000000000 (yoctoNEAR)."""
    return int(Decimal(str(near)) * YOCTO)


def fmt_near(yocto):
    near = (Decimal(int(yocto)) / YOCTO).normalize()
    return "%s NEAR" % ("{:f}".format(near) if near else "0")


DEFAULT_RPCS = ["https://test.rpc.fastnear.com", "https://rpc.testnet.near.org", "https://near-testnet.drpc.org"]


class Chain:
    """NEAR RPC with failover: a busy (429) or broken endpoint hands over to the next one."""

    def __init__(self, rpc=None, explorer="https://testnet.nearblocks.io", rpcs=None):
        env = [u.strip() for u in os.environ.get("NEAR_RPCS", "").split(",") if u.strip()]
        self.rpcs = env or rpcs or ([rpc] if rpc else []) + [u for u in DEFAULT_RPCS if u != rpc]
        self.rpc = self.rpcs[0]
        self.explorer = explorer
        self._lock = threading.Lock()

    def _post(self, body):
        last = None
        for attempt in range(len(self.rpcs) * 2):
            url = self.rpc
            req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json", "User-Agent": "outwit/0.1"})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return json.loads(r.read())
            except (urllib.error.URLError, OSError, ValueError) as e:
                last = e
                with self._lock:  # move on to the next endpoint, unless another thread already did
                    if self.rpc == url:
                        self.rpc = self.rpcs[(self.rpcs.index(url) + 1) % len(self.rpcs)]
                time.sleep(min(2.0, 0.25 * (attempt + 1)))
        raise RuntimeError("NEAR RPC unavailable: %s" % last)

    def _query(self, params):
        out = self._post({"jsonrpc": "2.0", "id": "outwit", "method": "query", "params": dict(params, finality="optimistic")})
        if "error" in out:
            raise RuntimeError(out["error"].get("data") or out["error"])
        if "error" in out["result"]:
            raise RuntimeError(out["result"]["error"])
        return out["result"]

    def view(self, contract, method, args=None):
        res = self._query({"request_type": "call_function", "account_id": contract, "method_name": method,
                           "args_base64": base64.b64encode(json.dumps(args or {}).encode()).decode()})
        return json.loads(bytes(res["result"]))

    def keys(self, account):
        res = self._query({"request_type": "view_access_key_list", "account_id": account})
        return {k["public_key"] for k in res["keys"]}

    def call(self, signer, key, contract, method, args, gas=30):
        req = {"rpc": self.rpc, "rpcs": self.rpcs, "account": signer, "key": key, "contract": contract,
               "method": method, "args": args, "gas": gas}
        try:
            proc = subprocess.run(["node", str(HERE / "chain" / "near.mjs")], input=json.dumps(req),
                                  capture_output=True, text=True, timeout=90)
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as e:
            return {"ok": False, "error": "NEAR bridge failed: %s" % e}

    def tx_url(self, tx):
        return "%s/txns/%s" % (self.explorer, tx) if tx else None

    def account_url(self, account):
        return "%s/address/%s" % (self.explorer, account)


class Vault:
    """One Outwit vault contract."""

    def __init__(self, chain, vault_id, ttl=4.0):
        self.chain = chain
        self.id = vault_id
        self.ttl = ttl
        self._cache = {}
        self._lock = threading.Lock()

    def view(self, method, args=None, fresh=False):
        """Read the contract. The page, the guard and the agent share answers for `ttl`
        seconds, which keeps a busy page well inside public RPC rate limits."""
        key = (method, json.dumps(args, sort_keys=True))
        with self._lock:
            hit = self._cache.get(key)
        if hit and not fresh and time.time() - hit[0] < self.ttl:
            return hit[1]
        value = self.chain.view(self.id, method, args)
        with self._lock:
            self._cache[key] = (time.time(), value)
        return value

    def invalidate(self):
        with self._lock:
            self._cache.clear()

    def _write(self, res):
        self.invalidate()
        return res

    def config(self):
        return self.view("get_config")

    def agents(self):
        return self.view("get_agents")

    def payees(self):
        return self.view("get_payees")

    def invoices(self, limit=100):
        return self.view("get_invoices", {"limit": limit})

    def proposals(self, limit=50):
        return self.view("get_proposals", {"limit": limit})

    def proposal(self, pid):
        return self.view("get_proposal", {"id": pid}, fresh=True)

    def pending(self):
        return self.view("get_pending", fresh=True)

    def incidents(self):
        return self.view("get_incidents")

    def keys(self):
        hit = self._cache.get(("keys", ""))
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]
        value = self.chain.keys(self.id)
        self._cache[("keys", "")] = (time.time(), value)
        return value

    def propose(self, agent_key, receiver_id, amount_yocto, invoice_id=None, memo=""):
        """Ask to pay, signed with the agent's own function-call key on the vault."""
        return self._write(self.chain.call(self.id, agent_key, self.id, "propose",
                                           {"receiver_id": receiver_id, "amount": str(amount_yocto),
                                            "invoice_id": invoice_id, "memo": memo[:280]}))

    def approve(self, guard, key, pid, reason):
        return self._write(self.chain.call(guard, key, self.id, "approve", {"id": pid, "reason": reason[:280]}))

    def reject(self, guard, key, pid, reason):
        return self._write(self.chain.call(guard, key, self.id, "reject", {"id": pid, "reason": reason[:280]}))

    def create_invoice(self, payee, key, amount_yocto, memo):
        return self._write(self.chain.call(payee, key, self.id, "create_invoice", {"amount": str(amount_yocto), "memo": memo[:280]}))


class SimVault:
    """The contract's rules in memory, for tests. Same views and calls as Vault."""

    def __init__(self, vault_id="vault.sim", owner="owner.sim", guards=("guard.sim",), balance_near=20):
        self.id = vault_id
        self.owner = owner
        self.guards = list(guards)
        self.balance = to_yocto(balance_near)
        self._agents, self._by_key, self._keys = {}, {}, set()
        self._payees, self._invoices, self._proposals = {}, [], []
        self.clock = lambda: int(time.time() * 1000)
        self.chain = self

    # Chain-ish helpers so callers can use vault.chain.tx_url(...)
    explorer = None

    def tx_url(self, tx):
        return None

    def account_url(self, account):
        return None

    @staticmethod
    def new_key():
        pk = "ed25519:sim" + secrets.token_hex(16)
        return pk, "secret:" + pk

    def _tx(self, result=None):
        return {"ok": True, "tx": "sim-" + secrets.token_hex(6), "result": result, "logs": []}

    def add_agent(self, name, public_key, policy):
        self._by_key[public_key] = name
        self._keys.add(public_key)
        self._agents[name] = {"name": name, "public_key": public_key, "policy": dict(policy), "leashed": None,
                              "leashed_by": None, "day": self.clock() // DAY_MS, "spent_today": "0",
                              "total_spent": "0", "payments": 0, "recent": []}

    def add_payee(self, account_id, label):
        self._payees[account_id] = {"account_id": account_id, "label": label, "added_ms": self.clock()}

    # ----- views -----
    def config(self):
        return {"owner": self.owner, "guards": self.guards, "available": str(self.balance),
                "proposals": len(self._proposals), "invoices": len(self._invoices)}

    def agents(self):
        return json.loads(json.dumps(list(self._agents.values())))

    def payees(self):
        return list(self._payees.values())

    def invoices(self, limit=100):
        return [dict(i) for i in self._invoices[-limit:]][::-1]

    def proposals(self, limit=50):
        return [dict(p) for p in self._proposals[-limit:]][::-1]

    def proposal(self, pid):
        return dict(self._proposals[pid]) if 0 <= pid < len(self._proposals) else None

    def pending(self):
        return [dict(p) for p in self._proposals if p["status"] == "Pending"]

    def incidents(self):
        return []

    def keys(self):
        return set(self._keys)

    def invalidate(self):
        pass

    # ----- calls -----
    def create_invoice(self, payee, key, amount_yocto, memo):
        if payee not in self._payees:
            return {"ok": False, "error": "Smart contract panicked: only approved payees can raise invoices"}
        iid = len(self._invoices)
        self._invoices.append({"id": iid, "payee": payee, "amount": str(amount_yocto), "memo": memo,
                               "status": "Open", "created_ms": self.clock(), "paid_by": None})
        return self._tx(iid)

    def propose(self, agent_key, receiver_id, amount_yocto, invoice_id=None, memo=""):
        pk = agent_key[len("secret:"):] if agent_key.startswith("secret:") else None
        if pk not in self._keys:
            return {"ok": False, "error": "Access key %s does not exist" % pk}
        name = self._by_key[pk]
        a, now, amount = self._agents[name], self.clock(), int(amount_yocto)
        if a["leashed"]:
            return {"ok": False, "error": "Smart contract panicked: agent is leashed: %s" % a["leashed"]}
        if a["day"] != now // DAY_MS:
            a["day"], a["spent_today"] = now // DAY_MS, "0"
        a["recent"] = [t for t in a["recent"] if now - t < MINUTE_MS]
        p = a["policy"]
        if p.get("payees_only") and receiver_id not in self._payees:
            reason = "not an approved payee: %s" % receiver_id
        elif amount > int(p["max_per_payment"]):
            reason = "over per-payment cap: %s > %s" % (fmt_near(amount), fmt_near(p["max_per_payment"]))
        elif int(a["spent_today"]) + amount > int(p["daily_limit"]):
            reason = "over daily limit"
        elif len(a["recent"]) >= int(p["max_proposals_per_minute"]):
            reason = "proposal loop: %d proposals in the last minute" % (len(a["recent"]) + 1)
        else:
            reason = None
        if not reason:
            a["recent"].append(now)
        pid = len(self._proposals)
        self._proposals.append({"id": pid, "agent": name, "receiver_id": receiver_id, "amount": str(amount),
                                "invoice_id": invoice_id, "memo": memo, "status": "Refused" if reason else "Pending",
                                "reason": reason, "decided_by": self.id if reason else None, "created_ms": now,
                                "decided_ms": now if reason else None})
        if reason:
            a["leashed"], a["leashed_by"] = reason, self.id
            self._keys.discard(pk)
        return self._tx({"id": pid, "status": "Refused" if reason else "Pending", "reason": reason})

    def _decide(self, pid, status, reason, by):
        p = self._proposals[pid]
        p.update(status=status, reason=reason, decided_by=by, decided_ms=self.clock())

    def approve(self, guard, key, pid, reason):
        if guard not in self.guards and guard != self.owner:
            return {"ok": False, "error": "Smart contract panicked: only the owner or a guard may do this"}
        p = self._proposals[pid]
        if p["status"] != "Pending":
            return {"ok": False, "error": "Smart contract panicked: proposal is not pending"}
        amount = int(p["amount"])
        problem = None
        if self.clock() - p["created_ms"] > PROPOSAL_TTL_MS:
            problem = "expired: no guard decided within 15 minutes"
        elif amount > self.balance:
            problem = "vault balance too low"
        if p["invoice_id"] is not None:
            inv = self._invoices[p["invoice_id"]]
            if inv["status"] != "Open":
                problem = problem or "invoice %d is not open" % inv["id"]
            elif inv["payee"] != p["receiver_id"] or int(inv["amount"]) != amount:
                problem = problem or "does not match invoice %d" % inv["id"]
        if problem:
            self._decide(pid, "Expired", problem, guard)
            return self._tx("Expired")
        a = self._agents[p["agent"]]
        a["spent_today"] = str(int(a["spent_today"]) + amount)
        a["total_spent"] = str(int(a["total_spent"]) + amount)
        a["payments"] += 1
        if p["invoice_id"] is not None:
            self._invoices[p["invoice_id"]].update(status="Paid", paid_by=pid)
        self.balance -= amount
        self._decide(pid, "Paid", reason, guard)
        return self._tx("Paid")

    def reject(self, guard, key, pid, reason):
        if guard not in self.guards and guard != self.owner:
            return {"ok": False, "error": "Smart contract panicked: only the owner or a guard may do this"}
        if self._proposals[pid]["status"] != "Pending":
            return {"ok": False, "error": "Smart contract panicked: proposal is not pending"}
        self._decide(pid, "Rejected", reason, guard)
        return self._tx()
