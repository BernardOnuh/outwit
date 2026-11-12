"""Talk to the Leash vault contract: live on NEAR, or simulated for --mock.

Both classes expose the same methods. Calls return the bridge's result shape,
{"ok", "tx", "result", "logs"} or {"ok": False, "error"}, so callers never care
which one they hold. SimVault mirrors contract/src/lib.rs rule for rule.
"""
import base64
import hashlib
import json
import secrets
import subprocess
import time
import urllib.request
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
YOCTO = 10 ** 24
MINUTE_MS = 60_000
DAY_MS = 86_400_000
MAX_INCIDENTS = 50


def to_yocto(near):
    """'0.25' (NEAR) -> 250000000000000000000000 (yoctoNEAR)."""
    return int(Decimal(str(near)) * YOCTO)


def fmt_near(yocto):
    near = (Decimal(int(yocto)) / YOCTO).normalize()
    return "%s NEAR" % ("{:f}".format(near) if near else "0")


class LiveVault:
    """The deployed contract. Views go straight to RPC; calls are signed by chain/near.mjs."""

    def __init__(self, cfg):
        self.rpc = cfg["rpc"]
        self.contract = cfg["vault"]
        self.owner = cfg.get("owner") or {}
        self.watchdog = cfg["watchdog"]
        self.explorer = cfg.get("explorer", "https://testnet.nearblocks.io")

    # ----- reads -----
    def _query(self, params):
        body = {"jsonrpc": "2.0", "id": "leash", "method": "query", "params": dict(params, finality="optimistic")}
        req = urllib.request.Request(self.rpc, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            out = json.loads(r.read())
        if "error" in out:
            raise RuntimeError(out["error"].get("data") or out["error"])
        if "error" in out["result"]:
            raise RuntimeError(out["result"]["error"])
        return out["result"]

    def view(self, method, args=None):
        res = self._query({"request_type": "call_function", "account_id": self.contract, "method_name": method,
                           "args_base64": base64.b64encode(json.dumps(args or {}).encode()).decode()})
        return json.loads(bytes(res["result"]))

    def agents(self):
        return self.view("get_agents")

    def incidents(self):
        return self.view("get_incidents")

    def blocklist(self):
        return self.view("get_blocklist")

    def keys(self):
        """Public keys on the vault account right now."""
        res = self._query({"request_type": "view_access_key_list", "account_id": self.contract})
        return {k["public_key"] for k in res["keys"]}

    # ----- writes -----
    def _call(self, signer, key, method, args, gas=30):
        req = {"rpc": self.rpc, "account": signer, "key": key, "contract": self.contract,
               "method": method, "args": args, "gas": gas}
        try:
            proc = subprocess.run(["node", str(HERE / "chain" / "near.mjs")], input=json.dumps(req),
                                  capture_output=True, text=True, timeout=90)
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as e:
            return {"ok": False, "error": "NEAR bridge failed: %s" % e}

    def leash(self, name, reason):
        return self._call(self.watchdog["account"], self.watchdog["key"], "leash", {"name": name, "reason": reason[:300]})

    def block(self, account_id):
        return self._call(self.watchdog["account"], self.watchdog["key"], "block_receiver", {"account_id": account_id})

    def can_release(self):
        return bool(self.owner.get("key"))

    def release(self, name, new_public_key=None):
        if not self.can_release():
            return {"ok": False, "error": "no owner key configured: release from the owner's wallet"}
        return self._call(self.owner["account"], self.owner["key"], "release",
                          {"name": name, "new_public_key": new_public_key})

    def pay(self, agent_key, receiver_id, amount_yocto, memo=""):
        """Pay as an agent: signed with the agent's own function-call key on the vault."""
        return self._call(self.contract, agent_key, "pay",
                          {"receiver_id": receiver_id, "amount": str(amount_yocto), "memo": memo})

    def tx_url(self, tx):
        return "%s/txns/%s" % (self.explorer, tx) if tx else None


class SimVault:
    """An in-memory vault with the contract's rules, for demos and tests."""

    explorer = None

    def __init__(self, contract="vault.sim", owner="owner.sim", guardians=("watchdog.sim",), balance_near=50):
        self.contract = contract
        self.owner_id = owner
        self.guardians = list(guardians)
        self.balance = to_yocto(balance_near)
        self._agents = {}
        self._by_key = {}
        self._secrets = {}      # secret key -> public key, standing in for ed25519
        self._keys = set()      # public keys on the vault account
        self._blocklist = set()
        self._incidents = []
        self.transfers = []
        self.clock = lambda: int(time.time() * 1000)

    @staticmethod
    def new_key():
        secret = "ed25519:sim" + secrets.token_hex(16)
        return "ed25519:" + hashlib.sha256(secret.encode()).hexdigest()[:44], secret

    def _tx(self, result=None, logs=()):
        return {"ok": True, "tx": "sim-" + secrets.token_hex(8), "result": result, "logs": list(logs)}

    def _fail(self, error):
        return {"ok": False, "error": error}

    def add_agent(self, name, public_key, secret_key, policy):
        assert name not in self._agents and public_key not in self._by_key
        self._secrets[secret_key] = public_key
        self._by_key[public_key] = name
        self._agents[name] = {
            "name": name, "public_key": public_key, "policy": dict(policy), "leashed": None, "leashed_by": None,
            "day": self.clock() // DAY_MS, "spent_today": "0", "total_spent": "0", "payments": 0, "recent": []}
        self._keys.add(public_key)

    # ----- reads -----
    def agents(self):
        return [json.loads(json.dumps(a)) for a in self._agents.values()]

    def incidents(self):
        return list(self._incidents)

    def blocklist(self):
        return sorted(self._blocklist)

    def keys(self):
        return set(self._keys)

    # ----- writes -----
    def _trip(self, name, reason, by):
        a = self._agents[name]
        if a["leashed"]:
            return
        a["leashed"], a["leashed_by"] = reason, by
        self._incident(name, "leashed", reason, by)
        self._keys.discard(a["public_key"])

    def _incident(self, name, kind, reason, by):
        self._incidents.append({"agent": name, "kind": kind, "reason": reason, "by": by, "at_ms": self.clock()})
        del self._incidents[:-MAX_INCIDENTS]

    def leash(self, name, reason, by=None):
        by = by or self.guardians[0]
        if by != self.owner_id and by not in self.guardians:
            return self._fail("Smart contract panicked: only the owner or a guardian may leash")
        if name not in self._agents:
            return self._fail("Smart contract panicked: no such agent")
        self._trip(name, reason[:300], by)
        return self._tx()

    def block(self, account_id, by=None):
        self._blocklist.add(account_id)
        return self._tx()

    def can_release(self):
        return True

    def release(self, name, new_public_key=None, by=None):
        if (by or self.owner_id) != self.owner_id:
            return self._fail("Smart contract panicked: only the owner may do this")
        a = self._agents.get(name)
        if not a:
            return self._fail("Smart contract panicked: no such agent")
        if not a["leashed"]:
            return self._fail("Smart contract panicked: agent is not leashed")
        was = a["leashed"]
        a["leashed"] = a["leashed_by"] = None
        a["recent"] = []
        if new_public_key and new_public_key != a["public_key"]:
            del self._by_key[a["public_key"]]
            self._by_key[new_public_key] = name
            a["public_key"] = new_public_key
        self._incident(name, "released", "released by the owner (was: %s)" % was, self.owner_id)
        self._keys.add(a["public_key"])
        return self._tx()

    def pay(self, agent_key, receiver_id, amount_yocto, memo=""):
        pk = self._secrets.get(agent_key)
        if pk not in self._keys:
            # The chain rejects the transaction before the contract ever runs.
            return self._fail("Transaction rejected: access key %s does not exist on %s" % (pk or "?", self.contract))
        name = self._by_key.get(pk)
        if not name:
            return self._fail("Smart contract panicked: unknown agent key")
        amount = int(amount_yocto)
        if amount <= 0:
            return self._fail("Smart contract panicked: amount must be positive")
        if amount > self.balance:
            return self._fail("Smart contract panicked: vault balance too low")
        a, p, now = self._agents[name], self._agents[name]["policy"], self.clock()
        if a["leashed"]:
            return self._fail("Smart contract panicked: agent is leashed: %s" % a["leashed"])
        if a["day"] != now // DAY_MS:
            a["day"], a["spent_today"] = now // DAY_MS, "0"
        a["recent"] = [t for t in a["recent"] if now - t < MINUTE_MS]
        spent, cap, daily = int(a["spent_today"]), int(p["max_per_payment"]), int(p["daily_limit"])
        allowed = p.get("allowed_receivers")
        if receiver_id in self._blocklist:
            reason = "scam blocklist: %s is flagged" % receiver_id
        elif allowed is not None and receiver_id not in allowed:
            reason = "receiver not allowed: %s" % receiver_id
        elif amount > cap:
            reason = "over per-payment cap: %s > %s" % (fmt_near(amount), fmt_near(cap))
        elif spent + amount > daily:
            reason = "over daily limit: %s spent + %s > %s" % (fmt_near(spent), fmt_near(amount), fmt_near(daily))
        elif len(a["recent"]) >= int(p["max_payments_per_minute"]):
            reason = "payment loop: %d payments in the last minute" % (len(a["recent"]) + 1)
        else:
            reason = None
        if reason:
            self._trip(name, reason, self.contract)
            return self._tx({"paid": False, "leashed": reason})
        a["recent"].append(now)
        a["spent_today"] = str(spent + amount)
        a["total_spent"] = str(int(a["total_spent"]) + amount)
        a["payments"] += 1
        self.balance -= amount
        self.transfers.append((name, receiver_id, amount, memo))
        return self._tx({"paid": True, "leashed": None})

    def tx_url(self, tx):
        return None
