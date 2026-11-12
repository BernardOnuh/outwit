"""Outwit for your agent: route every payment through the guard before it moves.

    from outwit_client import Outwit
    ow = Outwit("vault.yourname.testnet", agent_key="ed25519:...", guard_url="https://your-outwit-host")
    result = ow.pay("inkwell.yourname.testnet", "0.12", invoice_id=3,
                    memo="logo work", context=conversation_text)
    if result["paid"]: ...
    else: tell the user result["reason"]

The agent's key can only *propose* on its vault. Outwit vets the proposal and
approves or rejects it on-chain; `pay` waits for that verdict and returns it.
"""
import json
import secrets
import time
import urllib.error
import urllib.request

import vault as vaultlib


class Outwit:
    def __init__(self, vault_id, agent_key, guard_url=None, rpc="https://test.rpc.fastnear.com",
                 explorer="https://testnet.nearblocks.io", vault=None, guard=None):
        """Pass `guard_url` for the Outwit service, or `guard` (a guard.Guard) to run it in-process."""
        self.vault = vault or vaultlib.Vault(vaultlib.Chain(rpc, explorer), vault_id)
        self.key = agent_key
        self.guard_url = (guard_url or "").rstrip("/")
        self.guard = guard

    # ----- the guard API -----
    def _api(self, method, path, body=None):
        req = urllib.request.Request(self.guard_url + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", "User-Agent": "outwit-client/0.1"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def _send_context(self, ref, context, requester):
        if self.guard:
            return self.guard.add_context(ref, self.vault.id, context, requester)
        if self.guard_url:
            try:
                self._api("POST", "/v1/context", {"ref": ref, "vault_id": self.vault.id, "context": context, "requester": requester})
            except (urllib.error.URLError, OSError, ValueError):
                pass  # the guard still judges the proposal, just without the conversation

    def _decision(self, pid):
        if self.guard:
            found = [d for d in self.guard.decisions_for(self.vault.id) if d["id"] == pid]
        elif self.guard_url:
            try:
                found = [d for d in self._api("GET", "/v1/decisions?vault_id=" + self.vault.id)["decisions"] if d["id"] == pid]
            except (urllib.error.URLError, OSError, ValueError, KeyError):
                found = []
        else:
            found = []
        return found[0] if found else {}

    # ----- what agents call -----
    def pay(self, receiver_id, amount_near=None, invoice_id=None, memo="", context="", requester=None,
            amount=None, timeout=60):
        """Propose a payment and wait for Outwit's on-chain verdict.

        Returns {"paid", "status", "reason", "proposal_id", "propose_tx", "decision_tx", "explain", "findings"}.
        status is one of: paid, rejected (Outwit said no), refused (broke the vault's hard limits;
        the agent is now leashed), expired, error.
        """
        amount = int(amount) if amount is not None else vaultlib.to_yocto(amount_near)
        ref = secrets.token_hex(6)
        self._send_context(ref, context, requester)
        res = self.vault.propose(self.key, receiver_id.strip().lower(), amount, invoice_id, ("[ref:%s] %s" % (ref, memo)).strip())
        if not res.get("ok"):
            return {"paid": False, "status": "error", "reason": res.get("error"), "propose_tx": self.vault.chain.tx_url(res.get("tx"))}
        out = res.get("result") or {}
        pid = out.get("id")
        result = {"proposal_id": pid, "propose_tx": self.vault.chain.tx_url(res.get("tx")), "explain": [], "findings": []}
        if out.get("status") == "Refused":
            return dict(result, paid=False, status="refused", reason=out.get("reason"))
        deadline = time.time() + timeout
        p = None
        while time.time() < deadline:
            if self.guard:
                self.guard.run_once()
            p = self.vault.proposal(pid)
            if p and p["status"] != "Pending":
                break
            time.sleep(1.2)
        if not p or p["status"] == "Pending":
            return dict(result, paid=False, status="pending", reason="no verdict yet; check proposal %s later" % pid)
        d = self._decision(pid)
        return dict(result, paid=p["status"] == "Paid", status=p["status"].lower(), reason=p.get("reason"),
                    decision_tx=d.get("tx_url"), explain=d.get("explain", []), findings=d.get("findings", []),
                    rules=d.get("rules", []))

    def check(self, receiver_id, amount_near=None, invoice_id=None, context="", requester=None, amount=None):
        """Ask what Outwit would say, without proposing anything."""
        amount = int(amount) if amount is not None else vaultlib.to_yocto(amount_near)
        if self.guard:
            return self.guard.check(self.vault.id, receiver_id.strip().lower(), amount, invoice_id, context, requester)
        return self._api("POST", "/v1/check", {"vault_id": self.vault.id, "receiver_id": receiver_id, "amount": str(amount),
                                               "invoice_id": invoice_id, "context": context, "requester": requester})

    def invoices(self, open_only=True):
        return [i for i in self.vault.invoices() if not open_only or i["status"] == "Open"]

    def payees(self):
        return self.vault.payees()

    def balance(self):
        return int(self.vault.config()["available"])
