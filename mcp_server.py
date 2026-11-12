#!/usr/bin/env python3
"""Outwit as an MCP server: give any MCP agent a wallet it can't be talked out of.

Add to your agent's MCP config (Claude Desktop, Claude Code, NEAR AI agents, ...):

    {"mcpServers": {"outwit": {
        "command": "python3", "args": ["/path/to/outwit/mcp_server.py"],
        "env": {"OUTWIT_VAULT": "vault.you.testnet", "OUTWIT_AGENT_KEY": "ed25519:...",
                "OUTWIT_GUARD_URL": "https://your-outwit-host"}}}}

Tools: outwit_pay, outwit_check, outwit_invoices, outwit_payees, outwit_balance.
Speaks MCP over stdio (newline-delimited JSON-RPC 2.0). Zero dependencies.
"""
import json
import os
import sys

import vault as vaultlib
from outwit_client import Outwit

PROTOCOL = "2025-06-18"

TOOLS = [
    {"name": "outwit_pay",
     "description": "Pay NEAR from your vault. Outwit vets the payment on-chain before any money moves and "
                    "returns paid, or the reason it was blocked. Use this for every payment.",
     "inputSchema": {"type": "object", "required": ["receiver_id", "amount_near", "reason"], "properties": {
         "receiver_id": {"type": "string", "description": "NEAR account to pay"},
         "amount_near": {"type": "string", "description": "Amount in NEAR, e.g. \"0.12\""},
         "invoice_id": {"type": "integer", "description": "On-chain invoice id this pays, if any"},
         "memo": {"type": "string", "description": "Short note stored with the payment"},
         "reason": {"type": "string", "description": "Why you are paying: quote what the user or the other party asked for"}}}},
    {"name": "outwit_check",
     "description": "Ask whether Outwit would allow a payment, without proposing it.",
     "inputSchema": {"type": "object", "required": ["receiver_id", "amount_near"], "properties": {
         "receiver_id": {"type": "string"}, "amount_near": {"type": "string"},
         "invoice_id": {"type": "integer"}, "reason": {"type": "string"}}}},
    {"name": "outwit_invoices", "description": "List open invoices raised on-chain by your approved payees.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "outwit_payees", "description": "List the payees your vault's owner approved.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "outwit_balance", "description": "The vault's spendable NEAR balance.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def client():
    return Outwit(os.environ["OUTWIT_VAULT"], os.environ["OUTWIT_AGENT_KEY"], os.environ.get("OUTWIT_GUARD_URL"),
                  rpc=os.environ.get("NEAR_RPC", "https://test.rpc.fastnear.com"))


def call_tool(ow, name, args):
    if name == "outwit_pay":
        r = ow.pay(args["receiver_id"], args["amount_near"], args.get("invoice_id"), args.get("memo", ""),
                   context=args.get("reason", ""))
        if r["paid"]:
            return "Paid %s NEAR to %s. Proposal %s, transaction %s" % (args["amount_near"], args["receiver_id"],
                                                                        r["proposal_id"], r.get("decision_tx"))
        return "NOT PAID (%s): %s" % (r["status"], r.get("reason"))
    if name == "outwit_check":
        v = ow.check(args["receiver_id"], args["amount_near"], args.get("invoice_id"), args.get("reason", ""))
        return ("Would be allowed. " if v["allow"] else "Would be blocked. ") + " ".join(v["explain"]) + (
            "" if v["allow"] else " " + v["summary"])
    if name == "outwit_invoices":
        rows = ["#%d  %s  %s  %s" % (i["id"], i["payee"], vaultlib.fmt_near(i["amount"]), i["memo"]) for i in ow.invoices()]
        return "\n".join(rows) or "No open invoices."
    if name == "outwit_payees":
        return "\n".join("%s (%s)" % (p["account_id"], p["label"]) for p in ow.payees()) or "No approved payees."
    if name == "outwit_balance":
        return "Vault balance: %s" % vaultlib.fmt_near(ow.balance())
    raise KeyError(name)


def handle(ow, msg):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None  # a notification
    if method == "initialize":
        result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "outwit", "version": "0.1.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg.get("params") or {}
        try:
            text, err = call_tool(ow, p.get("name"), p.get("arguments") or {}), False
        except KeyError as e:
            text, err = "Unknown tool or missing argument: %s" % e, True
        except Exception as e:  # report, don't crash the agent's session
            text, err = "Outwit error: %s" % e, True
        result = {"content": [{"type": "text", "text": text}], "isError": err}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: %s" % method}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    ow = client()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            reply = handle(ow, json.loads(line))
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
