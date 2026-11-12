"""The firewall: read a NEAR transaction an agent wants to sign, say in plain
English what it would do, and block it when it looks like an attack.

A proposal is a NEAR transaction signed by the vault:
    {"receiver_id": "x.testnet", "actions": [{"type": "Transfer", "deposit": "1000..."}, ...]}
Action types follow NEAR's: Transfer, FunctionCall, AddKey, DeleteKey,
DeleteAccount, DeployContract, Stake.

The context says what the firewall knows about the world: the vault's balance,
approved vendors and their open invoices, recent payments, and the untrusted
text that led to this proposal. Every rule is deterministic and explainable;
nothing here asks a model for its opinion, so there is nothing to talk around.
"""
import re
import time
from decimal import Decimal

YOCTO = 10 ** 24
SEVERITY = {"info": 0, "medium": 1, "high": 2, "critical": 3}
BLOCKING = {"high", "critical"}

# Phrases that try to give orders from inside data the agent was handed.
INJECTION = [
    ("instruction override", re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules?|prompts?|guidelines?)")),
    ("fake authority", re.compile(r"(?i)\b(system (message|prompt|override)|admin(istrator)? (override|mode|command)|developer mode|i am (your|the) (owner|admin|developer|creator)|on behalf of the (owner|dao|council))\b")),
    ("role reset", re.compile(r"(?i)\byou are (now|no longer)\b|\bnew (role|persona|instructions)\b|\bact as\b")),
    ("urgency", re.compile(r"(?i)\b(urgent(ly)?|immediately|right now|asap|before it'?s too late|or (the|your) (funds|account) will)\b")),
    ("encoded payload", re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")),
    ("hidden markup", re.compile(r"(?i)<\s*(system|instructions?|admin)\s*>|\[\s*(system|inst)\s*\]")),
]

# The classic invoice-redirection (business email compromise) story.
REDIRECT = re.compile(r"(?i)\b(new|changed?|updated?|different)\b.{0,30}\b(wallet|account|address|payment details|bank details)\b"
                      r"|\b(wallet|account|address)\b.{0,20}\b(has changed|was changed|moved|migrated|compromised)\b")

ACCOUNT_RX = re.compile(r"\b([a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)*\.(?:testnet|near))\b|\b([0-9a-f]{64})\b")

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                            "i": "l", "_": "", "-": ""})


def near(yocto):
    """Format yoctoNEAR as NEAR for people."""
    value = (Decimal(int(yocto)) / YOCTO).normalize()
    return "{:f} NEAR".format(value) if value else "0 NEAR"


def short_key(pk):
    pk = str(pk or "?")
    return pk if len(pk) <= 20 else pk[:14] + "…" + pk[-4:]


def accounts_in(text):
    return {a or b for a, b in ACCOUNT_RX.findall((text or "").lower())}


def skeleton(account):
    """Collapse look-alike characters so 'acme-supp1ies' and 'acmesupplies' compare equal."""
    name = account.lower()
    for suffix in (".testnet", ".near"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    name = name.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return name.translate(HOMOGLYPHS)


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(account, known):
    """The known account `account` is impersonating, if any."""
    if account in known:
        return None
    for real in known:
        if account.endswith("." + real):
            continue  # a sub-account: only the real owner can create it
        s, r = skeleton(account), skeleton(real)
        base = real.split(".")[0]
        if s == r or (len(r) >= 5 and edit_distance(s, r) <= 2) or (len(base) >= 4 and base in account.split(".")[0] and account.split(".")[0] != base):
            return real
    return None


class Finding(dict):
    def __init__(self, rule, severity, message):
        super().__init__(rule=rule, severity=severity, message=message)


class Context:
    """What the firewall knows when it judges a proposal."""

    def __init__(self, vault_id, balance, vendors=None, invoices=None, tokens=None, recent=None,
                 requester=None, untrusted=None, window_s=600):
        self.vault_id = vault_id
        self.balance = int(balance)
        self.vendors = dict(vendors or {})          # account -> label
        self.invoices = list(invoices or [])        # {"id", "vendor", "amount" (yocto), "status": "open"|"paid"}
        self.tokens = dict(tokens or {})            # contract -> {"symbol", "decimals"}
        self.recent = list(recent or [])            # [(unix_s, receiver, yocto)] payments already sent
        self.requester = requester                  # account the person talking to the agent claims
        self.untrusted = untrusted or ""            # text from outside the trust boundary
        self.window_s = window_s

    def open_invoices(self, vendor):
        return [i for i in self.invoices if i["vendor"] == vendor and i.get("status", "open") == "open"]


def describe(proposal, ctx):
    """One plain-English line per action."""
    to = proposal.get("receiver_id", "?")
    who = ctx.vendors.get(to)
    label = "%s (%s)" % (to, who) if who else ("the vault itself" if to == ctx.vault_id else "%s, an unknown account" % to)
    lines = []
    for a in proposal.get("actions") or []:
        t = a.get("type")
        if t == "Transfer":
            lines.append("Send %s from the vault to %s." % (near(a.get("deposit", 0)), label))
        elif t == "FunctionCall":
            m, args, dep = a.get("method_name", "?"), a.get("args") or {}, int(a.get("deposit", 0) or 0)
            tok = ctx.tokens.get(to)
            if m in ("ft_transfer", "ft_transfer_call") and tok:
                amt = Decimal(int(args.get("amount", 0))) / (Decimal(10) ** tok["decimals"])
                tail = " and let that account's contract run code with it" if m == "ft_transfer_call" else ""
                lines.append("Send %s %s to %s%s." % ("{:f}".format(amt.normalize()), tok["symbol"], args.get("receiver_id", "?"), tail))
            else:
                lines.append("Call %s on %s%s." % (m, label, " with %s attached" % near(dep) if dep else ""))
        elif t == "AddKey":
            perm = (a.get("access_key") or {}).get("permission", "FullAccess")
            if perm == "FullAccess":
                lines.append("Give FULL CONTROL of the vault to key %s: whoever holds it can take everything." % short_key(a.get("public_key")))
            else:
                methods = perm.get("method_names") or []
                lines.append("Let key %s call %s on %s." % (short_key(a.get("public_key")),
                             ", ".join(methods) if methods else "any method", perm.get("receiver_id", "?")))
        elif t == "DeleteKey":
            lines.append("Remove key %s from the vault." % short_key(a.get("public_key")))
        elif t == "DeleteAccount":
            lines.append("DELETE the vault and send everything left (%s) to %s." % (near(ctx.balance), a.get("beneficiary_id", "?")))
        elif t == "DeployContract":
            lines.append("Replace the vault's code with new code.")
        elif t == "Stake":
            lines.append("Stake %s from the vault." % near(a.get("stake", 0)))
        else:
            lines.append("Unknown action %r." % t)
    return lines


def outgoing(proposal, ctx):
    """(receiver, yocto NEAR or None, token or None, raw amount) for each value transfer."""
    to = proposal.get("receiver_id")
    out = []
    for a in proposal.get("actions") or []:
        if a.get("type") == "Transfer":
            out.append((to, int(a.get("deposit", 0)), None, int(a.get("deposit", 0))))
        elif a.get("type") == "FunctionCall":
            args = a.get("args") or {}
            if a.get("method_name") in ("ft_transfer", "ft_transfer_call") and args.get("receiver_id"):
                out.append((args["receiver_id"], None, to, int(args.get("amount", 0))))
            if int(a.get("deposit", 0) or 0) > 1:
                out.append((to, int(a["deposit"]), None, int(a["deposit"])))
    return out


def check(proposal, ctx, now=None):
    """Judge a proposal. Returns {"allow", "risk", "summary", "findings", "explain"}."""
    now = now or time.time()
    findings = []
    add = lambda rule, sev, msg: findings.append(Finding(rule, sev, msg))
    to = proposal.get("receiver_id") or ""
    actions = proposal.get("actions") or []
    known = set(ctx.vendors) | set(ctx.tokens)
    mentioned = accounts_in(ctx.untrusted)
    if ctx.requester:
        mentioned.add(ctx.requester.lower())

    if not actions:
        add("empty", "high", "The transaction does nothing; refusing to sign something malformed.")

    for a in actions:
        t = a.get("type")
        if t == "AddKey":
            perm = (a.get("access_key") or {}).get("permission", "FullAccess")
            if perm == "FullAccess":
                add("full_access_key", "critical", "Adds a full-access key: the account takeover attack. Whoever holds that key owns the vault.")
            else:
                if not perm.get("method_names"):
                    add("broad_key", "high", "Adds a key that may call any method on %s." % perm.get("receiver_id"))
                if perm.get("receiver_id") not in known | {ctx.vault_id}:
                    add("key_for_unknown", "high", "Adds a key for %s, a contract the vault has no business with." % perm.get("receiver_id"))
                else:
                    add("new_key", "high", "Adds a new key to the vault. Keys are only added by the owner, never by the agent.")
        elif t == "DeleteKey":
            add("delete_key", "high", "Removes one of the vault's keys, which can lock the owner out.")
        elif t == "DeleteAccount":
            add("delete_account", "critical", "Deletes the vault and sends its whole balance to %s." % a.get("beneficiary_id"))
        elif t == "DeployContract":
            add("deploy", "critical", "Replaces the vault's code. New code can do anything with the funds.")
        elif t == "Stake":
            add("stake", "high", "Stakes the vault's funds, locking them with a validator.")
        elif t == "FunctionCall":
            m = a.get("method_name", "")
            if to not in known and to != ctx.vault_id:
                add("unknown_contract", "high", "Calls %s on %s, a contract that is not on the approved list." % (m, to))
            if m == "ft_transfer_call" and (a.get("args") or {}).get("receiver_id") not in ctx.vendors:
                add("transfer_call", "high", "ft_transfer_call hands tokens to a contract and lets it run code with them.")
            if re.search(r"(?i)approve|allowance|set_owner|add_owner|grant|upgrade|migrate", m):
                add("permission_call", "high", "Calls %s, which hands out control rather than paying for something." % m)

    named = next((i for i in ctx.invoices if i["id"] == proposal.get("invoice")), None)
    if named and named.get("status") == "paid":
        add("duplicate_invoice", "high", "Invoice %s is already paid; paying it again is a duplicate payment." % named["id"])

    total_near = 0
    for receiver, yocto, token, raw in outgoing(proposal, ctx):
        receiver = (receiver or "").lower()
        if yocto is not None:
            total_near += yocto
        fake = lookalike_of(receiver, set(ctx.vendors))
        if fake:
            add("lookalike", "critical", "%s imitates the approved vendor %s. This is an impersonation scam." % (receiver, fake))
        elif receiver not in ctx.vendors:
            add("unknown_recipient", "high", "%s is not an approved vendor." % receiver)
        if receiver in mentioned and receiver not in ctx.vendors:
            add("requester_paid", "critical", "The money would go to %s, the same account named by the person asking for it." % receiver)
        if receiver in ctx.vendors and yocto is not None:
            open_ = ctx.open_invoices(receiver)
            if not open_:
                paid = [i for i in ctx.invoices if i["vendor"] == receiver]
                add("no_invoice", "high", "%s has no open invoice%s." % (receiver, ": invoice %s is already paid" % paid[-1]["id"] if paid else ""))
            elif not any(int(i["amount"]) == yocto for i in open_):
                add("amount_mismatch", "high", "%s does not match any open invoice from %s (%s)." % (
                    near(yocto), receiver, ", ".join("%s: %s" % (i["id"], near(i["amount"])) for i in open_)))
        if token is not None and receiver in ctx.vendors:
            add("token_payment", "high", "Vendors are paid in NEAR against invoices, not in tokens.")

    if total_near and ctx.balance:
        share = total_near / ctx.balance
        if share >= 0.9:
            add("drain", "critical", "Sends %d%% of the vault's balance in one go." % round(share * 100))
        elif share >= 0.25:
            add("large_share", "high", "Sends %d%% of the vault's balance in one go." % round(share * 100))
    for receiver, yocto, _, _ in outgoing(proposal, ctx):
        if yocto is None:
            continue
        sent = [(t, r, y) for t, r, y in ctx.recent if r == receiver and now - t < ctx.window_s]
        if len(sent) >= 2:
            add("repeat_payments", "high", "%d payments to %s in the last %d minutes: a split or replayed payment." % (
                len(sent) + 1, receiver, ctx.window_s // 60))

    for name, rx in INJECTION:
        hit = rx.search(ctx.untrusted)
        if hit:
            add("injection:" + name.replace(" ", "_"), "medium", "Instruction-like text (%s) came from outside: %r." % (name, hit.group(0)[:60]))
    if REDIRECT.search(ctx.untrusted):
        add("redirect_story", "medium", "The request claims payment details changed: the classic invoice-redirection scam.")

    risk = max((f["severity"] for f in findings), key=SEVERITY.get, default="info")
    allow = risk not in BLOCKING
    if allow and any(f["rule"].startswith("injection:") for f in findings) and total_near:
        # Money moving right after someone tried to give the agent orders.
        add("payment_after_injection", "high", "A payment was proposed right after an attempt to override the agent's instructions.")
        risk, allow = "high", False
    blocking = sorted((f for f in findings if f["severity"] in BLOCKING), key=lambda f: -SEVERITY[f["severity"]])
    summary = ("Allowed" if allow else "Blocked: " + blocking[0]["message"])
    return {"allow": allow, "risk": risk, "summary": summary, "findings": findings, "explain": describe(proposal, ctx)}
