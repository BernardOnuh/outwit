// Connect your own AI agent to Outwit on NEAR testnet.
//
//   OWNER_ACCOUNT=you.testnet OWNER_KEY=ed25519:... \
//   node chain/connect.mjs --guard outwit-guard-xxxx.testnet --guard-url https://outwit.example \
//        --payee api.someone.testnet="Search API" --fund 5 [--agent my-agent] [--max 0.5] [--daily 3]
//
// Creates vault.<you>, deploys the Outwit vault contract with Outwit as its
// guard, registers your payees, gives your agent a key that can only propose,
// tells the guard to start watching, and prints what to put in your agent.
import { account, addAgent, deployVault, log, policy } from "./lib.mjs";

function args() {
  const a = { payees: [], agent: "agent", fund: "5", max: "0.5", daily: "3" };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i].replace(/^--/, "");
    const v = argv[++i];
    if (k === "payee") a.payees.push(v);
    else a[k.replace(/-(\w)/g, (_, c) => c.toUpperCase())] = v;
  }
  return a;
}

async function main() {
  const a = args();
  const { OWNER_ACCOUNT, OWNER_KEY } = process.env;
  if (!OWNER_ACCOUNT || !OWNER_KEY) throw new Error("set OWNER_ACCOUNT and OWNER_KEY (your funded testnet account)");
  if (!a.guard) throw new Error("--guard <Outwit guard account> is required");
  const owner = account(OWNER_ACCOUNT, OWNER_KEY);

  const { vaultId } = await deployVault(owner, a.guard, a.fund);
  log("vault", vaultId, "deployed, guarded by", a.guard);
  for (const p of a.payees) {
    const [id, label = id] = p.split("=");
    await owner.callFunction({ contractId: vaultId, methodName: "add_payee", args: { account_id: id, label } });
    log("payee", id, `(${label})`);
  }
  const agent = await addAgent(owner, vaultId, a.agent, policy({ maxPerPayment: a.max, dailyLimit: a.daily }));
  log("agent key (can only propose)", agent.public_key);

  if (a.guardUrl) {
    const r = await fetch(a.guardUrl.replace(/\/$/, "") + "/v1/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vault_id: vaultId }),
    });
    log("guard:", r.ok ? "now watching your vault" : `could not connect (${r.status}): ${await r.text()}`);
  }

  console.log(`
Your agent's settings (keep the key secret):

  OUTWIT_VAULT=${vaultId}
  OUTWIT_AGENT_KEY=${agent.key}
  OUTWIT_GUARD_URL=${a.guardUrl || "<the Outwit guard URL>"}

MCP (Claude, NEAR AI agents, any MCP client):
  {"mcpServers": {"outwit": {"command": "python3", "args": ["<path>/outwit/mcp_server.py"],
    "env": {"OUTWIT_VAULT": "${vaultId}", "OUTWIT_AGENT_KEY": "<the key above>", "OUTWIT_GUARD_URL": "${a.guardUrl || "<url>"}"}}}}

Python:
  from outwit_client import Outwit
  ow = Outwit("${vaultId}", agent_key, guard_url="${a.guardUrl || "<url>"}")
  ow.pay("payee.testnet", "0.1", invoice_id=0, context=conversation)
`);
}

main().catch((e) => {
  console.error("connect failed:", e.message || e);
  process.exitCode = 1;
});
