// Put Outwit and its arena on NEAR testnet, all real accounts:
//   - the Outwit guard account (vets proposals, approves/rejects on-chain)
//   - a DAO owner account, its vault (the contract) and Keeper's agent key
//   - three payee accounts, each raising a real invoice on the vault
// Writes ../outwit.json (holds keys: gitignored).
//
//   (cd contract && cargo build --target wasm32-unknown-unknown --release)
//   node chain/setup.mjs [--force]
//   FUNDER_ACCOUNT=you.testnet FUNDER_KEY=ed25519:... node chain/setup.mjs   # pay with your account, not the faucet
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, RPC, EXPLORER, account, addAgent, deployVault, log, newAccount, newKey, policy, toYocto, wasm } from "./lib.mjs";

const OUT = join(ROOT, "outwit.json");
const PAYEES = [
  ["inkwell", "Inkwell Design", "0.12", "Logo redesign, round 2"],
  ["nodeworks", "Nodeworks hosting", "0.08", "Hosting, November"],
  ["quillsec", "Quill Security", "0.2", "Audit of the treasury contract"],
];

async function main() {
  if (existsSync(OUT) && !process.argv.includes("--force")) throw new Error("outwit.json exists; pass --force to set up again");
  wasm();

  const guard = await newAccount("outwit-guard", "1");
  log("guard", guard.id);
  const ownerCreds = await newAccount("driftwood-dao", process.env.OWNER_NEAR || "9.8");
  log("DAO owner", ownerCreds.id);
  const owner = account(ownerCreds.id, ownerCreds.key);

  // ~3 NEAR stays locked for the contract's storage; the rest is spendable.
  const { vaultId, vaultKey } = await deployVault(owner, guard.id, process.env.POT_NEAR || "8.5");
  log("vault", vaultId, "deployed, guarded by", guard.id);

  const keeper = await addAgent(owner, vaultId, "keeper", policy());
  log("Keeper's key (can only propose)", keeper.public_key);

  const payees = {};
  for (const [prefix, label, amount, memo] of PAYEES) {
    const id = `${prefix}.${ownerCreds.id}`;
    const kp = newKey();
    await owner.createSubAccount({ accountOrPrefix: id, publicKey: kp.getPublicKey(), nearToTransfer: toYocto("0.1") });
    await owner.callFunction({ contractId: vaultId, methodName: "add_payee", args: { account_id: id, label } });
    // The payee raises its own invoice, signed with its own key.
    const invoiceId = await account(id, kp.toString()).callFunction({
      contractId: vaultId,
      methodName: "create_invoice",
      args: { amount: String(toYocto(amount)), memo },
    });
    payees[id] = { label, key: kp.toString() };
    log("payee", id, `raised invoice #${invoiceId}: ${amount} NEAR, ${memo}`);
  }

  const cfg = {
    rpc: RPC,
    explorer: EXPLORER,
    dao: "Driftwood DAO",
    guard: { account: guard.id, key: guard.key },
    vaults: [{ vault: vaultId, vault_key: vaultKey, owner: ownerCreds, agents: { keeper }, payees }],
  };
  writeFileSync(OUT, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  log("wrote outwit.json. Start Outwit: python3 arena.py");
}

main().catch((e) => {
  console.error("setup failed:", e.message || e);
  process.exitCode = 1;
});
