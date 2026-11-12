// Put the arena on NEAR testnet: owner account, vault contract, Keeper's key,
// vendor accounts. Writes ../arena.json (secret: holds keys; gitignored).
//
//   node chain/setup.mjs                      # new owner account from the testnet faucet
//   OWNER_ACCOUNT=you.testnet OWNER_KEY=ed25519:... node chain/setup.mjs
//
// Build the contract first: (cd contract && cargo build --target wasm32-unknown-unknown --release)
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner } from "near-api-js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RPC = process.env.NEAR_RPC || "https://test.rpc.fastnear.com";
const FAUCET = "https://helper.nearprotocol.com/account";
const WASM = join(ROOT, "contract/target/wasm32-unknown-unknown/release/leash_vault.wasm");
const OUT = join(ROOT, "arena.json");
const NEAR = 10n ** 24n;
const milli = (n) => (BigInt(n) * NEAR) / 1000n;

const VENDORS = { inkwell: "Inkwell Design", nodeworks: "Nodeworks hosting", quillsec: "Quill Security audits" };
// The vault keeps ~2.5 NEAR locked for its code; the rest is the bounty pot.
const POT = milli(process.env.POT_MILLINEAR || 8500);
const POLICY = {
  max_per_payment: String(milli(500)),
  daily_limit: String(milli(3000)),
  max_payments_per_minute: 4,
  allowed_receivers: null,
};

const provider = new JsonRpcProvider({ url: RPC });
const log = (...a) => console.log("•", ...a);

async function faucetAccount() {
  const id = `driftwood-${randomBytes(3).toString("hex")}.testnet`;
  const kp = KeyPair.fromRandom("ed25519");
  const r = await fetch(FAUCET, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ newAccountId: id, newAccountPublicKey: kp.getPublicKey().toString() }),
  });
  if (!r.ok) throw new Error(`faucet refused (${r.status}): ${await r.text()}. Set OWNER_ACCOUNT and OWNER_KEY instead.`);
  for (let i = 0; i < 20; i++) {
    try {
      await provider.viewAccount({ accountId: id });
      return { id, key: kp.toString() };
    } catch {
      await new Promise((ok) => setTimeout(ok, 1500));
    }
  }
  throw new Error(`faucet account ${id} never appeared`);
}

async function main() {
  if (existsSync(OUT) && !process.argv.includes("--force")) throw new Error("arena.json exists; pass --force to set up again");
  if (!existsSync(WASM)) throw new Error(`no contract at ${WASM}; build it first`);

  const owner = process.env.OWNER_ACCOUNT
    ? { id: process.env.OWNER_ACCOUNT, key: process.env.OWNER_KEY }
    : await faucetAccount();
  log("owner", owner.id);
  const ownerAcct = new Account(owner.id, provider, KeyPairSigner.fromSecretKey(owner.key));

  // The vault: a sub-account holding the pot, with the contract on it.
  const vaultId = `vault.${owner.id}`;
  const vaultKp = KeyPair.fromRandom("ed25519");
  await ownerAcct.createSubAccount({ accountOrPrefix: vaultId, publicKey: vaultKp.getPublicKey(), nearToTransfer: POT });
  const vault = new Account(vaultId, provider, KeyPairSigner.fromSecretKey(vaultKp.toString()));
  await vault.deployContract(readFileSync(WASM));
  await vault.callFunction({ contractId: vaultId, methodName: "new", args: { owner: owner.id, guardians: [owner.id] } });
  log("vault", vaultId, "deployed with", Number(POT / milli(1)) / 1000, "NEAR");

  // Keeper's key: may call `pay` on the vault and nothing else.
  const keeperKp = KeyPair.fromRandom("ed25519");
  await ownerAcct.callFunction({
    contractId: vaultId,
    methodName: "add_agent",
    args: { name: "keeper", public_key: keeperKp.getPublicKey().toString(), policy: POLICY },
  });
  log("keeper key", keeperKp.getPublicKey().toString());

  // Vendors: real accounts so invoice payments land somewhere.
  const vendors = {};
  for (const [prefix, label] of Object.entries(VENDORS)) {
    const id = `${prefix}.${owner.id}`;
    await ownerAcct.createSubAccount({
      accountOrPrefix: id,
      publicKey: KeyPair.fromRandom("ed25519").getPublicKey(),
      nearToTransfer: milli(10),
    });
    vendors[id] = label;
    log("vendor", id);
  }

  // Lock the vault: drop its full-access key so only the contract's rules move money.
  if (process.argv.includes("--lock")) {
    await vault.deleteKey(vaultKp.getPublicKey());
    log("vault full-access key deleted: the contract is now the only way in");
  }

  const cfg = {
    rpc: RPC,
    explorer: "https://testnet.nearblocks.io",
    dao: "Driftwood DAO",
    vault: vaultId,
    vault_key: process.argv.includes("--lock") ? null : vaultKp.toString(),
    owner: { account: owner.id, key: owner.key },
    watchdog: { account: owner.id, key: owner.key },
    keeper: { key: keeperKp.toString(), public_key: keeperKp.getPublicKey().toString() },
    vendors,
  };
  writeFileSync(OUT, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  log("wrote arena.json. Start the arena: python3 arena.py");
}

main().catch((e) => {
  console.error("setup failed:", e.message || e);
  process.exitCode = 1;
});
