// Shared helpers for the Outwit chain scripts.
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner } from "near-api-js";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const RPC = process.env.NEAR_RPC || "https://test.rpc.fastnear.com";
export const EXPLORER = "https://testnet.nearblocks.io";
export const WASM = join(ROOT, "contract/target/wasm32-unknown-unknown/release/outwit_vault.wasm");
const FAUCET = "https://helper.nearprotocol.com/account";
export const NEAR = 10n ** 24n;
export const toYocto = (near) => {
  const [w, f = ""] = String(near).split(".");
  return BigInt(w) * NEAR + BigInt((f + "0".repeat(24)).slice(0, 24));
};

export const provider = new JsonRpcProvider({ url: RPC });
export const log = (...a) => console.log("•", ...a);
export const account = (id, key) => new Account(id, provider, KeyPairSigner.fromSecretKey(key));
export const newKey = () => KeyPair.fromRandom("ed25519");

/** A new top-level .testnet account: paid for by FUNDER_ACCOUNT/FUNDER_KEY when set, else the testnet faucet. */
export async function newAccount(prefix, fundNear) {
  const { FUNDER_ACCOUNT, FUNDER_KEY } = process.env;
  if (!FUNDER_ACCOUNT) return faucetAccount(prefix);
  const id = `${prefix}-${randomBytes(3).toString("hex")}.testnet`;
  const kp = newKey();
  await account(FUNDER_ACCOUNT, FUNDER_KEY).createAccount({
    newAccountId: id,
    publicKey: kp.getPublicKey(),
    nearToTransfer: toYocto(fundNear),
  });
  return { id, key: kp.toString() };
}

export async function faucetAccount(prefix) {
  const id = `${prefix}-${randomBytes(3).toString("hex")}.testnet`;
  const kp = newKey();
  const r = await fetch(FAUCET, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ newAccountId: id, newAccountPublicKey: kp.getPublicKey().toString() }),
  });
  if (!r.ok) throw new Error(`testnet faucet refused (${r.status}): ${await r.text()}`);
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

export function wasm() {
  if (!existsSync(WASM)) throw new Error(`no contract at ${WASM}; run: (cd contract && cargo build --target wasm32-unknown-unknown --release)`);
  return readFileSync(WASM);
}

/** Create vault.<owner>, deploy the contract, set the guard, fund it. Returns the vault id and its key. */
export async function deployVault(owner, guardId, fundNear) {
  const vaultId = `vault.${owner.accountId}`;
  const kp = newKey();
  await owner.createSubAccount({ accountOrPrefix: vaultId, publicKey: kp.getPublicKey(), nearToTransfer: toYocto(fundNear) });
  const vault = account(vaultId, kp.toString());
  await vault.deployContract(wasm());
  await vault.callFunction({ contractId: vaultId, methodName: "new", args: { owner: owner.accountId, guards: [guardId] } });
  return { vaultId, vaultKey: kp.toString(), vault };
}

export async function addAgent(owner, vaultId, name, policy) {
  const kp = newKey();
  await owner.callFunction({
    contractId: vaultId,
    methodName: "add_agent",
    args: { name, public_key: kp.getPublicKey().toString(), policy },
  });
  return { key: kp.toString(), public_key: kp.getPublicKey().toString() };
}

export const policy = ({ maxPerPayment = "0.5", dailyLimit = "3", perMinute = 6, payeesOnly = false } = {}) => ({
  max_per_payment: String(toYocto(maxPerPayment)),
  daily_limit: String(toYocto(dailyLimit)),
  max_proposals_per_minute: perMinute,
  payees_only: payeesOnly,
});
