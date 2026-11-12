// Raise an invoice on a vault, signed by the payee's own account.
//
//   node chain/invoice.mjs <payee-account> <amount NEAR> "<memo>"       # payee keys from outwit.json
//   PAYEE_KEY=ed25519:... VAULT=vault.x.testnet node chain/invoice.mjs ...
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, EXPLORER, account, log, toYocto } from "./lib.mjs";

async function main() {
  const [payee, amount, memo = ""] = process.argv.slice(2);
  if (!payee || !amount) throw new Error('usage: node chain/invoice.mjs <payee-account> <amount NEAR> "<memo>"');
  let key = process.env.PAYEE_KEY;
  let vault = process.env.VAULT;
  const cfgPath = join(ROOT, "outwit.json");
  if ((!key || !vault) && existsSync(cfgPath)) {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    const v = cfg.vaults.find((v) => v.payees && v.payees[payee]) || cfg.vaults[0];
    vault = vault || v.vault;
    key = key || (v.payees[payee] || {}).key;
  }
  if (!key || !vault) throw new Error("no key for that payee; set PAYEE_KEY and VAULT");
  const out = await account(payee, key).callFunctionRaw({
    contractId: vault,
    methodName: "create_invoice",
    args: { amount: String(toYocto(amount)), memo },
  });
  const id = JSON.parse(Buffer.from(out.status.SuccessValue, "base64").toString());
  log(`invoice #${id} raised by ${payee} on ${vault}: ${amount} NEAR, ${memo}`);
  log(`${EXPLORER}/txns/${out.transaction.hash}`);
}

main().catch((e) => {
  console.error("invoice failed:", e.message || e);
  process.exitCode = 1;
});
