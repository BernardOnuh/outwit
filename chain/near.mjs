// Sign and send one NEAR function call for the Python side, which has no
// ed25519 in its standard library. Reads a JSON request on stdin, so keys
// never show up in the process list, and prints a JSON result on stdout:
//
//   {"rpc", "account", "key", "contract", "method", "args", "gas"?, "deposit"?}
//   -> {"ok": true, "tx": "<hash>", "result": <return value>, "logs": [...]}
//   -> {"ok": false, "error": "<message>", "tx"?: "<hash>"}
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";

const TGAS = 10n ** 12n;

async function readStdin() {
  let data = "";
  for await (const chunk of process.stdin) data += chunk;
  return JSON.parse(data);
}

function decode(status) {
  const value = status && status.SuccessValue;
  if (value === undefined) return undefined;
  if (value === "") return null;
  const text = Buffer.from(value, "base64").toString();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function failure(status) {
  const f = status && status.Failure;
  if (!f) return null;
  const exec = f.ActionError && f.ActionError.kind && f.ActionError.kind.FunctionCallError;
  const panic = exec && exec.ExecutionError;
  return panic || JSON.stringify(f);
}

async function main() {
  const req = await readStdin();
  const provider = new JsonRpcProvider({ url: req.rpc });
  const account = new Account(req.account, provider, KeyPairSigner.fromSecretKey(req.key));
  let out;
  try {
    out = await account.callFunctionRaw({
      contractId: req.contract,
      methodName: req.method,
      args: req.args || {},
      gas: BigInt(req.gas || 30) * TGAS,
      deposit: BigInt(req.deposit || 0),
      waitUntil: "EXECUTED_OPTIMISTIC",
    });
  } catch (e) {
    const tx = e && e.context && e.context.transactionHash;
    return { ok: false, error: String((e && e.message) || e), ...(tx ? { tx } : {}) };
  }
  const tx = out.transaction && out.transaction.hash;
  const logs = (out.receipts_outcome || []).flatMap((r) => r.outcome.logs);
  const err = failure(out.status);
  if (err) return { ok: false, tx, error: err, logs };
  return { ok: true, tx, result: decode(out.status), logs };
}

main()
  .then((r) => process.stdout.write(JSON.stringify(r) + "\n"))
  .catch((e) => {
    process.stdout.write(JSON.stringify({ ok: false, error: String((e && e.message) || e) }) + "\n");
    process.exitCode = 1;
  });
