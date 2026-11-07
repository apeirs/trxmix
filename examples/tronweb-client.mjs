// An unmodified TronWeb 6.5.1 client pointed at `trxmix serve`. It knows
// nothing about Nym: only fullHost differs.
//
//   trxmix serve &
//   node --require ./no-bypass-hook.cjs tronweb-client.mjs [http://127.0.0.1:8090]
//
// With TRXMIX_TEST_KEYFILE=key.json ({"privateKey": ...} of a fresh, unfunded
// Nile key) it also signs a 1-sun Nile transfer locally and broadcasts it. The
// key is never printed. Nile has no account for it, so the node must reject it.
import { readFileSync } from 'node:fs';
import { TronWeb } from 'tronweb';

const base = process.argv[2] || 'http://127.0.0.1:8090';
const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const holder = 'TKHuVq1oKVruCGLvqVexFs6dawKv6fQgFs';
const erc20 = [
  { name: 'name', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ name: 'who', type: 'address' }], outputs: [{ type: 'uint256' }] },
];

async function step(name, fn) {
  const t0 = performance.now();
  try {
    console.log(`${name}: ${await fn()}  (${((performance.now() - t0) / 1000).toFixed(1)} s)`);
  } catch (e) {
    console.log(`${name}: ERROR ${e?.message ?? e}  (${((performance.now() - t0) / 1000).toFixed(1)} s)`);
  }
}

const mainnet = new TronWeb({ fullHost: base });
const nile = new TronWeb({ fullHost: base + '/nile' });
const shasta = new TronWeb({ fullHost: base + '/shasta' });
console.log(`TronWeb ${TronWeb.version} fullHost = ${base} (mainnet), ${base}/nile, ${base}/shasta`);

await step('mainnet trx.getCurrentBlock', async () => `#${(await mainnet.trx.getCurrentBlock()).block_header.raw_data.number}`);
await step(`mainnet trx.getBalance ${holder}`, async () => `${(await mainnet.trx.getBalance(holder)) / 1e6} TRX`);
await step('mainnet trx.getAccountResources', async () => `energy limit ${(await mainnet.trx.getAccountResources(holder)).EnergyLimit}`);
await step('mainnet contract(USDT).name()', async () => {
  mainnet.setAddress(USDT); // constant calls need an owner address; no key involved
  const c = mainnet.contract(erc20, USDT);
  return await c.name().call();
});
await step(`mainnet contract(USDT).balanceOf(${holder})`, async () => {
  const c = mainnet.contract(erc20, USDT);
  return `${(await c.balanceOf(holder).call()).toString()} (6 decimals)`;
});
await step('mainnet contract().at(USDT) (ABI fetched from the node)', async () => {
  const c = await mainnet.contract().at(USDT);
  return `${c.abi.length} ABI entries`;
});
await step('mainnet trx.getChainParameters', async () => `${(await mainnet.trx.getChainParameters()).length} parameters`);
await step('nile trx.getCurrentBlock', async () => `#${(await nile.trx.getCurrentBlock()).block_header.raw_data.number}`);
await step('shasta trx.getCurrentBlock', async () => `#${(await shasta.trx.getCurrentBlock()).block_header.raw_data.number}`);

const keyfile = process.env.TRXMIX_TEST_KEYFILE;
if (keyfile) {
  const { privateKey } = JSON.parse(readFileSync(keyfile, 'utf8'));
  const from = TronWeb.address.fromPrivateKey(privateKey);
  const to = 'TVKfvNUMcZdZbxhPLb2CkQ4nyUUhvwhv1b';
  await step(`nile trx.getAccount ${from} (fresh key)`, async () => JSON.stringify(await nile.trx.getAccount(from)));
  let signed;
  await step('nile transactionBuilder.sendTrx + trx.sign (built and signed locally, 1 sun)', async () => {
    const tx = await nile.transactionBuilder.sendTrx(to, 1, from);
    signed = await nile.trx.sign(tx, privateKey);
    return `txID ${signed.txID}, ${signed.signature.length} signature`;
  });
  await step('nile trx.sendRawTransaction (signed)', async () => {
    const r = await nile.trx.sendRawTransaction(signed);
    const msg = r.message ? Buffer.from(r.message, 'hex').toString() : '';
    return `result=${r.result ?? false} code=${r.code ?? '-'} message="${msg}"`;
  });
}
