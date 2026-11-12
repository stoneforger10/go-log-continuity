import fs from 'node:fs';
import {spawn, execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {createPublicKey, verify} from 'node:crypto';
import {rpc, receipt, source, read, sha} from './check.mjs';

const code = 'contracts/GoLogContinuity.py';
const publisher = {name: 'studio-proof-deployer', address: '0x7a413BB4AB62E31d62d4cD9efC8C8a8Dae37FB42'};
const journal = 'PROOFS.json';
const commit = process.argv[2];
const verifyOnly = process.argv.includes('--verify-only');
assert(/^[a-f0-9]{40}$/.test(commit ?? ''));
const proof = fs.existsSync(journal)
  ? JSON.parse(fs.readFileSync(journal, 'utf8'))
  : {network: 'StudioNet', source_commit: commit, transactions: []};
assert.equal(proof.source_commit, commit);
const save = () => fs.writeFileSync(journal, JSON.stringify(proof, null, 2) + '\n');

function send(args, signer, entry) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/run-cli.cjs', ...args], {
      windowsHide: true,
      env: {...process.env, SUMDB_TEST_ACCOUNT: signer.name},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let pending = '';
    child.stderr.resume();
    child.stdout.on('data', chunk => {
      const lines = (pending + chunk.toString()).split(/\r?\n/);
      pending = lines.pop();
      for (const line of lines) {
        const matched = /^BROADCAST_HASH (0x[0-9a-f]{64})$/i.exec(line);
        if (matched) {
          entry.hash = matched[1];
          save();
          console.log(entry.step, entry.hash);
        }
      }
    });
    child.on('error', reject);
    child.on('close', resolve);
  });
}

async function transaction(step, args, signer) {
  let entry = proof.transactions.find(item => item.step === step);
  if (!entry) {
    assert(!verifyOnly, 'Verification requires an original broadcast journal');
    const nonce = await rpc('eth_getTransactionCount', [signer.address, 'latest']);
    assert.equal(await rpc('eth_getTransactionCount', [signer.address, 'pending']), nonce);
    entry = {step, args, signer: signer.address, nonce};
    proof.transactions.push(entry);
    save();
    await send(args, signer, entry);
  }
  assert.deepEqual(entry.args, args);
  assert.equal(entry.signer, signer.address);
  assert(entry.hash, 'Broadcast status unknown. Inspect account history before any retry.');
  entry.receipt = await receipt(entry.hash);
  save();
  assert(entry.receipt.committed, 'Transaction did not commit');
  const native = await rpc('eth_getTransactionByHash', [entry.hash]);
  assert.equal(native.from_address.toLowerCase(), signer.address.toLowerCase());
  assert.equal(BigInt(native.nonce), BigInt(entry.nonce));
  assert.equal(BigInt(native.value), 0n);
  console.log(step, entry.receipt.status, entry.receipt.execution);
  return entry.receipt.address;
}



const trustedKey = createPublicKey({
  key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from('Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8=', 'base64').subarray(1),
  ]),
  format: 'der', type: 'spki',
});

function verifyNote(note) {
  const [content, signed, remainder] = note.split('\n\n');
  assert.equal(remainder, undefined);
  const [format, sizeText, rootText] = content.split('\n');
  assert.equal(format, 'go.sum database tree');
  const match = /^— sum\.golang\.org ([A-Za-z0-9+/]+=)\n$/.exec(signed);
  assert(match);
  const signature = Buffer.from(match[1], 'base64');
  assert.equal(signature.subarray(0, 4).toString('hex'), '033de0ae');
  assert(verify(null, Buffer.from(content + '\n'), trustedKey, signature.subarray(4)));
  const size = Number(sizeText);
  assert(Number.isSafeInteger(size) && size > 0);
  const root = Buffer.from(rootText, 'base64').toString('hex');
  assert.equal(root.length, 64);
  return {size, root, note};
}

function alignedIntervals(start, stop) {
  const intervals = [];
  while (start < stop) {
    let step = 1;
    while (step * 2 <= stop - start && start % (step * 2) === 0) step *= 2;
    intervals.push([start, start + step]);
    start += step;
  }
  return intervals;
}

function rebuild(nodes, start, stop) {
  const found = nodes.get(start + ':' + stop);
  if (found) return found;
  const length = stop - start;
  assert(length > 1, 'Missing subtree proof');
  const cut = start + 2 ** Math.floor(Math.log2(length - 1));
  const combined = Buffer.concat([Buffer.from([1]), rebuild(nodes, start, cut), rebuild(nodes, cut, stop)]);
  return Buffer.from(sha(combined), 'hex');
}

function verifyExtension(extension) {
  const {old, new: next, frontier} = extension;
  assert.deepEqual(verifyNote(old.note), old);
  assert.deepEqual(verifyNote(next.note), next);
  assert(next.size > old.size);
  const intervals = [...alignedIntervals(0, old.size), ...alignedIntervals(old.size, next.size)];
  assert.equal(intervals.length, frontier.length);
  assert(frontier.every(node => /^[0-9a-f]{64}$/.test(node)));
  const nodes = new Map(intervals.map(([start, end], i) => [start + ':' + end, Buffer.from(frontier[i], 'hex')]));
  assert.equal(rebuild(nodes, 0, old.size).toString('hex'), old.root);
  assert.equal(rebuild(nodes, 0, next.size).toString('hex'), next.root);
  const [start, end] = intervals.at(-1);
  nodes.set(start + ':' + end, Buffer.alloc(32));
  assert.notEqual(rebuild(nodes, 0, next.size).toString('hex'), next.root);
}

const safeDir = 'safe.directory=' + process.cwd().replaceAll('\\', '/');
const anchor = execFileSync('git', ['-c', safeDir, 'show', commit + ':fixtures/anchor.note']);
const initial = verifyNote(anchor.toString('utf8'));
assert.equal(await rpc('eth_chainId', []), '0xf22f');
proof.address = await transaction('deploy', ['deploy', '--contract', code, '--args', anchor.toString('base64')], publisher);
proof.source = await source(proof.address);
save();
if (!proof.transactions.some(item => item.step === 'sync')) {
  const initialRead = await read(proof.address, 'head', []);
  assert.deepEqual(initialRead, initial);
  proof.initial = initialRead;
  save();
}

assert.equal(await transaction('sync', ['write', proof.address, 'sync'], publisher), proof.address);
const current = await read(proof.address, 'head', []);
proof.current = current;
save();
assert(current.size > initial.size, 'Go checkpoint did not advance in this attempt');
const extension = await read(proof.address, 'extension', [current.size]);
proof.extension = extension;
save();
assert.deepEqual(extension.old, initial);
assert.deepEqual(extension.new, current);
verifyExtension(extension);
proof.independent_signature_and_roots_verified = true;

const history = await rpc('sim_getTransactionsForAddress', [proof.address]);
assert.deepEqual(history.map(t => t.hash).sort(), proof.transactions.map(t => t.hash).sort());
proof.verified = true;
save();
console.log('Verified signed checkpoint extension', initial.size, '→', current.size, 'with', extension.frontier.length, 'hashes');
