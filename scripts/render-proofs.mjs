import fs from 'node:fs';
import assert from 'node:assert/strict';

const proof = JSON.parse(fs.readFileSync('PROOFS.json', 'utf8'));
const {address, source_commit: commit, source, transactions, initial, current, extension} = proof;
assert(proof.verified && proof.independent_signature_and_roots_verified && source.source_match);
assert.deepEqual(transactions.map(t => t.step), ['deploy', 'sync']);
assert(transactions.every(t => t.receipt.committed && t.receipt.status === 'FINALIZED'));
assert.deepEqual(extension.old, initial);
assert.deepEqual(extension.new, current);

const repository = 'https://github.com/stoneforger10/go-log-continuity';
const explorer = 'https://explorer-studio.genlayer.com';
const deployed = '[StudioNet contract](' + explorer + '/address/' + address + ')';
const sourceLink = '[Exact deployed source](' + repository + '/blob/' + commit + '/contracts/GoLogContinuity.py)';
const anchor = '[Go-signed deployment anchor](' + repository + '/blob/' + commit + '/fixtures/anchor.note)';
const labels = {deploy: 'Deploy and verify the signed anchor', sync: 'Verify and install a public Go log extension'};
const txLink = t => '[' + labels[t.step] + '](' + explorer + '/tx/' + t.hash + ')';
const delta = current.size - initial.size;
assert(delta > 0);

fs.writeFileSync('LIVE_PROOFS.md', [
  '# StudioNet evidence', '',
  '- ' + deployed,
  '- ' + sourceLink,
  '- ' + anchor,
  '- [Finalized receipts and full consistency witness](PROOFS.json)',
  '- Deployed source SHA-256 ' + source.sha256,
  '', '| Finalized transaction | Execution | Agree votes |', '|---|---|---:|',
  ...transactions.map(t => '| ' + txLink(t) + ' | ' + t.receipt.execution + ' | ' + t.receipt.agree_votes + ' |'), '',
  '| Checkpoint | Size | Signed root |', '|---|---:|---|',
  '| Anchor | ' + initial.size + ' | ' + initial.root + ' |',
  '| Accepted extension | ' + current.size + ' | ' + current.root + ' |',
  '',
  'The checkpoint advanced by ' + delta + ' entries. The independent proof script verified both Ed25519 signatures using Node cryptography and rebuilt both roots from ' +
    extension.frontier.length + ' stored subtree hashes. Mutating a hash caused the reconstructed root to differ.',
  '',
  'Six local tests cover a genuine Go signature, an RFC 8032 test vector, 496 reference tree extensions, rollback, forged proof data and same-size sync.',
  '',
].join('\n'));

const description = [
  'GoLogContinuity maintains a permissionless checkpoint for the public Go module checksum log. The leader fetches a signed candidate and public Merkle tiles in GenLayer’s nondeterministic flow. Validators verify the candidate against the pinned Go Ed25519 key and independently fetch the exact tiles required to prove its relationship to the stored head.',
  'The contract reconstructs both roots using shared prefix subtrees and appended subtrees. An advance stores the new signed checkpoint and the exact proof. Older checkpoints, conflicting roots and invalid proofs fail closed.',
  'StudioNet advanced the deployed anchor by ' + delta + ' entries. An independent verifier checked both signatures and reconstructed both roots. Continuity is anchored to the chosen signed checkpoint and the pinned key.',
].join('\n\n');
assert(description.length <= 1000);
fs.writeFileSync('SUBMISSION.md', [
  '# GoLogContinuity', '', '**Contribution type** Builder → Intelligent Contracts', '',
  '**Description**', '', description, '',
  '**Evidence**', '', '- [GitHub repository](' + repository + ')', '- ' + sourceLink, '- ' + deployed,
  '- [Live proof matrix](' + repository + '/blob/main/LIVE_PROOFS.md)',
  ...transactions.map(t => '- ' + txLink(t)), '',
].join('\n'));
