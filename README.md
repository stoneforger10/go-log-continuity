# GoLogContinuity

Maintain a verified onchain checkpoint for the public Go module checksum log. Anyone can call `sync()`. The transaction can advance the checkpoint only when the Go log signs the new root and the publicly fetched Merkle hashes prove that the previous tree is an exact prefix. Applications can read the current head or independently replay a stored extension.

## Evidence and consensus

The deployment takes a Base64-encoded signed Go checksum log note. It checks the note against the Ed25519 public key embedded in the Go toolchain. The example deployment uses [the captured Go checkpoint](fixtures/anchor.note).

For a sync, the leader fetches the signed note from `https://sum.golang.org/latest` inside a GenLayer nondeterministic block. It retrieves the hash tiles for the two aligned ranges `[0, oldSize)` and `[oldSize, newSize)`. The validator independently checks the exact candidate's Go signature, fetches its tiles again, and reconstructs both the previous and new roots from the shared prefix. The contract compares the exact proof hashes and checks the proof again before writing. This verification stays bound to the signed candidate size as the public log grows. [Go checksum log protocol](https://go.dev/ref/mod#checksum-database) · [GenLayer nondeterminism](https://docs.genlayer.com/developers/intelligent-contracts/features/non-determinism)

The proof contains the subtree roots of the greedy aligned power-of-two cover of each range, in order. Nodes are hashed as `SHA256(0x01 || left || right)`. Merge adjacent equal-height subtrees and fold remaining roots from right to left. Folding just the prefix must yield the previous root. Folding the prefix and suffix must yield the signed new root. The report exposes the signed notes and every subtree hash needed to verify the transition. [Go tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) · [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)

## Calls

- `head()` returns the accepted size, root and full signed note.
- `sync()` fetches the current candidate, verifies continuity, and returns its accepted size. A same-size, same-root note returns the current size. Rollback, conflicting roots and missing or altered tiles fail closed.
- `extension(size)` returns the previous note, new note and ordered consistency hashes for a recorded advance.

Continuity is relative to the chosen signed anchor and the pinned Go signing key. A valid candidate may lag the newest log head. This contract establishes prefix consistency for its own observed sequence. Detecting a split view elsewhere requires comparing independent checkpoints.

```sh
python -m pip install -r requirements-dev.txt
genvm-lint check contracts/GoLogContinuity.py
python -m pytest tests -q
```

[StudioNet contract](https://explorer-studio.genlayer.com/address/0xDb52b0d3669025ce1536fB49bC5C269eC52C3f87) · [Live proof matrix](LIVE_PROOFS.md) · [Submission text](SUBMISSION.md)
