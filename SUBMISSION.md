# GoLogContinuity

**Contribution type** Builder → Intelligent Contracts

**Description**

GoLogContinuity maintains a permissionless checkpoint for the public Go module checksum log. The leader fetches a signed candidate and public Merkle tiles in GenLayer’s nondeterministic flow. Validators verify the candidate against the pinned Go Ed25519 key and independently fetch the exact tiles required to prove its relationship to the stored head.

The contract reconstructs both roots using shared prefix subtrees and appended subtrees. An advance stores the new signed checkpoint and the exact proof. Older checkpoints, conflicting roots and invalid proofs fail closed.

StudioNet advanced the deployed anchor by 432 entries. An independent verifier checked both signatures and reconstructed both roots. Continuity is anchored to the chosen signed checkpoint and the pinned key.

**Evidence**

- [GitHub repository](https://github.com/stoneforger10/go-log-continuity)
- [Exact deployed source](https://github.com/stoneforger10/go-log-continuity/blob/1b2d0b15fe6a5527f2819c87b0131a7d93bc6a3d/contracts/GoLogContinuity.py)
- [StudioNet contract](https://explorer-studio.genlayer.com/address/0xDb52b0d3669025ce1536fB49bC5C269eC52C3f87)
- [Live proof matrix](https://github.com/stoneforger10/go-log-continuity/blob/main/LIVE_PROOFS.md)
- [Deploy and verify the signed anchor](https://explorer-studio.genlayer.com/tx/0x8f9d784704d4f5e3d955f1389d31b54d97770a38b47f35978c0c0612f153f8c4)
- [Verify and install a public Go log extension](https://explorer-studio.genlayer.com/tx/0x2af6d039690216532e6426d35b4348aa6cf1d039fb6479fe5cd320d824c32e11)
