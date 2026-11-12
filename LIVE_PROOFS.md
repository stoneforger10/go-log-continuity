# StudioNet evidence

- [StudioNet contract](https://explorer-studio.genlayer.com/address/0xDb52b0d3669025ce1536fB49bC5C269eC52C3f87)
- [Exact deployed source](https://github.com/stoneforger10/go-log-continuity/blob/1b2d0b15fe6a5527f2819c87b0131a7d93bc6a3d/contracts/GoLogContinuity.py)
- [Go-signed deployment anchor](https://github.com/stoneforger10/go-log-continuity/blob/1b2d0b15fe6a5527f2819c87b0131a7d93bc6a3d/fixtures/anchor.note)
- [Finalized receipts and full consistency witness](PROOFS.json)
- Deployed source SHA-256 516947aee80cc36c4eb893999c8fcfec840dc855ed3879a8652471b8f22ca3b7

| Finalized transaction | Execution | Agree votes |
|---|---|---:|
| [Deploy and verify the signed anchor](https://explorer-studio.genlayer.com/tx/0x8f9d784704d4f5e3d955f1389d31b54d97770a38b47f35978c0c0612f153f8c4) | SUCCESS | 3 |
| [Verify and install a public Go log extension](https://explorer-studio.genlayer.com/tx/0x2af6d039690216532e6426d35b4348aa6cf1d039fb6479fe5cd320d824c32e11) | SUCCESS | 3 |

| Checkpoint | Size | Signed root |
|---|---:|---|
| Anchor | 71228729 | 225d42cbd08da5c1f0a683c57d0cafe3bb5bf857d273cd21754705d318d3331d |
| Accepted extension | 71229161 | 675907f562b0ee5c42ffbac4d8454be14f489163427af73ef8913abd5601b80b |

The checkpoint advanced by 432 entries. The independent proof script verified both Ed25519 signatures using Node cryptography and rebuilt both roots from 26 stored subtree hashes. Mutating a hash caused the reconstructed root to differ.

Six local tests cover a genuine Go signature, an RFC 8032 test vector, 496 reference tree extensions, rollback, forged proof data and same-size sync.
