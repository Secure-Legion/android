# Vendored snow 0.10.0

Source: crates.io snow 0.10.0 (MIT/Apache-2.0; original licenses retained).
Local change: zeroize owned X25519/ChaChaPoly keys, chaining-key checkpoints,
HKDF temporary key buffers and DH result buffers. No Noise algorithm or wire
format change. This is a local hardening patch, not an independent audit.
Run the upstream test suite and Secure session tests before release.
Memory erasure is best effort; register/compiler copies and endpoint compromise
are outside a guarantee that every physical copy is erased.

Also reject non-contributory all-zero X25519 DH results and avoid enabling
unused ring/Blake2 backends through weak std feature forwarding.
