# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add known-answer vectors for multisignature transcript compatibility [#71]
- Add MuSig-style delinearized key aggregation to multisig for
  rogue-key protection, with `aggregate_pk` function for computing
  the verification key
- Add the one-shot `MultisigNonce` state [#53]
- Add `Error::InvalidMultisigTranscript` for malformed multisignature inputs
  [#53]
- Add `Error::InvalidMultisigShare` for invalid multisignature shares [#65]
- Add `multisig::verify_share` for validating a participant's signature share
  before aggregation [#65]

### Removed

- Remove `PartialOrd` and `Ord` from `SecretKey` [#54]
- Remove `Copy` from `SecretKeyVarGen` [#55]

### Changed

- Deduplicate multisignature aggregate-key derivation [#69]
- Redact secret scalar material from `SecretKey` and `SecretKeyVarGen` debug
  output [#52]
- Change `multisig::combine` to return a `Result` [#58]
- Change `multisig::combine` to reject invalid shares before aggregation [#65]
- Replace reusable raw multisignature nonce scalars with an opaque,
  zeroizing, one-shot state consumed by `sign_round_2`; require `R_vec` and
  `S_vec` to be index-aligned with `pk_vec`, with the signer's key appearing
  exactly once [#53]
- Change the double-signature challenge format to domain-separate it and bind
  both public keys; existing double signatures no longer verify, and new
  signatures do not verify with earlier versions [#51]
- Use hedged nonce generation with variant-specific domain separators
  in all Schnorr sign variants to prevent secret key recovery under
  weak RNGs
- Include generator point in VarGen Schnorr challenge hash
- Update `dusk-poseidon` to v0.42.0-rc.0
- Update `dusk-plonk` to 0.22.0-rc.0
- Move to stable MSRV 1.85
- Move to rust edition 2024

### Fixed

- Pin the absent secret-key ordering and implicit-copy trait diagnostics [#63]
- Pin the absent `Copy` trait diagnostic for `SecretKey` [#12]
- Include all features and targets in Clippy checks [#64]
- Reject empty or mismatched participant vectors in `multisig::combine` [#58]
- Check that reusing a consumed `MultisigNonce` emits E0382 [#60]
- Zeroize `SecretKey` when converting it into `SecretKeyVarGen` [#55]

## [0.6.0] - 2025-02-06

### Changed

- Update `dusk-poseidon` to v0.41
- Update `dusk-bls12_381` to v0.14
- Update `dusk-jubjub` to v0.15
- Update `dusk-plonk` to 0.21
- Serde feature no longer has any std dependence [#3596]

## [0.5.1] - 2024-12-17

### Added

- Add serde `Serialize` and `Deserialize` implementations for `PublicKey`, `SecretKey`, `Signature`,
`PublicKeyDouble`, `SignatureDouble`, `PublicKeyVarGen`, `SecretKeyVarGen` and `SignatureVarGen` [#29]
- Add `serde`, `bs58` and `serde_json` optional dependencies [#29]
- Add `serde` feature [#29]

## [0.5.0] - 2024-08-14

### Changed

- Update to dusk-plonk v0.20.0
- Update to dusk-poseidon v0.40.0

## [0.4.0] - 2024-05-22

### Removed

- Remove features: `"alloc", "std", "default"` [#21]
- Remove features: `"double", "var_generator", "multisig"` [#25]
- Remove `append` method in all signature variants [#23]

### Added

- Add `"zk"` feature [#21]

### Changed

- Update to new `dusk-poseidon` API, v0.39 [#19]

## [0.3.0] - 2024-04-24

### Changed

- Change `verify` methods to return a `Result` instead of a `bool` [#14]

### Added

- Add `Zeroize` trait implementation for `SecretKey` [#12]
- Add enum `Error` to differeniate different errors in signature verification [#14]
- Add point validity checks in signature verifications [#14]

### Removed

- Remove `Copy` trait from `SecretKey` [#12]
- Remove `From<SecretKey>` for `PublicKey`, use `From<&SecretKey>` instead [#12]

## [0.2.2] - 2024-03-11

### Added

- Add `Eq` trait to all public keys structs [#9]

## [0.2.1] - 2024-02-28

### Added

- Add a multisignature scheme [#2]

## [0.2.0] - 2024-01-24

### Changed

- Change challenge computation adding the public key to the hash [#3]

## [0.1.0] - 2024-01-08

### Added

- Add initial commit, this package continues the development of [dusk-schnorr](https://github.com/dusk-network/schnorr/) at version `0.18.0` under the new name: jubjub-schnorr

<!-- ISSUES -->
[#71]: https://github.com/dusk-network/jubjub-schnorr/issues/71
[#69]: https://github.com/dusk-network/jubjub-schnorr/issues/69
[#63]: https://github.com/dusk-network/jubjub-schnorr/issues/63
[#64]: https://github.com/dusk-network/jubjub-schnorr/issues/64
[#65]: https://github.com/dusk-network/jubjub-schnorr/issues/65
[#58]: https://github.com/dusk-network/jubjub-schnorr/issues/58
[#60]: https://github.com/dusk-network/jubjub-schnorr/issues/60
[#54]: https://github.com/dusk-network/jubjub-schnorr/issues/54
[#55]: https://github.com/dusk-network/jubjub-schnorr/issues/55
[#52]: https://github.com/dusk-network/jubjub-schnorr/issues/52
[#53]: https://github.com/dusk-network/jubjub-schnorr/issues/53
[#51]: https://github.com/dusk-network/jubjub-schnorr/issues/51
[#3596]: https://github.com/dusk-network/rusk/issues/3596
[#29]: https://github.com/dusk-network/jubjub-schnorr/issues/29
[#25]: https://github.com/dusk-network/jubjub-schnorr/issues/25
[#23]: https://github.com/dusk-network/jubjub-schnorr/issues/23
[#21]: https://github.com/dusk-network/jubjub-schnorr/issues/21
[#19]: https://github.com/dusk-network/jubjub-schnorr/issues/19
[#14]: https://github.com/dusk-network/jubjub-schnorr/issues/14
[#12]: https://github.com/dusk-network/jubjub-schnorr/issues/12
[#9]: https://github.com/dusk-network/jubjub-schnorr/issues/9
[#3]: https://github.com/dusk-network/jubjub-schnorr/issues/3
[#2]: https://github.com/dusk-network/jubjub-schnorr/issues/2

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/jubjub-schnorr/releases/tag/v0.1.0
