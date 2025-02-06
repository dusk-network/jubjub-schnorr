# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Update `dusk-poseidon` to v0.41
- Update `dusk-bls12_381` to v0.14
- Update `dusk-jubjub` to v0.15
- Update `dusk-plonk` to 0.21

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
[Unreleased]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/jubjub-schnorr/releases/tag/v0.1.0
