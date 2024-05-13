# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Remove features: `"alloc", "std", "default"` [#21]

### Added

- Add `"zk"` feature [#21]

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
[#21]: https://github.com/dusk-network/jubjub-schnorr/issues/21
[#14]: https://github.com/dusk-network/jubjub-schnorr/issues/14
[#12]: https://github.com/dusk-network/jubjub-schnorr/issues/12
[#9]: https://github.com/dusk-network/jubjub-schnorr/issues/9
[#3]: https://github.com/dusk-network/jubjub-schnorr/issues/3
[#2]: https://github.com/dusk-network/jubjub-schnorr/issues/2

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/jubjub-schnorr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/jubjub-schnorr/releases/tag/v0.1.0
