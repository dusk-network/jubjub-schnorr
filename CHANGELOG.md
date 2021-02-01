# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2021-01-29

### Added

- `PublicKeyPair` attributes R and R_prime exposed as methods
- `Proof::keys` added to fetch `PublicKeyPair`

### Changed

- JubJubScalars renamed from `U` to `u`, as in notation standards

## [0.3.0] - 2021-01-28

### Added

- Add `dusk_bytes::Serializable` trait to structure
- Add dusk_pki's `SecretKey` and `PublicKey`

### Removed

- Remove manual implementation of `to_bytes` and `from_bytes`
- Remove `SecretKey`, `PublicKey` from `schnorr`
- Remove `Error` schnorr enum

### Changed

- `single_key::SecretKey.sign` method is now `Signature::new`
- `double_key::SecretKey.sign` method is now `Proof::new`
- Change return value of single's key `verify` from `Result` to `bool`
- Change return value of double's key `verify` from `Result` to `bool`
- Update CHANGELOG to ISO 8601
- Bump `poseidon252` to `v0.16.0`
- Bump `dusk-bls12_381` to `v0.6`
- Bump `dusk-jubjub` to `v0.8`
- Bump `dusk-plonk` to `v0.5`
- Bump `canonical` to `v0.5`
- Bump `canonical_derive` to `v0.5`

## [0.2.1] - 2021-01-08

### Fixes

- Fix byte truncation for BLS -> JubJub conversion