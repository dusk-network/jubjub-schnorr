# AGENTS.md — jubjub-schnorr

## Care Level: Cryptographic — Elevated

Schnorr signatures used for transaction authorization. A bug here can
allow forged signatures or break consensus.

## Overview

Schnorr signatures on JubJub with PLONK circuit gadgets. Single crate.
`no_std`.

Variants: standard, double (two public keys), variable generator,
multisig.

## Commands

Run `make help` to list all available targets. Key points:

- **Always use `make` targets** — the Makefile is the source of truth
  for build, test, and clippy commands.
- Tests require `--release` (handled by `make test`) because the `zk`
  feature pulls in `dusk-plonk`.

## Architecture

### Key Files

| Path | Purpose |
|------|---------|
| `src/keys/secret.rs` | Secret key implementation |
| `src/keys/public.rs` | Public key implementation |
| `src/keys/public/double.rs` | PublicKeyDouble variant |
| `src/keys/public/var_gen.rs` | PublicKeyVarGen (variable generator) |
| `src/signatures.rs` | Signature types |
| `src/multisig.rs` | Multisignature scheme |
| `src/gadgets.rs` | ZK circuit gadgets (`zk` feature) |

### Features

- `alloc` — heap allocation support
- `zk` — PLONK circuit gadgets (pulls in `dusk-plonk`)
- `rkyv-impl` — rkyv serialization
- `serde` — JSON serialization

## Conventions

- **no_std by default**: the crate is `no_std`. Do not add `std`
  dependencies.
- **Always use `--release` for tests**: the `zk` feature pulls in
  `dusk-plonk`, which is extremely slow in debug mode.
- **No timing side-channels**: do not introduce branches or early
  returns on secret data. Use constant-time operations.

## Git

Single-crate repo. Commit messages use imperative mood, no scope
prefix.

## Changelog

Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes
only. Exclude tests, CI, tooling, and refactors.

- One fact per entry. Name the public item and behavior, including the
  affected released item if breaking. Leave implementation, rationale,
  consequences, and migration to the linked issue.
- Use existing `Added`, `Changed`, or `Removed` sections. Use `Fixed`
  only for released bugs. Correct unreleased bugs in their original
  entry.
- Link only the GitHub issue, not the PR. Match existing link style and
  define references below. Preserve other entries and follow
  [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and Markdown
  blank-line spacing.
