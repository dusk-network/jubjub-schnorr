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

Add an entry to `CHANGELOG.md` under `[Unreleased]` only for a change
that users of the crate can see. Tests, CI, tooling and internal
refactors get no entry.

- Write one fact per entry, in one sentence. Two facts get two
  entries.
- Name what changed at the crate's surface: the public item and its
  new behavior. Do not describe how the code does it.
- Name the released item that a breaking change breaks.
- Keep the reason, the consequences and the migration steps in the
  linked issue, not in the entry.
- Choose the section by the effect on users: new things go under
  `Added`, changed behavior goes under `Changed`, and removed things go
  under `Removed`. Use `Fixed` only for a bug that a release had. For a
  bug in unreleased code, correct the entry that added that code.
- Link the tracking GitHub issue, not the PR, and no other tracking
  identifier. Use the link format that the file already uses. A
  reference link needs its definition in the block at the bottom.
- Add to the existing section headings, and leave the other entries
  as they are.
- Use the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
  format.
- Follow standard markdown formatting: separate headings from
  surrounding content with blank lines, leave a blank line before and
  after lists, and never have two headings back-to-back without a blank
  line between them.
