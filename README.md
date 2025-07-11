# jubjub-schnorr
[![Build Status](https://github.com/dusk-network/jubjub-schnorr/workflows/Continuous%20integration/badge.svg)](https://github.com/dusk-network/jubjub-schnorr/actions/workflows/dusk_ci.yaml)
[![Repository](https://img.shields.io/badge/github-schnorr-blueviolet?logo=github)](https://github.com/dusk-network/jubjub-schnorr)
[![Documentation](https://img.shields.io/badge/docs-schnorr-blue?logo=rust)](https://docs.rs/jubjub-schnorr/)

This crate provides a Rust implementation of the Schnorr signature scheme for the JubJub elliptic curve group, using the Poseidon hash function. This implementation is designed by the [Dusk](https://dusk.network) team.

## About
The Schnorr signature scheme, named after its creator Claus Schnorr, is a digital signature scheme renowned for its simplicity. The scheme provides a simple method of creating short signatures. 

The implementation has been created using the [`jubjub`](https://github.com/dusk-network/jubjub) elliptic curve and the [`Poseidon`](https://github.com/dusk-network/Poseidon252) hash function, the paper for which can be found [here](https://eprint.iacr.org/2019/458.pdf).

The signature scheme is implemented within the [Phoenix](https://github.com/dusk-network/phoenix-core/blob/master/docs/protocol-description.pdf) transaction model and is based on the Schnorr Sigma protocol, compiled alongside the Fiat–Shamir transformation, to serve as a non-interactive signature scheme. Specifically, the Phoenix protocol employs a variant that utilizes double Schnorr signatures, verifiable with double public keys, enabling the delegation of computational processes within the protocol's later stages.

The repository also includes an implementation of the `SpeedyMuSig` Schnorr-based multisignature scheme described [here](https://eprint.iacr.org/2021/1375.pdf) (pag. 19). It allows several signers to create a signature that proves a message to be signed by them all, given their public keys. The signature can be verified using the same function used for the standard Schnorr signature, using the sum of all the signers' public keys.

## Library Structure
The library is partitioned into the following components:

- **Keys**: Module containing the secret key structure for signing messages, as well as the public key and the double public key structures used in verification.
- **Signatures**: Module containing the standard and double signature structs as well as functions to verify the validity of Schnorr signatures and double Schnorr signatures.
- **Gadgets**: Contains the Plonk gadgets for in-circuit verification of Schnorr signatures and double Schnorr Signatures.

## Signature Scheme Description

### Notation

In the following:
- Multiplication of a point $P$ by a scalar $s$ stands for adding $P$ $s$-times to itself.
- $\mathbb{F}_q$ is the prime finite field of order $q$
- for a prime $q$: $\mathbb{F}_q^× =  \mathbb{F}_q \setminus 0$ contains all nonzero elements of $\mathbb{F}_q$.

### Single Signature

#### Setup

In this library we implement our Schnorr signature scheme on the jubjub elliptic curve, specifically we have:
- a finite field $\mathbb{F}_q$ over prime $q$, in this implementation this field corresponds to the scalar field of the elliptic curve BLS12-381
- an elliptic curve $E / \mathbb{F}_q$, in our case this is the jubjub elliptic curve
- a subgroup $\mathbb{G} \in E(\mathbb{F}_q)$ of curve points, with prime order $p$
- a fixed generator point $G \in \mathbb{G}$
- a cryptographic hash function $H : \{0 , 1\}^∗ \rightarrow \mathbb{F}_p$ where $\mathbb{F}_p$ is the scalar field of the jubjub elliptic curve.

#### Key generation

- Choose a private signing key, $sk \in \mathbb{F}_p^×$.
- The public verification key is $PK = skG \in \mathbb{G}$.

#### Signing

To sign a message $m \in \mathbb{F}_q^×$:

- Choose a random private nonce $r \in \mathbb{F}_p^×$.
- Compute nonce point $R = rG \in \mathbb{G}$.
- Compute challenge hash $c = H(R \parallel $PK \parallel m) \in \mathbb{F}_p$ where $\parallel$ denotes concatenation and $R$ is represented as a bit string.
- Compute $u = r − sk \cdot c \in \mathbb{F}_p$.

The signature is the tuple $(u, R) \in \mathbb{F}_p \times \mathbb{G}$.

#### Verifying

- Compute challenge hash $c = H(R \parallel $PK \parallel m) \in \mathbb{F}_p$.
- Verify that $uG + cPK = R$.

If the signature was signed with the secret key corresponding to $PK$, this will hold true, since:

$$
uG + cPK = (r - sk\cdot c)G + (sk\cdot c)G = (r - sk\cdot c + sk\cdot c)G = rG = R
$$

### Double Signature

#### Setup

Same as in the single signature above with the addition of another generator point $G' \in \mathbb{G}$, that is different from $G$ and whose discrete logarithm relation with $G$ is unknown.

#### Key generation

- Choose a private signing key, $sk \in \mathbb{F}_p^×$.
- The public verification key is the tuple $(PK, PK')$ with $PK = skG \in \mathbb{G}$ and $PK' = skG' \in \mathbb{G}$.

#### Signing

To sign a message $m \in \mathbb{F}_q^×$:

- Choose a random private nonce $r \in \mathbb{F}_p^×$.
- Compute nonce points $R = rG \in \mathbb{G}$ and $R' = rG' \in \mathbb{G}$.
- Compute challenge hash $c = H(R \parallel R' \parallel $PK \parallel m) \in \mathbb{F}_p$ where $\parallel$ denotes concatenation and $R, R'$ are represented as a bit strings.
- Compute $u = r − sk \cdot c \in \mathbb{F}_p$.

The signature is the tuple $(u, R, R') \in \mathbb{F}_p \times \mathbb{G} \times \mathbb{G}$.

#### Verifying

- Compute challenge hash $c = H(R \parallel R' \parallel $PK \parallel m) \in \mathbb{F}_p$.
- Verify that $rG + cPK = R$ and $uG' + cPK' = R'$.

If the signature was signed with the correct private key, this should hold true because:

$$
uG + cPK = (r - sk\cdot c)G + (sk\cdot c)G = (r - sk\cdot c + sk\cdot c)G = rG = R
$$

and

$$
uG' + cPK' = (r - sk\cdot c)G' + (sk\cdot c)G' = (r - sk\cdot c + sk\cdot c)G' = rG' = R'
$$


### Notes on Security and Implementation

The implemented signature scheme is existentially unforgeable under chosen-message attacks assuming the hardness of the discrete logarithm problem in the random oracle model. This property is detailed in Section 12.5.1 of Katz and Lindell's Introduction to Modern Cryptography.

While the basic Schnorr signature scheme is a widely recognized construct, the double-key variant as employed by Phoenix is a novel introduction. In the context of the transaction protocol, this allows for the delegation of proof computations without compromising the confidentiality of the signer's secret key.

## Usage
To integrate the `jubjub-schnorr` crate into your project, add it with the following command:
```bash
cargo add jubjub-schnorr
```

A basic example demonstrating how to generate and verify a Schnorr signature:
```rust
use dusk_bls12_381::BlsScalar;
use jubjub_schnorr::{SecretKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use ff::Field;

fn main() {
    // Setup
    let mut rng = StdRng::seed_from_u64(1234u64);
    let message = BlsScalar::random(&mut rng);

    // Key generation
    let sk = SecretKey::random(&mut rng);

    // Standard Schnorr signature scheme:
    use jubjub_schnorr::PublicKey;

    let pk = PublicKey::from(&sk);
    let signature = sk.sign(&mut rng, message);
    assert!(pk.verify(&signature, message).is_ok(), "The signature should be valid.");

    // Double Dusk-Schnorr signature scheme:
    use jubjub_schnorr::PublicKeyDouble;

    let pk = PublicKeyDouble::from(&sk);
    let signature = sk.sign_double(&mut rng, message);
    assert!(pk.verify(&signature, message).is_ok(), "The signature should be valid.");

    // Dusk-Schnorr signature scheme with variable generator:
    use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
    use jubjub_schnorr::PublicKeyVarGen;

    let generator = GENERATOR_EXTENDED * JubJubScalar::from(42u64);
    let sk = sk.with_variable_generator(generator);
    let pk = PublicKeyVarGen::from(&sk);
    let signature = sk.sign(&mut rng, message);
    assert!(pk.verify(&signature, message).is_ok(), "The signature should be valid.");
}
```

## Licensing
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

Copyright (c) DUSK NETWORK. All rights reserved.
