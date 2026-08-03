// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::{Error as PlonkError, *};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_schnorr::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    gadgets,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

lazy_static::lazy_static! {
    pub static ref PP: PublicParameters = {
        let rng = &mut StdRng::seed_from_u64(2321u64);

        PublicParameters::setup(1 << 13, rng)
            .expect("Failed to generate PP")
    };
}

const LABEL: &[u8] = b"dusk-network";

fn invalid_points() -> [JubJubExtended; 2] {
    [
        JubJubExtended::identity(),
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), -BlsScalar::one())
            .into(),
    ]
}

//
// Test verify_signature
//
#[derive(Clone, Copy, Debug, Default)]
struct SignatureCircuit {
    u: JubJubScalar,
    r: JubJubExtended,
    pk: JubJubExtended,
    message: BlsScalar,
}

impl SignatureCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let pk = PublicKey::from(&sk);

        Self {
            u: *signature.u(),
            r: *signature.R(),
            pk: *pk.as_ref(),
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let sk_wrong = SecretKey::random(rng);
        let pk = PublicKey::from(&sk_wrong);

        Self {
            u: *signature.u(),
            r: *signature.R(),
            pk: *pk.as_ref(),
            message,
        }
    }

    pub fn all_identity() -> Self {
        Self {
            u: JubJubScalar::zero(),
            r: JubJubExtended::identity(),
            pk: JubJubExtended::identity(),
            message: BlsScalar::zero(),
        }
    }
}

impl Circuit for SignatureCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.r);

        let pk = composer.append_point(self.pk);
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature(composer, u, r, pk, msg)?;

        Ok(())
    }
}

#[test]
fn verify_signature() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) = Compiler::compile::<SignatureCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    //
    // Check valid circuit verifies
    let circuit = SignatureCircuit::valid_random(&mut rng);

    let (proof, _) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should be successful");

    let pub_inputs = vec![];
    verifier
        .verify(&proof, &pub_inputs)
        .expect("Verification should be successful");

    for invalid_point in invalid_points() {
        let mut invalid_r = circuit;
        invalid_r.r = invalid_point;
        prover
            .prove(&mut rng, &invalid_r)
            .expect_err("An invalid R point must be unsatisfiable");

        let mut invalid_pk = circuit;
        invalid_pk.pk = invalid_point;
        prover
            .prove(&mut rng, &invalid_pk)
            .expect_err("An invalid public key must be unsatisfiable");
    }

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");

    let circuit = SignatureCircuit::all_identity();
    prover
        .prove(&mut rng, &circuit)
        .expect_err("An all-identity signature must be unsatisfiable");
}

//
// Test verify_signature_double
//
#[derive(Clone, Copy, Debug, Default)]
struct SignatureDoubleCircuit {
    u: JubJubScalar,
    r: JubJubExtended,
    r_p: JubJubExtended,
    pk: JubJubExtended,
    pk_p: JubJubExtended,
    message: BlsScalar,
}

impl SignatureDoubleCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign_double(rng, message);

        let pk_double = PublicKeyDouble::from(&sk);

        Self {
            u: *signature.u(),
            r: *signature.R(),
            r_p: *signature.R_prime(),
            pk: *pk_double.pk(),
            pk_p: *pk_double.pk_prime(),
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign_double(rng, message);

        let sk_wrong = SecretKey::random(rng);
        let pk_double = PublicKeyDouble::from(&sk_wrong);

        Self {
            u: *signature.u(),
            r: *signature.R(),
            r_p: *signature.R_prime(),
            pk: *pk_double.pk(),
            pk_p: *pk_double.pk_prime(),
            message,
        }
    }

    pub fn all_identity() -> Self {
        Self {
            u: JubJubScalar::zero(),
            r: JubJubExtended::identity(),
            r_p: JubJubExtended::identity(),
            pk: JubJubExtended::identity(),
            pk_p: JubJubExtended::identity(),
            message: BlsScalar::zero(),
        }
    }

    pub fn adaptive_secondary_key() -> Self {
        let sk = SecretKey::from(JubJubScalar::from(17u64));
        let pk = PublicKeyDouble::from(&sk);
        let message = BlsScalar::from(23u64);
        let nonce = JubJubScalar::from(31u64);
        let r = GENERATOR_EXTENDED * nonce;
        let r_p = GENERATOR_NUMS_EXTENDED * JubJubScalar::from(37u64);

        let r_coordinates = r.to_hash_inputs();
        let r_p_coordinates = r_p.to_hash_inputs();
        let pk_coordinates = pk.pk().to_hash_inputs();
        let legacy_challenge: JubJubScalar = Hash::digest_truncated(
            Domain::Other,
            &[
                r_coordinates[0],
                r_coordinates[1],
                r_p_coordinates[0],
                r_p_coordinates[1],
                pk_coordinates[0],
                pk_coordinates[1],
                message,
            ],
        )[0];
        let inverse_challenge = legacy_challenge
            .invert()
            .expect("the deterministic legacy challenge is nonzero");
        let u = nonce - legacy_challenge * sk.as_ref();
        let pk_p = (r_p - GENERATOR_NUMS_EXTENDED * u) * inverse_challenge;

        Self {
            u,
            r,
            r_p,
            pk: *pk.pk(),
            pk_p,
            message,
        }
    }
}

impl Circuit for SignatureDoubleCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.r);
        let r_p = composer.append_point(self.r_p);

        let pk = composer.append_point(self.pk);
        let pk_p = composer.append_point(self.pk_p);
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature_double(composer, u, r, r_p, pk, pk_p, msg)
            .expect("this is infallible");

        Ok(())
    }
}

#[test]
fn verify_signature_double() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) =
        Compiler::compile::<SignatureDoubleCircuit>(&PP, LABEL)
            .expect("Circuit compilation should succeed");

    //
    // Check valid circuit verifies
    let circuit = SignatureDoubleCircuit::valid_random(&mut rng);

    let (proof, _) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should succeed");

    let pub_inputs = vec![];
    verifier
        .verify(&proof, &pub_inputs)
        .expect("Verifying the proof should succeed");

    for invalid_point in invalid_points() {
        let invalid_circuits = [
            SignatureDoubleCircuit {
                r: invalid_point,
                ..circuit
            },
            SignatureDoubleCircuit {
                r_p: invalid_point,
                ..circuit
            },
            SignatureDoubleCircuit {
                pk: invalid_point,
                ..circuit
            },
            SignatureDoubleCircuit {
                pk_p: invalid_point,
                ..circuit
            },
        ];

        for invalid in invalid_circuits {
            prover
                .prove(&mut rng, &invalid)
                .expect_err("An invalid double-signature point must fail");
        }
    }

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureDoubleCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");

    let circuit = SignatureDoubleCircuit::all_identity();
    prover
        .prove(&mut rng, &circuit)
        .expect_err("An all-identity double signature must be unsatisfiable");

    let circuit = SignatureDoubleCircuit::adaptive_secondary_key();
    prover
        .prove(&mut rng, &circuit)
        .expect_err("An adaptively solved secondary key must be unsatisfiable");
}

//
// Test verify_signature_var_gen
//
#[derive(Clone, Copy, Debug, Default)]
struct SignatureVarGenCircuit {
    u: JubJubScalar,
    r: JubJubExtended,
    pk: JubJubExtended,
    generator: JubJubExtended,
    message: BlsScalar,
}

impl SignatureVarGenCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKeyVarGen::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let pk_var_gen = PublicKeyVarGen::from(&sk);

        Self {
            u: *signature.u(),
            r: *signature.R(),
            pk: *pk_var_gen.public_key(),
            generator: *pk_var_gen.generator(),
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKeyVarGen::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let sk_wrong = SecretKeyVarGen::random(rng);
        let pk_var_gen = PublicKeyVarGen::from(&sk_wrong);

        Self {
            u: *signature.u(),
            r: *signature.R(),
            pk: *pk_var_gen.public_key(),
            generator: *pk_var_gen.generator(),
            message,
        }
    }

    pub fn all_identity() -> Self {
        Self {
            u: JubJubScalar::zero(),
            r: JubJubExtended::identity(),
            pk: JubJubExtended::identity(),
            generator: JubJubExtended::identity(),
            message: BlsScalar::zero(),
        }
    }
}

impl Circuit for SignatureVarGenCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.r);

        let pk_var_gen = composer.append_point(self.pk);
        let generator = composer.append_point(self.generator);
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature_var_gen(
            composer, u, r, pk_var_gen, generator, msg,
        )?;

        Ok(())
    }
}

#[test]
fn verify_signature_var_gen() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) =
        Compiler::compile::<SignatureVarGenCircuit>(&PP, LABEL)
            .expect("Circuit should compile successfully");

    //
    // Check valid circuit verifies
    let circuit = SignatureVarGenCircuit::valid_random(&mut rng);

    let (proof, _) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should be successful");

    let pub_inputs = vec![];
    verifier
        .verify(&proof, &pub_inputs)
        .expect("Verification should be successful");

    for invalid_point in invalid_points() {
        let invalid_circuits = [
            SignatureVarGenCircuit {
                r: invalid_point,
                ..circuit
            },
            SignatureVarGenCircuit {
                pk: invalid_point,
                ..circuit
            },
            SignatureVarGenCircuit {
                generator: invalid_point,
                ..circuit
            },
        ];

        for invalid in invalid_circuits {
            prover
                .prove(&mut rng, &invalid)
                .expect_err("An invalid variable-generator point must fail");
        }
    }

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureVarGenCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");

    let circuit = SignatureVarGenCircuit::all_identity();
    prover.prove(&mut rng, &circuit).expect_err(
        "An all-identity variable-generator signature must be unsatisfiable",
    );
}
