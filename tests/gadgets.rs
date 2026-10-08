// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod common;

use std::sync::LazyLock;

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

pub static PP: LazyLock<PublicParameters> = LazyLock::new(|| {
    let rng = &mut StdRng::seed_from_u64(2321u64);

    PublicParameters::setup(1 << 14, rng).expect("Failed to generate PP")
});

const LABEL: &[u8] = b"dusk-network";

/// The tag leading the double-signature challenge transcript.
const DOUBLE_CHALLENGE_DOMAIN: u64 = u64::from_be_bytes(*b"JJSCHDBL");

/// Appends a prover-supplied point and constrains it to the prime-order
/// subgroup, as a consumer circuit must before passing it to a gadget.
fn append_subgroup_point(
    composer: &mut Composer,
    point: JubJubExtended,
) -> Result<TorsionFreeWitnessPoint, PlonkError> {
    let point = composer.append_point(point)?;
    Ok(composer.assert_torsion_free_point(point))
}

/// Asserts that proving fails at the constraints, not at witness generation.
fn assert_unsatisfiable<C: Circuit>(prover: &Prover, circuit: &C, case: &str) {
    let mut rng = StdRng::seed_from_u64(0xbad);
    match prover.prove(&mut rng, circuit) {
        Err(PlonkError::CircuitUnsatisfied) => {}
        Ok(_) => panic!("{case}: produced a proof"),
        Err(other) => panic!("{case}: rejected by {other:?}, not a constraint"),
    }
}

/// The on-curve point `(sqrt(-1), 0)`, of order four.
fn order_four_point() -> JubJubExtended {
    let x = (-BlsScalar::one())
        .sqrt()
        .expect("minus one has a square root in the JubJub base field");

    JubJubAffine::from_raw_unchecked(x, BlsScalar::zero()).into()
}

/// The identity, an off-curve point and an on-curve point of order four.
fn invalid_points() -> [JubJubExtended; 3] {
    [
        JubJubExtended::identity(),
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::zero())
            .into(),
        order_four_point(),
    ]
}

/// Grinds a nonce until the challenge over `inputs(nonce)` is a multiple of
/// four, so that `[c]pk` drops the order-four component of a torsioned key.
fn grind_nonce(
    rng: &mut StdRng,
    inputs: impl Fn(JubJubScalar) -> Vec<BlsScalar>,
) -> (JubJubScalar, JubJubScalar) {
    loop {
        let nonce = JubJubScalar::random(&mut *rng);
        let c = Hash::digest_truncated(Domain::Other, &inputs(nonce))[0];
        if c.to_bytes()[0] & 3 == 0 {
            return (nonce, c);
        }
    }
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

    /// Signs under `pk = [sk]G + torsion`. With `torsion` of order four, the
    /// signature satisfies the signature equation that native verification
    /// never reaches.
    pub fn torsioned_key(rng: &mut StdRng, torsion: JubJubExtended) -> Self {
        let sk = JubJubScalar::random(&mut *rng);
        let pk = GENERATOR_EXTENDED * sk + torsion;
        let message = BlsScalar::random(&mut *rng);
        let pk_xy = pk.to_hash_inputs();

        let (nonce, c) = grind_nonce(rng, |nonce| {
            let r_xy = (GENERATOR_EXTENDED * nonce).to_hash_inputs();
            vec![r_xy[0], r_xy[1], pk_xy[0], pk_xy[1], message]
        });
        let r = GENERATOR_EXTENDED * nonce;
        let u = nonce - c * sk;
        assert_eq!(GENERATOR_EXTENDED * u + pk * c, r);

        Self { u, r, pk, message }
    }
}

impl Circuit for SignatureCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.r)?;

        let pk = append_subgroup_point(composer, self.pk)?;
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
        let r = SignatureCircuit {
            r: invalid_point,
            ..circuit
        };
        assert_unsatisfiable(&prover, &r, "invalid R");
        let pk = SignatureCircuit {
            pk: invalid_point,
            ..circuit
        };
        assert_unsatisfiable(&prover, &pk, "invalid public key");
    }

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureCircuit::invalid_random(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "wrong public key");
}

#[test]
fn verify_signature_rejects_torsioned_key() {
    let mut rng = StdRng::seed_from_u64(0x7041);
    let (prover, _) = Compiler::compile::<SignatureCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let control = SignatureCircuit::torsioned_key(
        &mut rng.clone(),
        JubJubExtended::identity(),
    );
    let circuit = SignatureCircuit::torsioned_key(&mut rng, order_four_point());

    // The challenge is copied by hand. Without the torsion it proves, so the
    // copy matches the gadget and only the subgroup check rejects the key.
    prover
        .prove(&mut rng, &control)
        .expect("The key without torsion should prove");
    assert_unsatisfiable(&prover, &circuit, "torsioned public key");
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

    /// Signs under `pk_p = [sk]G' + torsion`. With `torsion` of order four,
    /// the signature satisfies both signature equations that native
    /// verification never reaches.
    pub fn torsioned_key(rng: &mut StdRng, torsion: JubJubExtended) -> Self {
        let sk = JubJubScalar::random(&mut *rng);
        let pk = GENERATOR_EXTENDED * sk;
        let pk_p = GENERATOR_NUMS_EXTENDED * sk + torsion;
        let message = BlsScalar::random(&mut *rng);
        let domain = BlsScalar::from(DOUBLE_CHALLENGE_DOMAIN);
        let pk_xy = pk.to_hash_inputs();
        let pk_p_xy = pk_p.to_hash_inputs();

        let (nonce, c) = grind_nonce(rng, |nonce| {
            let r_xy = (GENERATOR_EXTENDED * nonce).to_hash_inputs();
            let r_p_xy = (GENERATOR_NUMS_EXTENDED * nonce).to_hash_inputs();
            vec![
                domain, r_xy[0], r_xy[1], r_p_xy[0], r_p_xy[1], pk_xy[0],
                pk_xy[1], pk_p_xy[0], pk_p_xy[1], message,
            ]
        });
        let r = GENERATOR_EXTENDED * nonce;
        let r_p = GENERATOR_NUMS_EXTENDED * nonce;
        let u = nonce - c * sk;
        assert_eq!(GENERATOR_EXTENDED * u + pk * c, r);
        assert_eq!(GENERATOR_NUMS_EXTENDED * u + pk_p * c, r_p);

        Self {
            u,
            r,
            r_p,
            pk,
            pk_p,
            message,
        }
    }
}

impl Circuit for SignatureDoubleCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.r)?;
        let r_p = composer.append_point(self.r_p)?;

        let pk = append_subgroup_point(composer, self.pk)?;
        let pk_p = append_subgroup_point(composer, self.pk_p)?;
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature_double(composer, u, r, r_p, pk, pk_p, msg)?;

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
            assert_unsatisfiable(&prover, &invalid, "invalid point");
        }
    }

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureDoubleCircuit::invalid_random(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "wrong public key");

    let fixture = common::legacy_double_signature_fixture();
    let circuit = SignatureDoubleCircuit {
        u: *fixture.signature.u(),
        r: *fixture.signature.R(),
        r_p: *fixture.signature.R_prime(),
        pk: *fixture.public_key.pk(),
        pk_p: *fixture.public_key.pk_prime(),
        message: fixture.message,
    };
    assert_unsatisfiable(&prover, &circuit, "adaptive secondary key");
}

#[test]
fn verify_signature_double_rejects_torsioned_key() {
    let mut rng = StdRng::seed_from_u64(0x7041);
    let (prover, _) = Compiler::compile::<SignatureDoubleCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let control = SignatureDoubleCircuit::torsioned_key(
        &mut rng.clone(),
        JubJubExtended::identity(),
    );
    let circuit =
        SignatureDoubleCircuit::torsioned_key(&mut rng, order_four_point());

    // The challenge is copied by hand. Without the torsion it proves, so the
    // copy matches the gadget and only the subgroup check rejects the key.
    prover
        .prove(&mut rng, &control)
        .expect("The secondary key without torsion should prove");
    assert_unsatisfiable(&prover, &circuit, "torsioned secondary key");
}

//
// Test verify_signature_var_gen
//
#[derive(Clone, Copy, Debug, Default)]
struct SignatureVarGenCircuit {
    // Keep the response as a field witness to test noncanonical inputs.
    u: BlsScalar,
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
            u: BlsScalar::from(*signature.u()),
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
            u: BlsScalar::from(*signature.u()),
            r: *signature.R(),
            pk: *pk_var_gen.public_key(),
            generator: *pk_var_gen.generator(),
            message,
        }
    }

    /// Signs under `pk = [sk]generator + torsion`. With `torsion` of order
    /// four, the signature satisfies the signature equation that native
    /// verification never reaches.
    pub fn torsioned_key(rng: &mut StdRng, torsion: JubJubExtended) -> Self {
        let sk = JubJubScalar::random(&mut *rng);
        let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng);
        let pk = generator * sk + torsion;
        let message = BlsScalar::random(&mut *rng);
        let pk_xy = pk.to_hash_inputs();
        let generator_xy = generator.to_hash_inputs();

        let (nonce, c) = grind_nonce(rng, |nonce| {
            let r_xy = (generator * nonce).to_hash_inputs();
            vec![
                r_xy[0],
                r_xy[1],
                pk_xy[0],
                pk_xy[1],
                generator_xy[0],
                generator_xy[1],
                message,
            ]
        });
        let r = generator * nonce;
        let u = nonce - c * sk;
        assert_eq!(generator * u + pk * c, r);

        Self {
            u: u.into(),
            r,
            pk,
            generator,
            message,
        }
    }
}

impl Circuit for SignatureVarGenCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.r)?;

        let pk = append_subgroup_point(composer, self.pk)?;
        let generator = append_subgroup_point(composer, self.generator)?;
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature_var_gen(composer, u, r, pk, generator, msg)?;

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
            assert_unsatisfiable(&prover, &invalid, "invalid point");
        }
    }

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureVarGenCircuit::invalid_random(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "wrong public key");
}

#[test]
fn verify_signature_var_gen_rejects_torsioned_key() {
    let mut rng = StdRng::seed_from_u64(0x7041);
    let (prover, _) = Compiler::compile::<SignatureVarGenCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let control = SignatureVarGenCircuit::torsioned_key(
        &mut rng.clone(),
        JubJubExtended::identity(),
    );
    let circuit =
        SignatureVarGenCircuit::torsioned_key(&mut rng, order_four_point());

    // The challenge is copied by hand. Without the torsion it proves, so the
    // copy matches the gadget and only the subgroup check rejects the key.
    prover
        .prove(&mut rng, &control)
        .expect("The key without torsion should prove");
    assert_unsatisfiable(&prover, &circuit, "torsioned public key");
}

#[test]
fn verify_signature_var_gen_rejects_noncanonical_response() {
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let modulus = BlsScalar::from(-JubJubScalar::one()) + BlsScalar::one();
    // The alias must fit the multiplier's 252-bit bound, so only the
    // canonicality check distinguishes it from the valid response.
    let mut circuit = (0..1024)
        .map(|_| SignatureVarGenCircuit::valid_random(&mut rng))
        .find(|circuit| {
            (circuit.u + modulus).to_bits()[252..]
                .iter()
                .all(|bit| *bit == 0)
        })
        .expect("A response with a 252-bit alias should be sampled");
    let (prover, verifier) =
        Compiler::compile::<SignatureVarGenCircuit>(&PP, LABEL)
            .expect("Circuit should compile successfully");

    let (proof, inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("The canonical response should satisfy the circuit");
    verifier.verify(&proof, &inputs).unwrap();

    circuit.u += modulus;
    assert_unsatisfiable(&prover, &circuit, "noncanonical response");
}
