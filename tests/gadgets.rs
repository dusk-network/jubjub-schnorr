// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod common;

use std::sync::LazyLock;

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::{Error as PlonkError, *};
use dusk_poseidon::{Domain, Hash, HashGadget};
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
// Pin the gates of each gadget
//

/// Returns the number of gates that `gadget` appends to `composer`.
fn appended_gates(
    composer: &mut Composer,
    gadget: impl FnOnce(&mut Composer) -> Result<(), PlonkError>,
) -> usize {
    let before = composer.constraints();
    gadget(composer).expect("The gadget should append its gates");
    composer.constraints() - before
}

/// Pins the gates each gadget appends. Dropping one identity check removes
/// one gate, and no satisfiability test can catch it for a point of a double
/// pair or for the generator: a transcript where only that point is the
/// identity needs a challenge that depends on its own output.
#[test]
fn gadget_gate_counts() {
    // The counts do not depend on the witness values.
    let mut composer = Composer::initialized();
    let u = composer.append_witness(JubJubScalar::one());
    let msg = composer.append_witness(BlsScalar::one());
    let r = composer.append_point(GENERATOR_EXTENDED).unwrap();
    let pk = append_subgroup_point(&mut composer, GENERATOR_EXTENDED).unwrap();

    let gates = [
        appended_gates(&mut composer, |composer| {
            gadgets::verify_signature(composer, u, r, pk, msg)
        }),
        appended_gates(&mut composer, |composer| {
            gadgets::verify_signature_double(composer, u, r, r, pk, pk, msg)
        }),
        appended_gates(&mut composer, |composer| {
            gadgets::verify_signature_var_gen(composer, u, r, pk, pk, msg)
        }),
    ];
    assert_eq!(gates, [3748, 6758, 5506]);
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

    /// Any response signs for the identity key, with `R = [u]G`.
    pub fn identity_key(rng: &mut StdRng) -> Self {
        let u = JubJubScalar::random(&mut *rng);

        Self {
            u,
            r: GENERATOR_EXTENDED * u,
            pk: JubJubExtended::identity(),
            message: BlsScalar::random(&mut *rng),
        }
    }

    /// The key owner signs with the identity nonce, with `u = -c * sk`.
    pub fn identity_nonce(rng: &mut StdRng) -> Self {
        let sk = JubJubScalar::random(&mut *rng);
        let pk = GENERATOR_EXTENDED * sk;
        let message = BlsScalar::random(&mut *rng);
        let r = JubJubExtended::identity();
        let (r_xy, pk_xy) = (r.to_hash_inputs(), pk.to_hash_inputs());

        let c = Hash::digest_truncated(
            Domain::Other,
            &[r_xy[0], r_xy[1], pk_xy[0], pk_xy[1], message],
        )[0];
        let u = -(c * sk);
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

#[test]
fn verify_signature_rejects_identity_points() {
    let mut rng = StdRng::seed_from_u64(0x1d);
    let (prover, _) = Compiler::compile::<SignatureCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let circuit = SignatureCircuit::identity_key(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity public key");

    let circuit = SignatureCircuit::identity_nonce(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity nonce commitment");
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

    /// Any response signs for identity keys, with `R = [u]G`, `R' = [u]G'`.
    pub fn identity_keys(rng: &mut StdRng) -> Self {
        let u = JubJubScalar::random(&mut *rng);

        Self {
            u,
            r: GENERATOR_EXTENDED * u,
            r_p: GENERATOR_NUMS_EXTENDED * u,
            pk: JubJubExtended::identity(),
            pk_p: JubJubExtended::identity(),
            message: BlsScalar::random(&mut *rng),
        }
    }

    /// The key owner signs with identity nonces, with `u = -c * sk`.
    pub fn identity_nonces(rng: &mut StdRng) -> Self {
        let sk = JubJubScalar::random(&mut *rng);
        let pk = GENERATOR_EXTENDED * sk;
        let pk_p = GENERATOR_NUMS_EXTENDED * sk;
        let message = BlsScalar::random(&mut *rng);
        let r = JubJubExtended::identity();
        let r_xy = r.to_hash_inputs();
        let (pk_xy, pk_p_xy) = (pk.to_hash_inputs(), pk_p.to_hash_inputs());

        let c = Hash::digest_truncated(
            Domain::Other,
            &[
                DOUBLE_CHALLENGE_DOMAIN.into(),
                r_xy[0],
                r_xy[1],
                r_xy[0],
                r_xy[1],
                pk_xy[0],
                pk_xy[1],
                pk_p_xy[0],
                pk_p_xy[1],
                message,
            ],
        )[0];
        let u = -(c * sk);
        assert_eq!(GENERATOR_EXTENDED * u + pk * c, r);
        assert_eq!(GENERATOR_NUMS_EXTENDED * u + pk_p * c, r);

        Self {
            u,
            r,
            r_p: r,
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

#[test]
fn verify_signature_double_rejects_identity_points() {
    let mut rng = StdRng::seed_from_u64(0x1d);
    let (prover, _) = Compiler::compile::<SignatureDoubleCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let circuit = SignatureDoubleCircuit::identity_keys(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity public keys");

    let circuit = SignatureDoubleCircuit::identity_nonces(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity nonce commitments");
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

    /// Any response signs for the identity key, with `R = [u]generator`.
    pub fn identity_key(rng: &mut StdRng) -> Self {
        let u = JubJubScalar::random(&mut *rng);
        let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng);

        Self {
            u: u.into(),
            r: generator * u,
            pk: JubJubExtended::identity(),
            generator,
            message: BlsScalar::random(&mut *rng),
        }
    }

    /// The key owner signs with the identity nonce, with `u = -c * sk`.
    pub fn identity_nonce(rng: &mut StdRng) -> Self {
        let sk = JubJubScalar::random(&mut *rng);
        let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng);
        let pk = generator * sk;
        let message = BlsScalar::random(&mut *rng);
        let r = JubJubExtended::identity();
        let (r_xy, pk_xy) = (r.to_hash_inputs(), pk.to_hash_inputs());
        let generator_xy = generator.to_hash_inputs();

        let c = Hash::digest_truncated(
            Domain::Other,
            &[
                r_xy[0],
                r_xy[1],
                pk_xy[0],
                pk_xy[1],
                generator_xy[0],
                generator_xy[1],
                message,
            ],
        )[0];
        let u = -(c * sk);
        assert_eq!(generator * u + pk * c, r);

        Self {
            u: u.into(),
            r,
            pk,
            generator,
            message,
        }
    }

    /// Any response signs for the identity generator, key and nonce.
    pub fn identity_generator(rng: &mut StdRng) -> Self {
        Self {
            u: JubJubScalar::random(&mut *rng).into(),
            r: JubJubExtended::identity(),
            pk: JubJubExtended::identity(),
            generator: JubJubExtended::identity(),
            message: BlsScalar::random(&mut *rng),
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
fn verify_signature_var_gen_rejects_identity_points() {
    let mut rng = StdRng::seed_from_u64(0x1d);
    let (prover, _) = Compiler::compile::<SignatureVarGenCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let circuit = SignatureVarGenCircuit::identity_key(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity public key");

    let circuit = SignatureVarGenCircuit::identity_nonce(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity nonce commitment");

    let circuit = SignatureVarGenCircuit::identity_generator(&mut rng);
    assert_unsatisfiable(&prover, &circuit, "identity generator");
}

#[test]
fn verify_signature_var_gen_rejects_noncanonical_response() {
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let modulus = jubjub_modulus();
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

//
// Test canonical responses in the fixed-generator gadgets
//
// `component_mul_generator` rejects a noncanonical scalar during witness
// generation, before appending any gate. To reach the constraints, a malicious
// prover is emulated: the prover keeps the selectors and copy constraints of
// the compiled circuit and only takes the wire values of the circuit it runs,
// so `Shadow` proves through rows that mirror the gadget's, filled with the
// honest witness of an arbitrary response.

/// Proves `circuit` with response `u` through the mirrored rows.
struct Shadow<C> {
    circuit: C,
    u: BlsScalar,
}

/// Mirrors the rows of `assert_non_identity` in the gadgets.
fn shadow_non_identity(composer: &mut Composer, point: WitnessPoint) {
    let x = *point.x();
    let x_inverse = composer[x].invert().unwrap_or(BlsScalar::zero());
    let x_inverse = composer.append_witness(x_inverse);
    composer.append_gate(
        Constraint::new()
            .mult(1)
            .a(x)
            .b(x_inverse)
            .constant(-BlsScalar::one()),
    );
}

/// Mirrors the rows of `Composer::component_mul_generator` for the value of
/// `jubjub` read as an integer below `2^253`: the canonical range checks, then
/// one signed-digit row per bit of the width-2 NAF, most significant first.
fn shadow_mul_generator(
    composer: &mut Composer,
    jubjub: Witness,
    generator: JubJubExtended,
) -> Result<TorsionFreeWitnessPoint, PlonkError> {
    composer.component_range_bits::<252>(jubjub);
    let distance = composer.gate_add(
        Constraint::new()
            .left(-BlsScalar::one())
            .a(jubjub)
            .constant(BlsScalar::from(-JubJubScalar::one())),
    );
    composer.component_range_bits::<252>(distance);

    let value = composer[jubjub];
    let bits = value.to_bits();
    let triple = (value + value + value).to_bits();
    let bit = |bits: &[u8; 256], i: usize| bits.get(i).copied().unwrap_or(0);

    let mut multiple = generator;
    let multiples: Vec<_> = (0..256)
        .map(|_| {
            let current = multiple;
            multiple = multiple.double();
            current
        })
        .collect();

    let mut point = JubJubExtended::identity();
    let mut scalar = BlsScalar::zero();
    let mut leading = Composer::ZERO;
    for i in (0..256).rev() {
        let acc = JubJubAffine::from(point);
        let acc_x = composer.append_witness(acc.get_u());
        let acc_y = composer.append_witness(acc.get_v());
        let acc_scalar = composer.append_witness(scalar);
        if i == 255 {
            composer.assert_equal_constant(acc_x, BlsScalar::zero(), None);
            composer.assert_equal_constant(acc_y, BlsScalar::one(), None);
            composer.assert_equal_constant(acc_scalar, BlsScalar::zero(), None);
        }
        if i == 252 {
            leading = acc_scalar;
        }

        let (digit, addend) =
            match bit(&triple, i + 1) as i8 - bit(&bits, i + 1) as i8 {
                1 => (BlsScalar::one(), multiples[i]),
                -1 => (-BlsScalar::one(), -multiples[i]),
                _ => (BlsScalar::zero(), JubJubExtended::identity()),
            };
        let addend_affine = JubJubAffine::from(addend);
        let xy = composer
            .append_witness(addend_affine.get_u() * addend_affine.get_v());
        composer.append_gate(
            Constraint::new().a(acc_x).b(acc_y).c(xy).d(acc_scalar),
        );

        point += addend;
        scalar = scalar.double() + digit;
    }

    let acc = JubJubAffine::from(point);
    let acc_x = composer.append_witness(acc.get_u());
    let acc_y = composer.append_witness(acc.get_v());
    let last = composer.append_witness(scalar);
    composer.append_gate(Constraint::new().a(acc_x).b(acc_y).d(last));
    composer.assert_equal_constant(leading, BlsScalar::zero(), None);
    composer.assert_equal(last, jubjub);

    // Fresh witnesses holding the same values satisfy the copy constraints.
    let point = composer.append_point(point)?;
    Ok(TorsionFreeWitnessPoint::new_unchecked(point))
}

impl Circuit for Shadow<SignatureCircuit> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.circuit.r)?;
        let pk = append_subgroup_point(composer, self.circuit.pk)?;
        let msg = composer.append_witness(self.circuit.message);

        // `gadgets::verify_signature`
        shadow_non_identity(composer, r);
        shadow_non_identity(composer, pk.into());
        let challenge = [*r.x(), *r.y(), *pk.x(), *pk.y(), msg];
        let c =
            HashGadget::digest_truncated(composer, Domain::Other, &challenge)
                [0];
        let s_a = shadow_mul_generator(composer, u, GENERATOR_EXTENDED)?;
        let s_b = composer.component_mul_point(c, pk);
        let point = composer.component_add_point(s_a, s_b);
        composer.assert_equal_point(r, point.into());

        Ok(())
    }
}

impl Circuit for Shadow<SignatureDoubleCircuit> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.circuit.r)?;
        let r_p = composer.append_point(self.circuit.r_p)?;
        let pk = append_subgroup_point(composer, self.circuit.pk)?;
        let pk_p = append_subgroup_point(composer, self.circuit.pk_p)?;
        let msg = composer.append_witness(self.circuit.message);

        // `gadgets::verify_signature_double`
        for point in [r, r_p, pk.into(), pk_p.into()] {
            shadow_non_identity(composer, point);
        }
        let domain = composer.append_constant(DOUBLE_CHALLENGE_DOMAIN);
        let challenge = [
            domain,
            *r.x(),
            *r.y(),
            *r_p.x(),
            *r_p.y(),
            *pk.x(),
            *pk.y(),
            *pk_p.x(),
            *pk_p.y(),
            msg,
        ];
        let c =
            HashGadget::digest_truncated(composer, Domain::Other, &challenge)
                [0];
        let s_a = shadow_mul_generator(composer, u, GENERATOR_EXTENDED)?;
        let s_b = composer.component_mul_point(c, pk);
        let point = composer.component_add_point(s_a, s_b);
        let s_p_a = shadow_mul_generator(composer, u, GENERATOR_NUMS_EXTENDED)?;
        let s_p_b = composer.component_mul_point(c, pk_p);
        let point_p = composer.component_add_point(s_p_a, s_p_b);
        composer.assert_equal_point(r, point.into());
        composer.assert_equal_point(r_p, point_p.into());

        Ok(())
    }
}

/// Returns the alias `u + r` of a canonical response, when it fits in 252 bits
/// so that only the canonical bound tells the two apart.
fn short_alias(u: JubJubScalar) -> Option<BlsScalar> {
    let alias = BlsScalar::from(u) + jubjub_modulus();
    alias.to_bits()[252..]
        .iter()
        .all(|bit| *bit == 0)
        .then_some(alias)
}

/// The JubJub scalar modulus `r` as a BLS scalar.
fn jubjub_modulus() -> BlsScalar {
    BlsScalar::from(-JubJubScalar::one()) + BlsScalar::one()
}

/// Proves a sampled canonical response through the mirrored rows, then
/// requires its 252-bit alias to be unsatisfiable.
fn assert_alias_unsatisfiable<C>(
    rng: &mut StdRng,
    sample: impl Fn(&mut StdRng) -> (C, JubJubScalar),
) where
    C: Circuit + Default + Copy,
    Shadow<C>: Circuit,
{
    let (circuit, u, alias) = (0..1024)
        .map(|_| sample(rng))
        .find_map(|(circuit, u)| Some((circuit, u, short_alias(u)?)))
        .expect("A response with a 252-bit alias should be sampled");
    let (prover, verifier) = Compiler::compile::<C>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    let canonical = Shadow {
        circuit,
        u: u.into(),
    };
    let (proof, inputs) = prover
        .prove(rng, &canonical)
        .expect("The mirrored rows should prove a canonical response");
    verifier.verify(&proof, &inputs).unwrap();

    let noncanonical = Shadow { circuit, u: alias };
    assert_unsatisfiable(&prover, &noncanonical, "noncanonical response");
}

#[test]
fn fixed_generator_gadgets_reject_noncanonical_response() {
    let mut rng = StdRng::seed_from_u64(0xcafe);

    // `[u + r]G = [u]G` for both generators, so the alias satisfies the
    // signature equations and only the canonical bound rejects it.
    assert_alias_unsatisfiable(&mut rng, |rng| {
        let circuit = SignatureCircuit::valid_random(rng);
        (circuit, circuit.u)
    });
    assert_alias_unsatisfiable(&mut rng, |rng| {
        let circuit = SignatureDoubleCircuit::valid_random(rng);
        (circuit, circuit.u)
    });
}
