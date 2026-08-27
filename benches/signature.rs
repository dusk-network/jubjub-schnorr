// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use dusk_plonk::prelude::{Error as PlonkError, *};
use ff::Field;
use jubjub_schnorr::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    Signature, SignatureDouble, SignatureVarGen, gadgets,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const CAPACITY: usize = 13;
const LABEL: &[u8; 12] = b"dusk-network";

static PP: LazyLock<PublicParameters> = LazyLock::new(|| {
    let rng = &mut StdRng::seed_from_u64(2321u64);
    PublicParameters::setup(1 << CAPACITY, rng).expect("Failed to generate PP")
});
static CONSTRAINTS: AtomicUsize = AtomicUsize::new(0);

fn proof_creation<C>(
    criterion: &mut Criterion,
    name: &str,
    valid: impl FnOnce(&mut StdRng) -> C,
) where
    C: Circuit,
{
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let (prover, _verifier) =
        Compiler::compile::<C>(&PP, LABEL).expect("circuit should compile");
    let circuit = valid(&mut rng);
    let name = format!(
        "{name} proof creation ({} constraints)",
        CONSTRAINTS.load(Ordering::Relaxed)
    );

    criterion.bench_function(&name, |bencher| {
        bencher.iter(|| {
            prover
                .prove(&mut rng, &circuit)
                .expect("proof creation of valid circuit should succeed");
        });
    });
}

#[derive(Debug, Default)]
struct SignatureCircuit {
    signature: Signature,
    pk: PublicKey,
    message: BlsScalar,
}

impl SignatureCircuit {
    fn valid(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);
        let pk = PublicKey::from(&sk);

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SignatureCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(*self.signature.u());
        let r = composer.append_point(self.signature.R());
        let pk = composer.append_point(self.pk.as_ref());
        let message = composer.append_witness(self.message);

        let _result = gadgets::verify_signature(composer, u, r, pk, message);
        CONSTRAINTS.store(composer.constraints(), Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SigDoubleCircuit {
    signature: SignatureDouble,
    pk: PublicKeyDouble,
    message: BlsScalar,
}

impl SigDoubleCircuit {
    fn valid(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign_double(rng, message);
        let pk = PublicKeyDouble::from(&sk);

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SigDoubleCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(*self.signature.u());
        let r = composer.append_point(self.signature.R());
        let r_prime = composer.append_point(self.signature.R_prime());
        let pk = composer.append_point(self.pk.pk());
        let pk_prime = composer.append_point(self.pk.pk_prime());
        let message = composer.append_witness(self.message);

        gadgets::verify_signature_double(
            composer, u, r, r_prime, pk, pk_prime, message,
        )
        .expect("this is infallible");
        CONSTRAINTS.store(composer.constraints(), Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SigVarGenCircuit {
    signature: SignatureVarGen,
    pk: PublicKeyVarGen,
    message: BlsScalar,
}

impl SigVarGenCircuit {
    fn valid(rng: &mut StdRng) -> Self {
        let sk = SecretKeyVarGen::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);
        let pk = PublicKeyVarGen::from(&sk);

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SigVarGenCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let u = composer.append_witness(*self.signature.u());
        let r = composer.append_point(self.signature.R());
        let pk = composer.append_point(self.pk.public_key());
        let generator = composer.append_point(self.pk.generator());
        let message = composer.append_witness(self.message);

        let _result = gadgets::verify_signature_var_gen(
            composer, u, r, pk, generator, message,
        );
        CONSTRAINTS.store(composer.constraints(), Ordering::Relaxed);
        Ok(())
    }
}

fn proof_creation_signature(criterion: &mut Criterion) {
    proof_creation(criterion, "Signature", SignatureCircuit::valid);
}

fn proof_creation_signature_double(criterion: &mut Criterion) {
    proof_creation(criterion, "Signature double", SigDoubleCircuit::valid);
}

fn proof_creation_signature_var_generation(criterion: &mut Criterion) {
    proof_creation(
        criterion,
        "Signature variable generator",
        SigVarGenCircuit::valid,
    );
}

criterion_group! {
    name = schnorr;
    config = Criterion::default().sample_size(10);
    targets =
        proof_creation_signature,
        proof_creation_signature_double,
        proof_creation_signature_var_generation,
}
criterion_main!(schnorr);
