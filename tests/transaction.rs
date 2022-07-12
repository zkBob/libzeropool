
use fawkes_crypto::backend::bellman_groth16::{setup::setup_with_params, Parameters};
use fawkes_crypto_phase2::parameters::MPCParameters;
use libzeropool::{
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    fawkes_crypto::{
        backend::bellman_groth16::{engines::Bn256, prover, verifier},
        circuit::cs::{DebugCS, CS},
        core::signal::Signal,
        rand::thread_rng,
    },
    POOL_PARAMS,
};

use libzeropool::fawkes_crypto::engines::bn256::Fr;
use std::{
    fs::{self, File},
    time::Instant,
};

use libzeropool::helpers::sample_data::State;

#[test]
fn test_circuit_tx_fullfill() {
    let mut rng = thread_rng();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let (p, s) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);

    let ref cs = DebugCS::rc_new();
    let ref p = CTransferPub::alloc(cs, Some(&p));
    let ref s = CTransferSec::alloc(cs, Some(&s));

    let mut num_gates = cs.borrow().num_gates();
    let start = Instant::now();
    c_transfer(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    num_gates = cs.borrow().num_gates() - num_gates;

    println!("tx gates = {}", num_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}


#[test]
fn test_circuit_tx_setup_and_prove() {
    fn circuit<C: CS<Fr = Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
        c_transfer(&public, &secret, &*POOL_PARAMS);
    }

    let mut rng = thread_rng();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let (public, secret) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);

    let ts_setup = Instant::now();

    let params_path = std::env::var("PARAMS_PATH").unwrap_or(String::from("params"));

    let params_file = File::open(params_path).unwrap();

    let bp = MPCParameters::read(params_file, false, false)
        .unwrap()
        .get_params()
        .to_owned();

    let params: Parameters<Bn256> = setup_with_params(circuit, bp);

    let duration = ts_setup.elapsed();
    println!("Time elapsed in setup() is: {:?}", duration);

    let ts_prove = Instant::now();
    let (inputs, snark_proof) = prover::prove(&params, &public, &secret, circuit);
    let duration = ts_prove.elapsed();
    println!("Time elapsed in prove() is: {:?}", duration);

    let ts_verify = Instant::now();
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    let duration = ts_verify.elapsed();
    println!("Time elapsed in verify() is: {:?}", duration);

    assert!(res, "Verifier result should be true");
}
