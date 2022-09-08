use fawkes_crypto::rand::Rng;
use libzeropool::{POOL_PARAMS, circuit::tree::{CTreePub, CTreeSec, tree_update},
    native::tree::{TreePub, TreeSec},
    fawkes_crypto::{
        ff_uint::Num,
        circuit::{
            cs::{CS, DebugCS}
        }, 
        core::signal::Signal,
        rand::thread_rng,
        backend::bellman_groth16::{
            engines::Bn256,
            prover,
            verifier,
            Parameters,
        }
    }, 
};

use libzeropool::fawkes_crypto::engines::bn256::Fr;
use std::time::Instant;
    

use libzeropool::helpers::sample_data::HashTreeState;


#[test]
fn test_circuit_tx_fullfill_not_empty(){
    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);
    let num_elements:usize = rng.gen_range(1, 1000);

    for _ in 0..num_elements {
        state.push(rng.gen(), &*POOL_PARAMS);
    }

    let root_before = state.root();
    let proof_filled = state.merkle_proof(num_elements-1);
    let proof_free = state.merkle_proof(num_elements);
    let prev_leaf = state.hashes[0].last().unwrap().clone();
    state.push(rng.gen(), &*POOL_PARAMS);
    let root_after = state.root();
    let leaf = state.hashes[0].last().unwrap().clone();
    


    let p = TreePub {root_before, root_after, leaf};
    let s = TreeSec {proof_filled, proof_free, prev_leaf};


    let ref cs = DebugCS::rc_new();
    let ref p = CTreePub::alloc(cs, Some(&p));
    let ref s = CTreeSec::alloc(cs, Some(&s));

    
    let mut num_gates = cs.borrow().num_gates();
    let start = Instant::now();
    tree_update(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    num_gates=cs.borrow().num_gates()-num_gates;

    println!("tx gates = {}", num_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}

#[test]
fn test_circuit_tx_fullfill_empty(){
    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);


    let root_before = state.root();
    let proof_filled = state.merkle_proof(0);
    let proof_free = state.merkle_proof(0);
    let prev_leaf = Num::ZERO;
    state.push(rng.gen(), &*POOL_PARAMS);
    let root_after = state.root();
    let leaf = state.hashes[0].last().unwrap().clone();
     
    let p = TreePub {root_before, root_after, leaf};
    let s = TreeSec {proof_filled, proof_free, prev_leaf};


    let ref cs = DebugCS::rc_new();
    let ref p = CTreePub::alloc(cs, Some(&p));
    let ref s = CTreeSec::alloc(cs, Some(&s));

    
    let mut num_gates = cs.borrow().num_gates();
    let start = Instant::now();
    tree_update(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    num_gates=cs.borrow().num_gates()-num_gates;

    println!("tx gates = {}", num_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}

#[test]
fn load_params_and_prove() {
    fn circuit<C:CS<Fr=Fr>>(public: CTreePub<C>, secret: CTreeSec<C>) {
        tree_update(&public, &secret, &*POOL_PARAMS);
    }

    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);

    let root_before = state.root();
    let proof_filled = state.merkle_proof(0);
    let proof_free = state.merkle_proof(0);
    let prev_leaf = Num::ZERO;
    state.push(rng.gen(), &*POOL_PARAMS);
    let root_after = state.root();
    let leaf = state.hashes[0].last().unwrap().clone();
     
    let public = TreePub {root_before, root_after, leaf};
    let secret = TreeSec {proof_filled, proof_free, prev_leaf};

    let params_filename = std::env::var("PARAMS_PATH").unwrap_or(String::from("../phase2-bn254/params"));
    let should_filter_points_at_infinity = true;

    let params = Parameters::<Bn256>::read(
        &mut std::fs::read(params_filename).unwrap()[..].as_ref(),
        should_filter_points_at_infinity,
        true,
    )
    .unwrap();

    let (inputs, snark_proof) = prover::prove(&params, &public, &secret, circuit);

    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);

    assert!(res, "Verifier result should be true");
}
