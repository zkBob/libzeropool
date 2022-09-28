use libzeropool::{POOL_PARAMS, circuit::tx::{CTransferPub, CTransferSec, c_transfer},
    fawkes_crypto::{
        circuit::{
            cs::CS
        }, 
        rand::thread_rng,
        backend::bellman_groth16::{
            engines::Bn256,
            setup::setup,
            prover,
            verifier
        }
    }, 
};

use libzeropool::fawkes_crypto::engines::bn256::Fr;
use std::time::Instant;
    

use libzeropool::helpers::sample_data::State;


#[test]
fn test_transfer_limits() {
    fn circuit<C:CS<Fr=Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
        c_transfer(&public, &secret, &*POOL_PARAMS);
    }

    let mut rng = thread_rng();
    let state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);
    
    let ts_setup = Instant::now();
    let params = setup::<Bn256, _, _, _>(circuit);
    let duration = ts_setup.elapsed();
    println!("Time elapsed in setup() is: {:?}", duration);

    for (amount, limit, success) in vec![(0, 0, true), (1, 0, false), (1, 1, true), (1, 100, true), (101, 100, false)] {
        let (public, secret) = state.sample_deterministic_transfer(&mut rng, &*POOL_PARAMS, amount as u64, limit as u64);
    
        let ts_prove = Instant::now();
        let (inputs, snark_proof) = prover::prove(&params, &public, &secret, circuit);
        let duration = ts_prove.elapsed();
        println!("Time elapsed in prove() is: {:?}", duration);
        
        let ts_verify = Instant::now();
        let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
        let duration = ts_verify.elapsed();
        println!("Time elapsed in verify() is: {:?}", duration);
    
        assert_eq!(res, success);
    }
}