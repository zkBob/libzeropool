use fawkes_crypto::rand::Rng;
use libzeropool::{POOL_PARAMS, circuit::tx::{CTransferPub, CTransferSec, c_transfer},
    fawkes_crypto::{
        circuit::cs::DebugCS, 
        rand::thread_rng, core::signal::Signal
    }, native::params::PoolBN256, 
};
use std::panic;

use libzeropool::helpers::sample_data::State;

#[test]
fn test_daily_limits_1() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    transfer(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 1, 200, 0, false);
}

#[test]
fn test_daily_limits_2() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    transfer(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 1, true);
}

#[test]
fn test_daily_limits_3() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    transfer(&mut state, &mut rng, 201, 200, 0, false);
}

#[test]
fn test_daily_limits_4() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    transfer(&mut state, &mut rng, 200, 200, 0, true);
    transfer(&mut state, &mut rng, 200, 200, 1, true);
    transfer(&mut state, &mut rng, 200, 200, 10, true);
}

#[test]
fn test_daily_limits_5() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    transfer(&mut state, &mut rng, 200, 200, 0, true);
    transfer(&mut state, &mut rng, 200, 200, 10, true);
    transfer(&mut state, &mut rng, 200, 200, 9, false);
}

#[test]
fn test_daily_limits_6() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 1, 200, 0, false);
}

#[test]
fn test_daily_limits_7() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 1, true);
}

#[test]
fn test_daily_limits_8() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 201, 200, 0, false);
}

#[test]
fn test_daily_limits_9() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 200, 200, 0, true);
    deposit(&mut state, &mut rng, 200, 200, 1, true);
    deposit(&mut state, &mut rng, 200, 200, 10, true);
}

#[test]
fn test_daily_limits_10() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 200, 200, 0, true);
    deposit(&mut state, &mut rng, 200, 200, 10, true);
    deposit(&mut state, &mut rng, 1, 200, 9, false);
}

#[test]
fn test_daily_limits_11() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 0, true);
    withdrawal(&mut state, &mut rng, 1, 200, 0, false);
}

#[test]
fn test_daily_limits_12() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    deposit(&mut state, &mut rng, 100, 200, 0, true);
    transfer(&mut state, &mut rng, 100, 200, 0, true);
    withdrawal(&mut state, &mut rng, 100, 200, 1, true);
}

#[test]
fn test_daily_limits_13() {
    let mut rng = thread_rng();
    let mut state = State::sample_deterministic_state(&mut rng, &*POOL_PARAMS);

    withdrawal(&mut state, &mut rng, 201, 200, 0, false);
}

fn deposit<R: Rng>(state: &mut State<PoolBN256>, rng: &mut R, amount: u64, daily_limit: u64, current_day: u64, success: bool) {
    let (public, secret) = state.sample_deterministic_deposit(rng, &*POOL_PARAMS, amount as u64, current_day as u64, daily_limit as u64);
    let params = POOL_PARAMS.clone();
    let result = panic::catch_unwind(move || {
        let ref cs = DebugCS::rc_new();
        let ref p = CTransferPub::alloc(cs, Some(&public));
        let ref s = CTransferSec::alloc(cs, Some(&secret));
        c_transfer(p, s, &params)
    });
    assert_eq!(result.is_ok(), success);
}

fn transfer<R: Rng>(state: &mut State<PoolBN256>, rng: &mut R, amount: u64, daily_limit: u64, current_day: u64, success: bool) {
    let (public, secret) = state.sample_deterministic_transfer(rng, &*POOL_PARAMS, amount as u64, current_day as u64, daily_limit as u64);
    let params = POOL_PARAMS.clone();
    let result = panic::catch_unwind(move || {
        let ref cs = DebugCS::rc_new();
        let ref p = CTransferPub::alloc(cs, Some(&public));
        let ref s = CTransferSec::alloc(cs, Some(&secret));
        c_transfer(p, s, &params)
    });
    assert_eq!(result.is_ok(), success);
}

fn withdrawal<R: Rng>(state: &mut State<PoolBN256>, rng: &mut R, amount: u64, daily_limit: u64, current_day: u64, success: bool) {
    let (public, secret) = state.sample_deterministic_withdrawal(rng, &*POOL_PARAMS, amount as u64, current_day as u64, daily_limit as u64);
    let params = POOL_PARAMS.clone();
    let result = panic::catch_unwind(move || {
        let ref cs = DebugCS::rc_new();
        let ref p = CTransferPub::alloc(cs, Some(&public));
        let ref s = CTransferSec::alloc(cs, Some(&secret));
        c_transfer(p, s, &params)
    });
    assert_eq!(result.is_ok(), success);
}