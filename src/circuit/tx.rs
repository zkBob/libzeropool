use crate::fawkes_crypto::typenum::{Unsigned};
use crate::fawkes_crypto::circuit::{
    bitify::{c_comp_constant, c_into_bits_le, c_into_bits_le_strict},
    bool::CBool,
    ecc::CEdwardsPoint,
    eddsaposeidon::c_eddsaposeidon_verify,
    num::CNum,
    poseidon::{c_poseidon_merkle_proof_root, c_poseidon, CMerkleProof},
};
use crate::fawkes_crypto::core::{
    signal::Signal, sizedvec::SizedVec,
};
use crate::fawkes_crypto::native::{ecc::JubJubParams};
use crate::fawkes_crypto::ff_uint::{Num, NumRepr, PrimeField, PrimeFieldParams};
use crate::fawkes_crypto::circuit::cs::RCS;
use crate::circuit::{
    boundednum::CBoundedNum,
    account::CAccount,
    note::CNote
};


use crate::native::{
    tx::{TransferPub, TransferSec, Tx},
    params::PoolParams
};

use crate::constants;


#[derive(Clone, Signal)]
#[Value = "TransferPub<P>"]
#[Field = "P::Fr"]
pub struct CTransferPub<P: PoolParams> {
    pub root: CNum<P::Fr>,
    pub nullifier: CNum<P::Fr>,
    pub out_commit: CNum<P::Fr>,
    pub delta: CNum<P::Fr>,
    pub memo: CNum<P::Fr>,
}

#[derive(Clone, Signal)]
#[Value = "Tx<P>"]
#[Field = "P::Fr"]
pub struct CTx<P: PoolParams> {
    pub input: (CAccount<P>, SizedVec<CNote<P>, constants::IN>),
    pub output: (CAccount<P>, CNote<P>)
}

#[derive(Clone, Signal)]
#[Value = "TransferSec<P>"]
#[Field = "P::Fr"]
pub struct CTransferSec<P:PoolParams> {
    pub tx: CTx<P>,
    pub in_proof: SizedVec<CMerkleProof<P::Fr, constants::H>, constants::INPROOF>,
    pub eddsa_s: CNum<P::Fr>,
    pub eddsa_r: CNum<P::Fr>,
    pub eddsa_a: CNum<P::Fr>,
}

pub fn c_nullfifier<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    account_hash: &CNum<Fr>,
    xsk: &CNum<Fr>,
    params: &P,
) -> CNum<Fr> {
    c_poseidon(
        [account_hash.clone(), xsk.clone()].as_ref(),
        params.compress(),
    )
}


pub fn c_note_hash<P: PoolParams>(
    note: &CNote<P>,
    params: &P,
) -> CNum<P::Fr> {
    c_poseidon(
        [
            note.d.as_num().clone(),
            note.pk_d.clone(),
            note.v.as_num().clone(),
            note.st.as_num().clone(),
        ]
        .as_ref(),
        params.note(),
    )
}

pub fn c_accout_hash<P: PoolParams>(ac: &CAccount<P>, params: &P) -> CNum<P::Fr> {
    let mut inputs = vec![ac.xsk.clone()];
    inputs.extend(ac.interval.iter().map(|n| n.as_num().clone() ));
    inputs.extend(vec![ac.v.as_num().clone(), ac.st.as_num().clone()]);
    c_poseidon(
        &inputs,
        params.account(),
    )
}


pub fn c_tx_hash<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    in_hash: &[CNum<Fr>],
    out_hash: &[CNum<Fr>],
    params: &P,
) -> CNum<Fr> {
    let notes = in_hash
        .iter()
        .chain(out_hash.iter())
        .cloned()
        .collect::<Vec<_>>();
    c_poseidon(&notes, params.tx())
}

pub fn c_tx_verify<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    s: &CNum<Fr>,
    r: &CNum<Fr>,
    xsk: &CNum<Fr>,
    tx_hash: &CNum<Fr>,
    params: &P,
) -> CBool<Fr> {
    c_eddsaposeidon_verify(s, r, xsk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn c_derive_key_dk<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    xsk: &CNum<Fr>,
    params: &P,
) -> Vec<CBool<Fr>> {
    let cs = xsk.get_cs();
    let t_dk = c_poseidon(&[xsk.clone()], params.hash());
    let dk_value = t_dk
        .get_value()
        .map(|v| v.to_other_reduced::<P::Fs>().to_other().unwrap());
    let dk = CNum::alloc(cs, dk_value.as_ref());

    let g = CEdwardsPoint::from_const(cs, params.jubjub().edwards_g());

    let t_dk_bits = c_into_bits_le_strict(&t_dk);
    let dk_bits = c_into_bits_le(&dk, P::Fs::MODULUS_BITS as usize);
    c_comp_constant(
        &dk_bits,
        Num::<P::Fs>::from(-1).to_other().unwrap(),
    )
    .assert_const(&false);
    (g.mul(&t_dk_bits, params.jubjub()).x - g.mul(&dk_bits, params.jubjub()).x).assert_zero();

    dk_bits
}

pub fn c_derive_key_pk_d<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    d: &CNum<Fr>,
    dk: &[CBool<Fr>],
    params: &P,
) -> CNum<Fr> {
    let d_hash = c_poseidon(&[d.clone()], params.hash());
    CEdwardsPoint::from_scalar(&d_hash, params.jubjub())
        .mul(dk, params.jubjub())
        .x
}

pub fn c_parse_delta<P:PoolParams>(delta: &CNum<P::Fr>) -> CNum<P::Fr> {
    let delta_bits = c_into_bits_le(delta, 64);
    delta - &delta_bits[63].to_num() * Num::from_uint(NumRepr::ONE << constants::V::U32).unwrap()
}

pub fn c_transfer<P:PoolParams>(
    p: &CTransferPub<P>,
    s: &CTransferSec<P>,
    params: &P,
) {
    let cs = p.get_cs();

    //build input hashes
    let account_hash = c_accout_hash(&s.tx.input.0, params);
    let note_hash = s.tx.input.1.iter().map(|n| c_note_hash(n, params)).collect::<Vec<_>>();

    let mut in_hash = vec![account_hash.clone()];
    in_hash.extend(note_hash.clone());


    //check decryption key
    let dk_bits = c_derive_key_dk(&s.eddsa_a, params);

    //build ownership
    (&s.tx.input.0.xsk - &s.eddsa_a).assert_zero();
    (&s.tx.output.0.xsk - &s.eddsa_a).assert_zero();

    for i in 0..constants::IN::USIZE {
        (&s.tx.input.1[i].pk_d - c_derive_key_pk_d(&s.tx.input.1[i].d.as_num(), &dk_bits, params)).assert_zero();
    }

    //check nullifier
    (&p.nullifier - c_nullfifier(&account_hash, &s.eddsa_a, params)).assert_zero();



    //build output hashes
    let out_account_hash = c_accout_hash(&s.tx.output.0, params);
    let out_note_hash = c_note_hash(&s.tx.output.1, params);
    let out_commitment_hash = c_poseidon([out_account_hash.clone(), out_note_hash.clone()].as_ref(), params.compress());
    (&out_commitment_hash - &p.out_commit).assert_zero();


    //build merkle proofs
    {
        let cur_root = c_poseidon_merkle_proof_root(&account_hash, &s.in_proof[0], params.compress());
        let mut is:CNum<P::Fr> = s.derive_const(&Num::ZERO);
        for it in s.tx.input.0.interval.iter() {
            is += it.as_num();
        }
        //root is correct or value==0 && interval is zero set && salt is zero 
        ((cur_root - &p.root) * (s.tx.input.0.v.as_num()+s.tx.input.0.st.as_num()+is)).assert_zero();
    }

    for i in 0..constants::IN::USIZE {
        let cur_root = c_poseidon_merkle_proof_root(&note_hash[i], &s.in_proof[i+1], params.compress());
        ((cur_root - &p.root) * s.tx.input.1[i].v.as_num()).assert_zero();
    }

    //bind msg_hash to the circuit
    (&p.memo + Num::ONE).assert_nonzero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, [out_account_hash, out_note_hash].as_ref(), params);

    //check signature
    c_tx_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params).assert_const(&true);

    //parse delta
    let delta_amount = c_parse_delta::<P>(&p.delta);

    //check balances
    let mut amount = delta_amount;

    amount += s.tx.input.0.v.as_num();

    for note in s.tx.input.1.iter() {
        amount += note.v.as_num();
    }
    amount -= s.tx.output.0.v.as_num() + s.tx.output.1.v.as_num();
    amount.assert_zero();

    //TODO implement interval check
}
