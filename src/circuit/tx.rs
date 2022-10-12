use fawkes_crypto::{circuit::{
    bitify::{c_into_bits_le, c_into_bits_le_strict, c_comp, c_from_bits_le},
    bool::CBool,
    eddsaposeidon::c_eddsaposeidon_verify,
    num::CNum,
    poseidon::{c_poseidon_merkle_proof_root, c_poseidon, c_poseidon_merkle_tree_root, c_poseidon_sponge, CMerkleProof},
    cs::{RCS, CS}
}, ff_uint::PrimeFieldParams};
use fawkes_crypto::core::{signal::Signal, sizedvec::SizedVec,};
use fawkes_crypto::ff_uint::{Num, NumRepr};
use crate::{circuit::{account::CAccount, note::CNote, key::{c_derive_key_eta, c_derive_key_p_d}}, constants::{DAY_SIZE_BITS, TURNOVER_SIZE_BITS}};
use crate::native::tx::{TransferPub, TransferSec, Tx};
use crate::native::params::PoolParams;
use crate::constants::{HEIGHT, IN, OUT, BALANCE_SIZE_BITS, ENERGY_SIZE_BITS, POOLID_SIZE_BITS};

use super::boundednum::CBoundedNum;


#[derive(Clone, Signal)]
#[Value = "TransferPub<C::Fr>"]
pub struct CTransferPub<C:CS> {
    pub root: CNum<C>,
    pub nullifier: CNum<C>,
    pub out_commit: CNum<C>,
    pub delta: CNum<C>, // int64 token delta, int64 energy delta, uint32 blocknumber
    pub memo: CNum<C>,
    pub day: CBoundedNum<C, { DAY_SIZE_BITS }>,
    pub daily_limit: CBoundedNum<C, { TURNOVER_SIZE_BITS }>,
}

#[derive(Clone, Signal)]
#[Value = "Tx<C::Fr>"]
pub struct CTx<C:CS> {
    pub input: (CAccount<C>, SizedVec<CNote<C>, { IN }>),
    pub output: (CAccount<C>, SizedVec<CNote<C>, { OUT}>)
}

#[derive(Clone, Signal)]
#[Value = "TransferSec<C::Fr>"]
pub struct CTransferSec<C:CS> {
    pub tx: CTx<C>,
    pub in_proof: (CMerkleProof<C, { HEIGHT }>, SizedVec<CMerkleProof<C, { HEIGHT }>, { IN }>),
    pub eddsa_s: CNum<C>,
    pub eddsa_r: CNum<C>,
    pub eddsa_a: CNum<C>,
}

pub fn c_nullfifier<C:CS, P: PoolParams<Fr = C::Fr>>(
    in_account_hash: &CNum<C>,
    eta: &CNum<C>,
    path: &CNum<C>,
    params: &P,
) -> CNum<C> {
    let intermediate_hash = c_poseidon(
        [in_account_hash.clone(), eta.clone(), path.clone()].as_ref(),
        params.nullifier_intermediate(),
    );

    c_poseidon(
        [in_account_hash.clone(), intermediate_hash].as_ref(),
        params.compress(),
    )
}

pub fn c_tx_hash<C:CS, P: PoolParams<Fr = C::Fr>>(
    in_hash: &[CNum<C>],
    out_commitment: &CNum<C>,
    params: &P,
) -> CNum<C> {
    let data = in_hash.iter().chain(core::iter::once(out_commitment)).cloned().collect::<Vec<_>>();
    c_poseidon_sponge(&data, params.sponge())
}

pub fn c_tx_verify<C:CS, P: PoolParams<Fr = C::Fr>>(
    s: &CNum<C>,
    r: &CNum<C>,
    a: &CNum<C>,
    tx_hash: &CNum<C>,
    params: &P,
) -> CBool<C> {
    c_eddsaposeidon_verify(s, r, a, tx_hash, params.eddsa(), params.jubjub())
}


pub fn c_out_commitment_hash<C:CS, P:PoolParams<Fr=C::Fr>>(items:&[CNum<C>], params: &P) -> CNum<C> {
    assert!(items.len()==OUT+1);
    c_poseidon_merkle_tree_root(items, params.compress())
}

pub fn c_parse_delta<C:CS, P:PoolParams<Fr=C::Fr>>(delta: &CNum<C>) -> (CNum<C>, CNum<C>, CNum<C>, CNum<C>) {
    fn c_parse_uint<C:CS>(bits: &mut &[CBool<C>], len:usize) -> CNum<C> {
        let res = c_from_bits_le(&bits[0..len]);
        *bits = &bits[len..];
        res
    }

    fn c_parse_int<C:CS>(bits: &mut &[CBool<C>], len:usize) -> CNum<C> {
        let two_component_term = - bits[len-1].as_num() * Num::from_uint(NumRepr::ONE << len as u32).unwrap();
        two_component_term + c_parse_uint(bits, len)
    }

    let delta_bits_vec = c_into_bits_le(delta, BALANCE_SIZE_BITS+ENERGY_SIZE_BITS+HEIGHT+POOLID_SIZE_BITS);
    let mut delta_bits = delta_bits_vec.as_slice();

    (
        c_parse_int(&mut delta_bits, BALANCE_SIZE_BITS),
        c_parse_int(&mut delta_bits, ENERGY_SIZE_BITS),
        c_parse_uint(&mut delta_bits, HEIGHT),
        c_parse_uint(&mut delta_bits, POOLID_SIZE_BITS),
    )

}



pub fn c_transfer<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CTransferPub<C>,
    s: &CTransferSec<C>,
    params: &P,
) {
    //parse delta
    let (delta_value, delta_energy, current_index, poolid) = c_parse_delta::<C,P>(&p.delta);
    let mut total_value = delta_value;
    let mut total_enegry = delta_energy;

    let input_index = s.tx.input.0.i.as_num();
    let output_index = s.tx.output.0.i.as_num();
    
    
    //build input hashes
    let in_note_hash = s.tx.input.1.iter().map(|n| n.hash(params)).collect::<Vec<_>>();

    //assert input notes are unique
    let mut t:CNum<C> = p.derive_const(&Num::ZERO);
    for i in 0..IN {
        for j in i+1..IN {
            t+=(&in_note_hash[i]-&in_note_hash[j]).is_zero().as_num();
        }
    }
    t.assert_zero();



    //build output hashes
    let out_account_hash = s.tx.output.0.hash(params);
    let out_note_hash = s.tx.output.1.iter().map(|e| e.hash(params)).collect::<Vec<_>>();
    let out_hash = [[out_account_hash].as_ref(), out_note_hash.as_slice()].concat();

    //assert out notes are unique or zero, compute out sum
    let mut out_notes_sum: CNum<C> = p.derive_const(&Num::ZERO);
    let mut t:CNum<C> = p.derive_const(&Num::ZERO);
    let mut out_note_zero_num:CNum<C> = p.derive_const(&Num::ZERO);
    for i in 0..OUT {
        out_note_zero_num+=s.tx.output.1[i].is_zero().as_num();
        for j in i+1..OUT {
            t+=(&out_note_hash[i]-&out_note_hash[j]).is_zero().as_num();
        }
        out_notes_sum += s.tx.output.1[i].b.as_num();
    }
    t -= &out_note_zero_num*(&out_note_zero_num-Num::ONE)/Num::from(2u64);
    t.assert_zero();

    //check output     
    let out_ch = c_out_commitment_hash(&out_hash, params);
    (&out_ch - &p.out_commit).assert_zero();


    //build decryption key
    //address is derived from decryption key
    //also decryption key is using for decrypting the data of notes
    let eta = c_derive_key_eta(&s.eddsa_a, params);
    let eta_bits = c_into_bits_le_strict(&eta);

    //check ownership
    (&s.tx.input.0.p_d - c_derive_key_p_d(&s.tx.input.0.d.as_num(), &eta_bits, params).x).assert_zero();
    (&s.tx.output.0.p_d - c_derive_key_p_d(&s.tx.output.0.d.as_num(), &eta_bits, params).x).assert_zero();

    for i in 0..IN {
        (&s.tx.input.1[i].p_d - c_derive_key_p_d(&s.tx.input.1[i].d.as_num(), &eta_bits, params).x).assert_zero();
    }

    // Check daily turnover limit
    let in_account = &s.tx.input.0;
    let out_account = &s.tx.output.0;
    {
        let is_new_day = c_comp(&p.day.as_num(), &in_account.last_action_day.as_num(), DAY_SIZE_BITS);

        let delta_value_is_positive = c_comp(&total_value, &p.derive_const(&Num::ZERO), TURNOVER_SIZE_BITS);
        let delta_value_abs = total_value.clone().switch(&delta_value_is_positive, &-&total_value);
        let tx_turnover = delta_value_abs + out_notes_sum;
        let turnover = tx_turnover.switch(&is_new_day, &(in_account.daily_turnover.as_num() + &tx_turnover));

        // Check that current day >= last_action_day
        (&is_new_day | p.day.is_eq(&in_account.last_action_day)).assert_const(&true);
        // Check turnover limit
        c_comp(&turnover, &p.daily_limit.as_num(), TURNOVER_SIZE_BITS).assert_const(&false);    
        // Check output account turnover
        out_account.daily_turnover.as_num().is_eq(&turnover).assert_const(&true);
        // Check output account last_action_day
        out_account.last_action_day.as_num().is_eq(&p.day.as_num()).assert_const(&true);
    }

    //assuming input_pos_index <= current_index
    let ref input_pos_index = c_from_bits_le(s.in_proof.0.path.as_slice());

    let (in_account_hash, nullifier) = {
        let in_account_hash_new = in_account.hash(params);
        let in_account_hash_old = in_account.hash_old(params);

        let nullifier_new = c_nullfifier(&in_account_hash_new, &eta, input_pos_index, params);
        let nullifier_old = c_nullfifier(&in_account_hash_old, &eta, input_pos_index, params);

        let is_old_account = nullifier_old.is_eq(&p.nullifier);
        (!&is_old_account | 
            in_account.last_action_day.as_num().is_eq(&p.derive_const(&Num::ZERO)) & 
            in_account.daily_turnover.as_num().is_eq(&p.derive_const(&Num::ZERO))
        ).assert_const(&true);

        let in_account_hash = in_account_hash_old.switch(&is_old_account, &in_account_hash_new);
        let nullifier = nullifier_old.switch(&is_old_account, &nullifier_new);
        (in_account_hash, nullifier)
    };

    //build merkle proofs and check nullifier
    {
        //check nullifier
        (&p.nullifier - nullifier).assert_zero();

        let cur_root = c_poseidon_merkle_proof_root(&in_account_hash, &s.in_proof.0, params.compress());
        //assert root == cur_root || account.is_dummy()
        //all uninitialized empty accounts considered to be in the privacy set
        (cur_root.is_eq(&p.root) | s.tx.input.0.is_initial(&poolid)).assert_const(&true);

        //input_index <= output_index
        c_comp(input_index, output_index, HEIGHT).assert_const(&false);

        //output_index <= current_index
        c_comp(output_index, &current_index, HEIGHT).assert_const(&false);

        //compute enegry
        total_enegry += s.tx.input.0.b.as_num() * (&current_index - input_pos_index);
    }


    for i in 0..IN {
        let note_value = s.tx.input.1[i].b.as_num();
        let ref note_index = c_from_bits_le(s.in_proof.1[i].path.as_slice());

        let cur_root = c_poseidon_merkle_proof_root(&in_note_hash[i], &s.in_proof.1[i], params.compress());
        ((cur_root - &p.root) * note_value).assert_zero();

        //note_index >= account_in.interval && note_index < account_out.interval || note_index == 0 && value == 0

        //input_index <= note_index && note_index < output_index || note_dummy
        let note_index_ok = (!c_comp(input_index, note_index, HEIGHT)) & c_comp(output_index, note_index, HEIGHT);
        let note_dummy = s.tx.input.1[i].is_dummy_raw().is_zero();
        (note_index_ok | note_dummy).assert_const(&true);

        //compute enegry
        total_enegry += note_value * (&current_index - note_index);
    }

    //bind msg_hash to the circuit
    (&p.memo + Num::ONE).assert_nonzero();

    //build tx 
    let in_hash = [[in_account_hash].as_ref(), in_note_hash.as_slice()].concat();
    let tx_hash = c_tx_hash(&in_hash, &out_ch, params);

    //check signature
    c_tx_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params).assert_const(&true);

    //check balances
    total_value += s.tx.input.0.b.as_num() - s.tx.output.0.b.as_num();

    for note in s.tx.input.1.iter() {
        total_value += note.b.as_num();
    }

    for note in s.tx.output.1.iter() {
        total_value -= note.b.as_num();
    }

    total_value.assert_zero();

    //final check energy
    total_enegry += s.tx.input.0.e.as_num();
    total_enegry -= s.tx.output.0.e.as_num();

    //assuming no overflow when sum total_enegry
    c_into_bits_le(&total_enegry, <C::Fr as PrimeFieldParams>::MODULUS_BITS as usize - 2);
}

