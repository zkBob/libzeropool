use crate::fawkes_crypto::{
    native::ecc::JubJubParams,
    native::poseidon::PoseidonParams,
    ff_uint::PrimeField,
    engines::bn256::{Fr, JubJubBN256}
};


pub trait PoolParams: Clone + Sized {
    type Fr: PrimeField;
    type Fs: PrimeField;
    type J: JubJubParams<Fr = Self::Fr, Fs = Self::Fs>;

    fn jubjub(&self) -> &Self::J;
    fn hash(&self) -> &PoseidonParams<Self::Fr>;
    fn compress(&self) -> &PoseidonParams<Self::Fr>;
    fn note(&self) -> &PoseidonParams<Self::Fr>;
    fn account(&self) -> &PoseidonParams<Self::Fr>;
    fn account_old(&self) -> &PoseidonParams<Self::Fr>;
    fn eddsa(&self) -> &PoseidonParams<Self::Fr>;
    fn sponge(&self) -> &PoseidonParams<Self::Fr>;
    fn nullifier_intermediate(&self) -> &PoseidonParams<Self::Fr>;
}

#[derive(Clone)]
pub struct PoolBN256 {
    pub jubjub: JubJubBN256,
    pub hash: PoseidonParams<Fr>,
    pub compress: PoseidonParams<Fr>,
    pub note: PoseidonParams<Fr>,
    pub account: PoseidonParams<Fr>,
    pub account_old: PoseidonParams<Fr>,
    pub eddsa: PoseidonParams<Fr>,
    pub sponge: PoseidonParams<Fr>,
    pub nullifier_intermediate: PoseidonParams<Fr>,
}

impl PoolParams for PoolBN256 {
    type Fr = Fr;
    type Fs = <JubJubBN256 as JubJubParams>::Fs;
    type J = JubJubBN256;


    fn jubjub(&self) -> &Self::J {
        &self.jubjub
    }

    fn hash(&self) -> &PoseidonParams<Self::Fr> {
        &self.hash
    }

    fn compress(&self) -> &PoseidonParams<Self::Fr> {
        &self.compress
    }

    fn note(&self) -> &PoseidonParams<Self::Fr> {
        &self.note
    }

    fn account(&self) -> &PoseidonParams<Self::Fr> {
        &self.account
    }

    fn account_old(&self) -> &PoseidonParams<Self::Fr> {
        &self.account_old
    }

    fn eddsa(&self) -> &PoseidonParams<Self::Fr> {
        &self.eddsa
    }

    fn sponge(&self) -> &PoseidonParams<Self::Fr> {
        &self.sponge
    }

    fn nullifier_intermediate(&self) -> &PoseidonParams<Self::Fr> {
        &self.nullifier_intermediate
    }
}


