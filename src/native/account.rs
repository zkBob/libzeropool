use fawkes_crypto::{ff_uint::{PrimeField, Num}, native::poseidon::poseidon};
use crate::native::{boundednum::BoundedNum,params::PoolParams};
use crate::constants;


use std::fmt::Debug;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Account<Fr:PrimeField> {
    pub d: BoundedNum<Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
    pub p_d: Num<Fr>,
    pub i: BoundedNum<Fr, { constants::HEIGHT }>,
    pub b: BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }>,
    pub e: BoundedNum<Fr, { constants::ENERGY_SIZE_BITS }>,
    pub last_action_day: BoundedNum<Fr, { constants::DAY_SIZE }>,
    pub today_turnover_used: BoundedNum<Fr, { constants::TURNOVER_SIZE }>,
}

impl<Fr:PrimeField> Account<Fr> {
    pub fn hash<P:PoolParams<Fr=Fr>>(&self, params:&P) -> Num<Fr> {
        poseidon(&[
            self.d.to_num(), 
            self.p_d, 
            self.i.to_num(), 
            self.b.to_num(), 
            self.e.to_num(),
            self.last_action_day.to_num(),
            self.today_turnover_used.to_num(),    
        ], params.account())
    }

    pub fn hash_old<P:PoolParams<Fr=Fr>>(&self, params:&P) -> Num<Fr> {
        poseidon(&[
            self.d.to_num(), 
            self.p_d, 
            self.i.to_num(), 
            self.b.to_num(), 
            self.e.to_num(), 
        ], params.account_old())
    }
}


impl<Fr:PrimeField> Eq for Account<Fr> {}

impl<Fr:PrimeField> PartialEq for Account<Fr> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.d.eq(&other.d) && 
        self.p_d.eq(&other.p_d) && 
        self.i.eq(&other.i) &&
        self.b.eq(&other.b) &&
        self.e.eq(&other.e)
    }
}
