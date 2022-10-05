
use fawkes_crypto::ff_uint::{NumRepr, Uint};

use crate::{constants, 
    fawkes_crypto::{
        ff_uint::Num,
        native::poseidon::{poseidon, MerkleProof}, 
        rand::{self, Rng},
    }, 
    native::{
        account::Account, 
        boundednum::BoundedNum, 
        note::Note, 
        params::{PoolParams}, 
        tx::{make_delta, Tx, TransferPub, TransferSec, nullifier, tx_hash, tx_sign, out_commitment_hash},
        key::{derive_key_a, derive_key_eta, derive_key_p_d}
    }
};


pub const N_ITEMS:usize = 1000;

pub struct HashTreeState<P:PoolParams> {
    pub hashes:Vec<Vec<Num<P::Fr>>>,
    pub default_hashes: Vec<Num<P::Fr>>
}

impl<P:PoolParams> HashTreeState<P> {
    pub fn new(params:&P) -> Self {
        let default_hashes = {
            std::iter::successors(Some(Num::ZERO), |t| 
                Some(poseidon([*t,*t].as_ref(), params.compress()))
            ).skip(constants::OUTPLUSONELOG).take(constants::HEIGHT - constants::OUTPLUSONELOG+1).collect()
        };
        
        let hashes = (0..constants::HEIGHT - constants::OUTPLUSONELOG+1).map(|_| vec![]).collect();

        Self {hashes, default_hashes}
    }

    pub fn push(&mut self, n:Num<P::Fr>, params:&P) {
        let mut p = self.hashes[0].len();
        self.hashes[0].push(n);

        for i in 0..constants::HEIGHT - constants::OUTPLUSONELOG {
            p >>= 1;
            if self.hashes[i+1].len() <= p {
                self.hashes[i+1].push(self.default_hashes[i+1]);
            }
            let left = self.cell(i, 2*p);
            let right = self.cell(i, 2*p+1);
            self.hashes[i+1][p] = poseidon([left, right].as_ref(), params.compress());
        }
    }

    pub fn cell(&self, i:usize, j:usize) -> Num<P::Fr> {
        if self.hashes[i].len() <= j {
            self.default_hashes[i]
        } else {
            self.hashes[i][j]
        }
    }

    pub fn merkle_proof(&self, id:usize) -> MerkleProof<P::Fr, { constants::HEIGHT - constants::OUTPLUSONELOG }> {
        let sibling = (0..constants::HEIGHT - constants::OUTPLUSONELOG).map(|i| self.cell(i, (id>>i)^1)).collect();
        let path =  (0..constants::HEIGHT - constants::OUTPLUSONELOG).map(|i| (id>>i)&1==1).collect();
        MerkleProof {sibling, path}
    }

    pub fn root(&self) -> Num<P::Fr> {
        return self.cell(constants::HEIGHT - constants::OUTPLUSONELOG, 0)
    }
}

pub struct State<P:PoolParams> {
    pub hashes:Vec<Vec<Num<P::Fr>>>,
    pub items:Vec<(Account<P::Fr>, Note<P::Fr>)>,
    pub default_hashes:Vec<Num<P::Fr>>,
    pub sigma:Num<P::Fs>,
    pub account_id:usize,
    pub note_id:Vec<usize>
}

impl<P:PoolParams> State<P> {
    pub fn random_sample_state<R:Rng>(rng:&mut R, params:&P) -> Self {
        let sigma = rng.gen();
        let a = derive_key_a(sigma, params);
        let eta = derive_key_eta(a.x, params);


        let account_id = rng.gen_range(0, N_ITEMS);
        let note_id = rand::seq::index::sample(rng, N_ITEMS, constants::IN).into_vec();


        let mut items:Vec<(Account<_>, Note<_>)> = (0..N_ITEMS).map(|_| (Account::sample(rng, params), Note::sample(rng, params) )).collect();

        for i in note_id.iter().cloned() {
            items[i].1.p_d = derive_key_p_d(items[i].1.d.to_num(), eta, params).x;
        }

        items[account_id].0.p_d = derive_key_p_d(items[account_id].0.d.to_num(), eta, params).x;
        items[account_id].0.i = BoundedNum::new(Num::ZERO);

        let mut default_hashes = vec![Num::ZERO;constants::HEIGHT+1];
        let mut hashes = vec![];

        for i in 0..constants::HEIGHT {
            let t = default_hashes[i];
            default_hashes[i+1] = poseidon([t,t].as_ref(), params.compress());
        }

        {
            let mut t = vec![];
            for j in 0..N_ITEMS {
                let (a, n) = items[j].clone();
                t.push(a.hash_old(params));
                t.push(n.hash(params));
            }
            if t.len() & 1 == 1 {
                t.push(default_hashes[0]);
            }
            hashes.push(t);
        }

        for i in 0..constants::HEIGHT {
            let mut t = vec![];
            for j in 0..hashes[i].len()>>1 {
                t.push(poseidon([hashes[i][2*j],hashes[i][2*j+1]].as_ref(), params.compress()));
            }
            if t.len() & 1 == 1 {
                t.push(default_hashes[i+1]);
            }
            hashes.push(t);
        }

        Self {
            hashes,
            items,
            default_hashes,
            sigma,
            account_id,
            note_id
        }
    }

    pub fn random_sample_transfer<R:Rng>(&self, rng:&mut R, params:&P) -> (TransferPub<P::Fr>, TransferSec<P::Fr>) {

        let zero_note = Note {
            d: BoundedNum::new(Num::ZERO),
            p_d: Num::ZERO,
            b: BoundedNum::new(Num::ZERO),
            t: BoundedNum::new(Num::ZERO),
        };

        let root = self.root();
        let index = N_ITEMS*2;
        let a = derive_key_a(self.sigma, params);
        let eta = derive_key_eta(a.x, params);
        let nullifier = nullifier(self.hashes[0][self.account_id*2], eta, Num::from(self.account_id as u32 * 2), params);
        let memo:Num<P::Fr> = rng.gen();

        
        let mut input_value = self.items[self.account_id].0.b.to_num();
        for &i in self.note_id.iter() {
            input_value+=self.items[i].1.b.to_num();
        }

        let mut input_energy = self.items[self.account_id].0.e.to_num();
        input_energy += self.items[self.account_id].0.b.to_num()*(Num::from((index-self.account_id*2) as u32)) ;


        for &i in self.note_id.iter() {
            input_energy+=self.items[i].1.b.to_num()*Num::from((index-(2*i+1)) as u32);
        }

        let mut out_account: Account<P::Fr> = Account::sample(rng, params);
        out_account.b = BoundedNum::new(input_value);
        out_account.e = BoundedNum::new(input_energy);
        out_account.i = BoundedNum::new(Num::from(index as u32));
        out_account.p_d = derive_key_p_d(out_account.d.to_num(), eta, params).x;
        out_account.last_action_day = BoundedNum::new(Num::from_uint_unchecked(NumRepr(Uint::from_u64(1))));

        
        let mut out_note: Note<P::Fr> = Note::sample(rng, params);
        out_note.b = BoundedNum::new(Num::ZERO);

        let mut input_hashes = vec![self.items[self.account_id].0.hash_old(params)];
        for &i in self.note_id.iter() {
            input_hashes.push(self.items[i].1.hash(params));
        }

        let out_notes:Vec<_> = std::iter::once(out_note).chain(core::iter::repeat(zero_note).take(constants::OUT-1)).collect();
        let out_hashes:Vec<_> = std::iter::once(out_account.hash(params)).chain(out_notes.iter().map(|n| n.hash(params))).collect();
        let out_commit = out_commitment_hash(&out_hashes, params);
        let tx_hash = tx_hash(&input_hashes, out_commit, params);
        let (eddsa_s,eddsa_r) = tx_sign(self.sigma, tx_hash, params);


        let delta = make_delta::<P::Fr>(Num::ZERO, Num::ZERO, Num::from(index as u32), Num::ZERO);
        
        let p = TransferPub::<P::Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,  
            current_day: Num::from_uint_unchecked(NumRepr(Uint::from_u64(1))),
            daily_limit: Num::from_uint_unchecked(NumRepr(Uint::from_u64(100)))
        };



        
    
        let tx = Tx {
            input: (self.items[self.account_id].0.clone(), self.note_id.iter().map(|&i| self.items[i].1.clone()).collect()),
            output: (out_account, out_notes.iter().cloned().collect() )
        };


        
        let s = TransferSec::<P::Fr> {
            tx,
            in_proof: (
                self.merkle_proof(self.account_id*2),
                self.note_id.iter().map(|&i| self.merkle_proof(i*2+1) ).collect()
            ),
            eddsa_s:eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a:a.x
        };

        (p, s)
    }

    pub fn sample_deterministic_state<R:Rng>(rng:&mut R, params:&P) -> Self {
        let sigma = rng.gen();
        let a = derive_key_a(sigma, params);
        let eta = derive_key_eta(a.x, params);


        let account_id = rng.gen_range(0, N_ITEMS);
        let note_id = rand::seq::index::sample(rng, N_ITEMS, constants::IN).into_vec();


        let mut items:Vec<(Account<_>, Note<_>)> = (0..N_ITEMS).map(|_| (Account::sample(rng, params), Note::sample(rng, params) )).collect();

        for i in note_id.iter().cloned() {
            items[i].1.p_d = derive_key_p_d(items[i].1.d.to_num(), eta, params).x;
        }

        items[account_id].0.p_d = derive_key_p_d(items[account_id].0.d.to_num(), eta, params).x;
        items[account_id].0.i = BoundedNum::new(Num::ZERO);
        items[account_id].0.b = BoundedNum::new(Num::from_uint_unchecked(NumRepr(Uint::from_u64(1000))));

        let mut default_hashes = vec![Num::ZERO;constants::HEIGHT+1];
        let mut hashes = vec![];

        for i in 0..constants::HEIGHT {
            let t = default_hashes[i];
            default_hashes[i+1] = poseidon([t,t].as_ref(), params.compress());
        }

        {
            let mut t = vec![];
            for j in 0..N_ITEMS {
                let (a, n) = items[j].clone();
                t.push(a.hash_old(params));
                t.push(n.hash(params));
            }
            if t.len() & 1 == 1 {
                t.push(default_hashes[0]);
            }
            hashes.push(t);
        }

        for i in 0..constants::HEIGHT {
            let mut t = vec![];
            for j in 0..hashes[i].len()>>1 {
                t.push(poseidon([hashes[i][2*j],hashes[i][2*j+1]].as_ref(), params.compress()));
            }
            if t.len() & 1 == 1 {
                t.push(default_hashes[i+1]);
            }
            hashes.push(t);
        }

        Self {
            hashes,
            items,
            default_hashes,
            sigma,
            account_id,
            note_id
        }
    }

    pub fn sample_deterministic_transfer<R:Rng>(&mut self, rng:&mut R, params:&P, amount: u64, current_day: u64, daily_limit: u64) -> (TransferPub<P::Fr>, TransferSec<P::Fr>) {
        let amount = Num::from_uint_unchecked(NumRepr(Uint::from_u64(amount)));
        let current_day = Num::from_uint_unchecked(NumRepr(Uint::from_u64(current_day)));
        let daily_limit = Num::from_uint_unchecked(NumRepr(Uint::from_u64(daily_limit)));

        let index = self.items.len()*2;
        let a = derive_key_a(self.sigma, params);
        let eta = derive_key_eta(a.x, params);
        
        let mut input_value = self.items[self.account_id].0.b.to_num();
        for &i in self.note_id.iter() {
            input_value+=self.items[i].1.b.to_num();
        }

        let mut input_energy = self.items[self.account_id].0.e.to_num();
        input_energy += self.items[self.account_id].0.b.to_num()*(Num::from((index-self.account_id*2) as u32)) ;


        for &i in self.note_id.iter() {
            input_energy+=self.items[i].1.b.to_num()*Num::from((index-(2*i+1)) as u32);
        }

        let in_account = &self.items[self.account_id].0;
        let mut today_turnover_used = amount;
        if &current_day == in_account.last_action_day.as_num() {
            today_turnover_used += in_account.today_turnover_used.as_num();
        }

        let mut out_account: Account<P::Fr> = Account::sample(rng, params);
        out_account.b = BoundedNum::new(input_value - amount);
        out_account.e = BoundedNum::new(input_energy);
        out_account.i = BoundedNum::new(Num::from(index as u32));
        out_account.p_d = derive_key_p_d(out_account.d.to_num(), eta, params).x;
        out_account.last_action_day = BoundedNum::new(current_day);
        out_account.today_turnover_used = BoundedNum::new(today_turnover_used);

        
        let mut out_note: Note<P::Fr> = Note::sample(rng, params);
        out_note.b = BoundedNum::new(amount);
        out_note.p_d = derive_key_p_d(out_note.d.to_num(), eta, params).x;

        self.prepare_tx(rng, params, out_account, Some(out_note), Num::ZERO, current_day, daily_limit)
    }

    pub fn sample_deterministic_deposit<R:Rng>(&mut self, rng:&mut R, params:&P, amount: u64, current_day: u64, daily_limit: u64) -> (TransferPub<P::Fr>, TransferSec<P::Fr>) {
        let amount = Num::from_uint_unchecked(NumRepr(Uint::from_u64(amount)));
        let current_day = Num::from_uint_unchecked(NumRepr(Uint::from_u64(current_day)));
        let daily_limit = Num::from_uint_unchecked(NumRepr(Uint::from_u64(daily_limit)));

        let index = self.items.len()*2;
        let a = derive_key_a(self.sigma, params);
        let eta = derive_key_eta(a.x, params);

        let mut input_value = self.items[self.account_id].0.b.to_num();
        for &i in self.note_id.iter() {
            input_value+=self.items[i].1.b.to_num();
        }

        let mut input_energy = self.items[self.account_id].0.e.to_num();
        input_energy += self.items[self.account_id].0.b.to_num()*(Num::from((index-self.account_id*2) as u32)) ;
        for &i in self.note_id.iter() {
            input_energy+=self.items[i].1.b.to_num()*Num::from((index-(2*i+1)) as u32);
        }

        let in_account = &self.items[self.account_id].0;
        let mut today_turnover_used = amount;
        if &current_day == in_account.last_action_day.as_num() {
            today_turnover_used += in_account.today_turnover_used.as_num();
        }

        let mut out_account: Account<P::Fr> = Account::sample(rng, params);
        out_account.b = BoundedNum::new(input_value + amount);
        out_account.e = BoundedNum::new(input_energy);
        out_account.i = BoundedNum::new(Num::from(index as u32));
        out_account.p_d = derive_key_p_d(out_account.d.to_num(), eta, params).x;
        out_account.last_action_day = BoundedNum::new(current_day);
        out_account.today_turnover_used = BoundedNum::new(today_turnover_used);

        self.prepare_tx(rng, params, out_account, None, amount, current_day, daily_limit)
    }

    pub fn sample_deterministic_withdrawal<R:Rng>(&mut self, rng:&mut R, params:&P, amount: u64, current_day: u64, daily_limit: u64) -> (TransferPub<P::Fr>, TransferSec<P::Fr>) {
        let amount = Num::from_uint_unchecked(NumRepr(Uint::from_u64(amount)));
        let current_day = Num::from_uint_unchecked(NumRepr(Uint::from_u64(current_day)));
        let daily_limit = Num::from_uint_unchecked(NumRepr(Uint::from_u64(daily_limit)));

        let index = self.items.len()*2;
        let a = derive_key_a(self.sigma, params);
        let eta = derive_key_eta(a.x, params);

        let mut input_value = self.items[self.account_id].0.b.to_num();
        for &i in self.note_id.iter() {
            input_value+=self.items[i].1.b.to_num();
        }

        let mut input_energy = self.items[self.account_id].0.e.to_num();
        input_energy += self.items[self.account_id].0.b.to_num()*(Num::from((index-self.account_id*2) as u32)) ;
        for &i in self.note_id.iter() {
            input_energy+=self.items[i].1.b.to_num()*Num::from((index-(2*i+1)) as u32);
        }

        let in_account = &self.items[self.account_id].0;
        let mut today_turnover_used = amount;
        if &current_day == in_account.last_action_day.as_num() {
            today_turnover_used += in_account.today_turnover_used.as_num();
        }

        let mut out_account: Account<P::Fr> = Account::sample(rng, params);
        out_account.b = BoundedNum::new(input_value - amount);
        out_account.e = BoundedNum::new(input_energy);
        out_account.i = BoundedNum::new(Num::from(index as u32));
        out_account.p_d = derive_key_p_d(out_account.d.to_num(), eta, params).x;
        out_account.last_action_day = BoundedNum::new(current_day);
        out_account.today_turnover_used = BoundedNum::new(today_turnover_used);

        self.prepare_tx(rng, params, out_account, None, -amount, current_day, daily_limit)
    }


    fn prepare_tx<R:Rng>(
        &mut self, 
        rng: &mut R, 
        params:&P,
        out_account: Account<P::Fr>, 
        out_note: Option<Note<P::Fr>>,
        delta_value: Num<P::Fr>,
        current_day: Num<P::Fr>,
        daily_limit: Num<P::Fr>
    ) -> (TransferPub<P::Fr>, TransferSec<P::Fr>) {
        let zero_note = Note {
            d: BoundedNum::new(Num::ZERO),
            p_d: Num::ZERO,
            b: BoundedNum::new(Num::ZERO),
            t: BoundedNum::new(Num::ZERO),
        };

        let root = self.root();
        let index = self.items.len()*2;
        let a = derive_key_a(self.sigma, params);
        let eta = derive_key_eta(a.x, params);
        let nullifier = nullifier(self.hashes[0][self.account_id*2], eta, Num::from(self.account_id as u32 * 2), params);
        let memo:Num<P::Fr> = rng.gen();

        let owned_zero_notes = (0..).map(|_| {
            let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
            let p_d = derive_key_p_d::<P, P::Fr>(d.to_num(), eta, &params).x;
            Note {
                d,
                p_d,
                b: BoundedNum::new(Num::ZERO),
                t: rng.gen(),
            }
        });

        let in_notes: Vec<_> = self.note_id.iter().map(|&i| self.items[i].1.clone()).collect();
        let in_notes: Vec<_> = in_notes.clone().into_iter().chain(owned_zero_notes).take(constants::IN).collect();

        let account_hash = {
            if self.hashes[0].contains(&self.items[self.account_id].0.hash_old(params)) {
                self.items[self.account_id].0.hash_old(params)
            } else {
                self.items[self.account_id].0.hash(params)
            }
        };

        let mut input_hashes = vec![account_hash];
        for note in in_notes.iter() {
            input_hashes.push(note.hash(params));
        }

        let mut out_notes = vec![];
        if let Some(note) = out_note {
            out_notes.push(note);
        }
        let out_notes:Vec<_> = out_notes.into_iter().chain((0..).map(|_| zero_note)).take(constants::OUT).collect();
        let out_hashes:Vec<_> = std::iter::once(out_account.hash(params)).chain(out_notes.iter().map(|n| n.hash(params))).collect();
        let out_commit = out_commitment_hash(&out_hashes, params);
        let tx_hash = tx_hash(&input_hashes, out_commit, params);
        let (eddsa_s,eddsa_r) = tx_sign(self.sigma, tx_hash, params);


        let delta = make_delta::<P::Fr>(delta_value, Num::ZERO, Num::from(index as u32), Num::ZERO);
        
        let p = TransferPub::<P::Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,
            current_day,
            daily_limit
        };

        let tx = Tx {
            input: (self.items[self.account_id].0.clone(), in_notes.into_iter().collect()),
            output: (out_account, out_notes.iter().cloned().collect() )
        };
        
        let s = TransferSec::<P::Fr> {
            tx,
            in_proof: (
                self.merkle_proof(self.account_id*2),
                self.note_id.iter().map(|&i| self.merkle_proof(i*2+1) )
                    .chain((0..).map(|_| self.zero_proof()))
                    .take(constants::IN).collect()
            ),
            eddsa_s:eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a:a.x
        };

        self.items.push((out_account, out_note.or(Some(Note::sample(rng, params))).unwrap()));
        self.note_id = vec![];
        if out_note.is_some() {
            self.note_id.push(self.items.len() - 1 as usize);
        }
        self.account_id = self.items.len() - 1 as usize;

        let mut hashes = vec![];
        {
            let mut t = vec![];
            for j in 0..self.items.len() {
                let (a, n) = self.items[j].clone();
                t.push(a.hash(params));
                t.push(n.hash(params));
            }
            if t.len() & 1 == 1 {
                t.push(self.default_hashes[0]);
            }
            hashes.push(t);
        }

        for i in 0..constants::HEIGHT {
            let mut t = vec![];
            for j in 0..hashes[i].len()>>1 {
                t.push(poseidon([hashes[i][2*j],hashes[i][2*j+1]].as_ref(), params.compress()));
            }
            if t.len() & 1 == 1 {
                t.push(self.default_hashes[i+1]);
            }
            hashes.push(t);
        }
        self.hashes = hashes;

        (p, s)
    }

    fn cell(&self, i:usize, j:usize) -> Num<P::Fr> {
        if self.hashes[i].len() <= j {
            self.default_hashes[i]
        } else {
            self.hashes[i][j]
        }
    }

    fn merkle_proof(&self, id:usize) -> MerkleProof<P::Fr, { constants::HEIGHT }> {
        let sibling = (0..constants::HEIGHT).map(|i| self.cell(i, (id>>i)^1)).collect();
        let path =  (0..constants::HEIGHT).map(|i| (id>>i)&1==1).collect();
        MerkleProof {sibling, path}
    }

    fn root(&self) -> Num<P::Fr> {
        return self.cell(constants::HEIGHT, 0)
    }

    fn zero_proof(&self) -> MerkleProof<P::Fr, { constants::HEIGHT }> {
        MerkleProof {
            sibling: (0..constants::HEIGHT).map(|_| Num::ZERO).collect(),
            path: (0..constants::HEIGHT).map(|_| false).collect(),
        }
    }

}
