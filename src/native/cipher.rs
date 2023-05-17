use crate::{
    fawkes_crypto::{
        ff_uint::{Num, seedbox::{SeedboxChaCha20, SeedBox, SeedBoxGen}},
        borsh::{BorshSerialize, BorshDeserialize},
        native::ecc::{EdwardsPoint},

    },
    native::{
        account::Account,
        note::Note,
        params::PoolParams,
        key::{derive_key_a, derive_key_p_d}
    },
    constants::{self, SHARED_SECRETS_HEAPLESS_SIZE, ACCOUNT_HEAPLESS_SIZE, NOTE_HEAPLESS_SIZE}
};

use super::symmetric::{encrypt_chacha_constant_nonce, keccak256, decrypt_chacha_constant_nonce, Buffer, encrypt_xchacha, decrypt_xchacha};

#[derive(Debug)]
pub struct UnsupportedMemoVesion;

/// The version of the memo
pub enum Version {
    /// The original version of the memo
    Original,
    /// The version of the memo with the delegated deposits related data
    DelegatedDeposit,
    /// The version of the memo without ECDH during shared secrets encryption
    SymmetricEncryption
}

impl Version {
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Original => 0x0000,
            Self::DelegatedDeposit => 0x0100,
            Self::SymmetricEncryption => 0x0001,
        }
    }

    pub fn from_u16(version: u16) -> Result<Version, UnsupportedMemoVesion> {
        match version {
            0x0000 => Ok(Self::Original),
            0x0100 => Ok(Self::DelegatedDeposit),
            0x0001 => Ok(Self::SymmetricEncryption),
            _ => Err(UnsupportedMemoVesion),
        }
    }
}

pub fn encrypt<P: PoolParams>(
    entropy: &[u8],
    kappa: &[u8],
    account: Account<P::Fr>,
    note: &[Note<P::Fr>],
    params:&P
) -> Vec<u8> {
    let nozero_notes_num = note.len();
    let nozero_items_num = nozero_notes_num+1;

    let mut sb = SeedboxChaCha20::new_with_salt(entropy);

    let account_data = {
        let mut account_key = [0u8;constants::U256_SIZE];
        sb.fill_bytes(&mut account_key);
        let account_ciphertext = encrypt_chacha_constant_nonce(&account_key, &account.try_to_vec().unwrap());
        (account_key, account_ciphertext)
    };


    let notes_data = note.iter().map(|e|{
        let a:Num<P::Fs> = sb.gen();
        let p_d = EdwardsPoint::subgroup_decompress(e.p_d, params.jubjub()).unwrap();
        let ecdh =  p_d.mul(a, params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let ciphertext = encrypt_chacha_constant_nonce(&key, &e.try_to_vec().unwrap());
        let a_pub = derive_key_p_d(e.d.to_num(), a, params); 
        (a_pub.x, key, ciphertext)

    }).collect::<Vec<_>>();

    let shared_secret_data = {
        let mut nonce = [0; constants::XCHACHA20_POLY1305_NONCE_SIZE];
        sb.fill_bytes(&mut nonce);
        let text:Vec<u8> = core::iter::once(&account_data.0[..]).chain(notes_data.iter().map(|e| &e.1[..])).collect::<Vec<_>>().concat();
        let ciphertext = encrypt_xchacha(kappa, &nonce, &text);
        (nonce, ciphertext)
    };

    let mut res = vec![];

    (nozero_items_num as u16).serialize(&mut res).unwrap();
    (Version::SymmetricEncryption.to_u16()).serialize(&mut res).unwrap();
    account.hash(params).serialize(&mut res).unwrap();

    for e in note.iter() {
        e.hash(params).serialize(&mut res).unwrap();
    }
    shared_secret_data.0.serialize(&mut res).unwrap();
    res.extend(&shared_secret_data.1);

    res.extend(&account_data.1);

    notes_data.iter().for_each(|nd|{
        nd.0.serialize(&mut res).unwrap();
        res.extend(&nd.2);
    });

    res
}

fn buf_take<'a>(memo: &mut &'a[u8], size:usize) -> Option<&'a[u8]> {
    if memo.len() < size {
        None
    } else {
        let res = &memo[0..size];
        *memo = &memo[size..];
        Some(res)
    }
}

pub fn decrypt_out<P: PoolParams>(eta: Num<P::Fr>, kappa: &[u8; 32], mut memo: &[u8], params: &P)->Option<(Account<P::Fr>, Vec<Note<P::Fr>>)> {
    let num_size = constants::num_size_bits::<P::Fr>()/8;
    let account_size = constants::account_size_bits::<P::Fr>()/8;
    let note_size = constants::note_size_bits::<P::Fr>()/8;


    let nozero_items_num = u16::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let version = Version::from_u16(u16::deserialize(&mut memo).ok()?).ok()?;

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * constants::U256_SIZE + constants::POLY_1305_TAG_SIZE;

    let account_hash = Num::deserialize(&mut memo).ok()?;
    let note_hashes = buf_take(&mut memo, nozero_notes_num * num_size)?;

    let shared_secret_text = decrypt_shared_secrets::<P, SHARED_SECRETS_HEAPLESS_SIZE>(version, eta, kappa, &mut memo, shared_secret_ciphertext_size, params)?;

    let mut shared_secret_text_ptr = shared_secret_text.as_slice();

    let account_key= <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr).ok()?;
    let note_key = (0..nozero_notes_num).map(|_| <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr)).collect::<Result<Vec<_>,_>>().ok()?;

    let account_ciphertext = buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;
    let account = decrypt_account(&account_key, account_ciphertext, account_hash, params)?;

    let note = (0..nozero_notes_num).map(|i| {
        buf_take(&mut memo, num_size)?;
        let note_hash = {
            let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
            Num::deserialize(note_hash).ok()?
        };

        let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;

        decrypt_note(&note_key[i], ciphertext, note_hash, params)
    }).collect::<Option<Vec<_>>>()?;
    
    Some((account, note))
}

fn decrypt_shared_secrets<P: PoolParams, const N: usize>(version: Version, eta: Num<P::Fr>, kappa: &[u8; 32], buf: &mut &[u8], size: usize, params: &P) -> Option<Buffer<u8, N>> {
    match version {
        Version::Original => {
            let a_p = EdwardsPoint::subgroup_decompress(Num::deserialize(buf).ok()?, params.jubjub())?;
            let ecdh = a_p.mul(eta.to_other_reduced(), params.jubjub());
            let key = {
                let mut x: [u8; 32] = [0; 32];
                ecdh.x.serialize(&mut &mut x[..]).unwrap();
                keccak256(&x)
            };
            let ciphertext = buf_take(buf, size)?;
            Some(decrypt_chacha_constant_nonce::<N>(&key, ciphertext)?)
        },
        Version::SymmetricEncryption => {
            let nonce = &buf_take(buf, constants::XCHACHA20_POLY1305_NONCE_SIZE)?;
            let ciphertext = buf_take(buf, size)?;
            Some(decrypt_xchacha::<N>(kappa, nonce, ciphertext)?)
        },
        Version::DelegatedDeposit => None
    }
}

fn shared_secrets_size(version: Version, num_size: usize, items_num: usize) -> Option<usize> {
    let shared_secret_ciphertext_size = items_num * constants::U256_SIZE + constants::POLY_1305_TAG_SIZE;
    match version {
        Version::Original => {
            let ecdh_size = num_size;
            Some(ecdh_size + shared_secret_ciphertext_size)
        },
        Version::SymmetricEncryption => {
            let nonce_size = constants::XCHACHA20_POLY1305_NONCE_SIZE;
            Some(nonce_size + shared_secret_ciphertext_size)
        },
        Version::DelegatedDeposit => None
    }
}

fn _decrypt_in<P: PoolParams>(eta:Num<P::Fr>, mut memo:&[u8], params:&P)->Option<Vec<Option<Note<P::Fr>>>> {
    let num_size = constants::num_size_bits::<P::Fr>()/8;
    let account_size = constants::account_size_bits::<P::Fr>()/8;
    let note_size = constants::note_size_bits::<P::Fr>()/8;


    let nozero_items_num = u16::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let version = Version::from_u16(u16::deserialize(&mut memo).ok()?).ok()?;

    let nozero_notes_num = nozero_items_num - 1;

    buf_take(&mut memo, num_size)?;
    let note_hashes = buf_take(&mut memo, nozero_notes_num * num_size)?;

    let shared_secrets_size = shared_secrets_size(version, num_size, nozero_items_num)?;
    buf_take(&mut memo, shared_secrets_size)?;
    buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;


    let note = (0..nozero_notes_num).map(|i| {
        let a_pub = EdwardsPoint::subgroup_decompress(Num::deserialize(&mut memo).ok()?, params.jubjub())?;
        let ecdh = a_pub.mul(eta.to_other_reduced(), params.jubjub());
        
        let key = {
            let mut x: [u8; 32] = [0; 32];
            ecdh.x.serialize(&mut &mut x[..]).unwrap();
            keccak256(&x)
        };

        let note_hash = {
            let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
            Num::deserialize(note_hash).ok()?
        };
        
        let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;

        decrypt_note(&key, ciphertext, note_hash, params)
    }).collect::<Vec<Option<_>>>();

    Some(note)
}

pub fn decrypt_in<P: PoolParams>(eta:Num<P::Fr>, memo:&[u8], params:&P)->Vec<Option<Note<P::Fr>>> {
    if let Some(res) = _decrypt_in(eta, memo, params) {
        res
    } else {
        vec![]
    }
}

/// get encrypted memo chunks with associated decryption keys (chunk: account or note)
/// returns vector of tupple (index, chunk, key)
/// indexes are zero-based and enumerated within current memo
pub fn symcipher_decryption_keys<P: PoolParams>(eta: Num<P::Fr>, kappa: &[u8; 32], mut memo:&[u8], params:&P) -> Option<Vec<(u64, Vec<u8>, Vec<u8>)>> {
    let num_size = constants::num_size_bits::<P::Fr>()/8;
    let account_size = constants::account_size_bits::<P::Fr>()/8;
    let note_size = constants::note_size_bits::<P::Fr>()/8;

    let nozero_items_num = u16::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let version = Version::from_u16(u16::deserialize(&mut memo).ok()?).ok()?;

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * constants::U256_SIZE + constants::POLY_1305_TAG_SIZE;

    let account_hash = Num::deserialize(&mut memo).ok()?;
    let note_hashes = buf_take(&mut memo, nozero_notes_num * num_size)?;

    let shared_secret_text = decrypt_shared_secrets::<P, SHARED_SECRETS_HEAPLESS_SIZE>(version, eta, kappa, &mut memo, shared_secret_ciphertext_size, params);

    if let Some(shared_secret_text) = shared_secret_text {
        // here is a our transaction, we can restore account and all notes
        let mut shared_secret_text_ptr = shared_secret_text.as_slice();

        let account_key= <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr).ok()?;
        let note_key = (0..nozero_notes_num).map(|_| <[u8;constants::U256_SIZE]>::deserialize(&mut shared_secret_text_ptr)).collect::<Result<Vec<_>,_>>().ok()?;

        let account_ciphertext = buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;
        let _ = decrypt_account(&account_key, account_ciphertext, account_hash, params)?;

        let account_tuple = (0 as u64, account_ciphertext.to_vec(), account_key.to_vec());
        let result = Some(account_tuple)
            .into_iter()
            .chain(
                (0..nozero_notes_num).filter_map(|i| {
                buf_take(&mut memo, num_size)?;

                let note_hash = {
                    let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
                    Num::deserialize(note_hash).ok()?
                };

                let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;
                match decrypt_note(&note_key[i], ciphertext, note_hash, params) {
                    Some(_) => Some((i as u64 + 1, ciphertext.to_vec(), note_key[i].to_vec())),
                    _ => None,
                }
            })
        ).collect::<Vec<_>>();
        
        Some(result)
    } else {
        // search for incoming notes
        buf_take(&mut memo, account_size+constants::POLY_1305_TAG_SIZE)?;   // skip account
        let notes = (0..nozero_notes_num).filter_map(|i| {
            let a_pub = EdwardsPoint::subgroup_decompress(Num::deserialize(&mut memo).ok()?, params.jubjub())?;
            let ecdh = a_pub.mul(eta.to_other_reduced(), params.jubjub());
            
            let key = {
                let mut x: [u8; 32] = [0; 32];
                ecdh.x.serialize(&mut &mut x[..]).unwrap();
                keccak256(&x)
            };
    
            let note_hash = {
                let note_hash = &mut &note_hashes[i * num_size..(i + 1) * num_size];
                Num::deserialize(note_hash).ok()?
            };

            let ciphertext = buf_take(&mut memo, note_size+constants::POLY_1305_TAG_SIZE)?;
            match decrypt_note(&key, ciphertext, note_hash, params) {
                Some(_) => Some((i as u64 + 1, ciphertext.to_vec(), key.to_vec())),
                _ => None,
            }
        })
        .collect();

        Some(notes)
    }
}

pub fn decrypt_account<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], hash: Num<P::Fr>, params: &P) -> Option<Account<P::Fr>> {
    match decrypt_account_no_validate(symkey, ciphertext, params) {
        Some(acc) if acc.hash(params) == hash => Some(acc),
        _ => None,
    }
}

pub fn decrypt_account_no_validate<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], _: &P) -> Option<Account<P::Fr>> {
    let plain = decrypt_chacha_constant_nonce::<ACCOUNT_HEAPLESS_SIZE>(&symkey, ciphertext)?;
    Account::try_from_slice(plain.as_slice()).ok()
}

pub fn decrypt_note<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], hash: Num<P::Fr>, params: &P) -> Option<Note<P::Fr>> {
    match decrypt_note_no_validate(symkey, ciphertext, params) {
        Some(note) if note.hash(params) == hash => Some(note),
        _ => None,
    }
}

pub fn decrypt_note_no_validate<P: PoolParams>(symkey: &[u8], ciphertext: &[u8], _: &P) -> Option<Note<P::Fr>> {
    let plain = decrypt_chacha_constant_nonce::<NOTE_HEAPLESS_SIZE>(&symkey, ciphertext)?;
    Note::try_from_slice(plain.as_slice()).ok()
}

/// Deprecated
fn _encrypt_old<P: PoolParams>(
    entropy: &[u8],
    eta:Num<P::Fr>,
    account: Account<P::Fr>,
    note: &[Note<P::Fr>],
    params:&P
) -> Vec<u8> {
    let nozero_notes_num = note.len();
    let nozero_items_num = nozero_notes_num+1;

    let mut sb = SeedboxChaCha20::new_with_salt(entropy);

    let account_data = {
        let mut account_key = [0u8;constants::U256_SIZE];
        sb.fill_bytes(&mut account_key);
        let account_ciphertext = encrypt_chacha_constant_nonce(&account_key, &account.try_to_vec().unwrap());
        (account_key, account_ciphertext)
    };
    
    let notes_data = note.iter().map(|e|{
        let a:Num<P::Fs> = sb.gen();
        let p_d = EdwardsPoint::subgroup_decompress(e.p_d, params.jubjub()).unwrap();
        let ecdh =  p_d.mul(a, params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let ciphertext = encrypt_chacha_constant_nonce(&key, &e.try_to_vec().unwrap());
        let a_pub = derive_key_p_d(e.d.to_num(), a, params); 
        (a_pub.x, key, ciphertext)
        
    }).collect::<Vec<_>>();

    let shared_secret_data = {
        let a_p_pub = derive_key_a(sb.gen(), params);
        let ecdh = a_p_pub.mul(eta.to_other_reduced(), params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let text:Vec<u8> = core::iter::once(&account_data.0[..]).chain(notes_data.iter().map(|e| &e.1[..])).collect::<Vec<_>>().concat();
        let ciphertext = encrypt_chacha_constant_nonce(&key, &text);
        (a_p_pub.x, ciphertext)
    };

    let mut res = vec![];

    (nozero_items_num as u32).serialize(&mut res).unwrap();
    account.hash(params).serialize(&mut res).unwrap();

    for e in note.iter() {
        e.hash(params).serialize(&mut res).unwrap();
    }
    shared_secret_data.0.serialize(&mut res).unwrap();
    res.extend(&shared_secret_data.1);

    res.extend(&account_data.1);

    notes_data.iter().for_each(|nd|{
        nd.0.serialize(&mut res).unwrap();
        res.extend(&nd.2);
    });

    res
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use crate::constants::XCHACHA20_POLY1305_NONCE_SIZE;
    use crate::native::cipher::{symcipher_decryption_keys, decrypt_account, decrypt_note, encrypt};
    use crate::native::note::Note;
    use crate::native::symmetric::{encrypt_chacha_constant_nonce, decrypt_chacha_constant_nonce, encrypt_xchacha, decrypt_xchacha};
    use crate::{POOL_PARAMS, native::boundednum::BoundedNum};
    use crate::native::account::Account;
    use fawkes_crypto::ff_uint::Num;
    use fawkes_crypto::{rand::Rng, engines::bn256::Fr};
    use fawkes_crypto::rand::rngs::OsRng;
    use crate::native::key::{derive_key_a, derive_key_eta, derive_key_p_d, derive_key_kappa};

    use super::{_encrypt_old, decrypt_out, decrypt_in, Version};

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(100)]
    #[test_case(128)]
    #[test_case(1024)]
    fn test_chacha_constant_nonce(buf_len: usize) {
        let mut rng = OsRng::default();

        let key: [u8; 32] = rng.gen();
        let plaintext: Vec<u8> = (0..buf_len).map(|_| { rng.gen() }).collect();
        let ciphertext = encrypt_chacha_constant_nonce(&key, &plaintext.as_slice());
        let decrypted = decrypt_chacha_constant_nonce::<0>(&key, &ciphertext.as_slice()).unwrap();

        assert_eq!(plaintext.len(), decrypted.as_slice().len());
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(100)]
    #[test_case(128)]
    #[test_case(1024)]
    fn test_xchacha(buf_len: usize) {
        let mut rng = OsRng::default();

        let key: [u8; 32] = rng.gen();
        let nonce: [u8; XCHACHA20_POLY1305_NONCE_SIZE] = rng.gen();
        let plaintext: Vec<u8> = (0..buf_len).map(|_| { rng.gen() }).collect();
        let ciphertext = encrypt_xchacha(&key, &nonce, &plaintext.as_slice());
        let decrypted = decrypt_xchacha::<0>(&key, &nonce, &ciphertext.as_slice()).unwrap();

        assert_eq!(plaintext.len(), decrypted.as_slice().len());
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test_case(0, 0.0, Version::Original)]
    #[test_case(1, 0.0, Version::Original)]
    #[test_case(1, 1.0, Version::Original)]
    #[test_case(5, 0.8, Version::Original)]
    #[test_case(15, 0.0, Version::Original)]
    #[test_case(15, 1.0, Version::Original)]
    #[test_case(20, 0.5, Version::Original)]
    #[test_case(30, 0.7, Version::Original)]
    #[test_case(42, 0.5, Version::Original)]
    #[test_case(0, 0.0, Version::SymmetricEncryption)]
    #[test_case(1, 0.0, Version::SymmetricEncryption)]
    #[test_case(1, 1.0, Version::SymmetricEncryption)]
    #[test_case(5, 0.8, Version::SymmetricEncryption)]
    #[test_case(15, 0.0, Version::SymmetricEncryption)]
    #[test_case(15, 1.0, Version::SymmetricEncryption)]
    #[test_case(20, 0.5, Version::SymmetricEncryption)]
    #[test_case(30, 0.7, Version::SymmetricEncryption)]
    #[test_case(42, 0.5, Version::SymmetricEncryption)]
    fn test_decrypt_in_out(notes_count: u32, note_probability: f64, version: Version) {
        let params = &POOL_PARAMS.clone();
        let mut rng = OsRng::default();

        // sender eta
        let eta1 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        // sender kappa
        let kappa1 = derive_key_kappa(eta1);

        // receciver eta
        let eta2 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);

        // output account
        let mut account: Account<Fr> = Account::sample(&mut rng, params);
        account.b = BoundedNum::new(Num::from(10000000000 as u64));
        account.e = BoundedNum::new(Num::from(12345 as u64));
        account.i = BoundedNum::new(Num::from(128 as u32));
        account.p_d = derive_key_p_d(account.d.to_num(), eta1, params).x;

        // output notes
        let mut dst_notes_num: usize = 0;
        let notes: Vec<Note<Fr>> = (0..notes_count as u64).map(|_| {
            let mut a_note = Note::sample(&mut rng, params);
            a_note.b = BoundedNum::new(Num::from(500000000 as u64));
            if rng.gen_bool(note_probability) {
                // a few notes to the receiver
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta2, params).x;
                dst_notes_num += 1;
            } else {
                // other notes are loopback
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta1, params).x;
            }
            a_note
        }).collect();

        // encrypt account and notes with the sender key
        let entropy: [u8; 32] = rng.gen();
        let mut encrypted = match version {
            Version::Original => _encrypt_old(&entropy, eta1, account, notes.as_slice(), params),
            Version::SymmetricEncryption => encrypt(&entropy, &kappa1, account, notes.as_slice(), params),
            Version::DelegatedDeposit => unreachable!()
        };  

        // let's decrypt the memo from the receiver side and check the result
        let decrypted_in = decrypt_in(eta2, encrypted.as_mut_slice(), params);
        assert_eq!(decrypted_in.len(), notes.len());
        let in_notes: Vec<_> = decrypted_in
                .into_iter()
                .enumerate()
                .filter_map(|(i, note)| {
                    match note {
                        Some(note) => { //if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x => {
                            assert_eq!(&note, notes.get(i).unwrap());
                            Some(note)
                        }
                        _ => None,
                    }
                })
                .collect();
        assert_eq!(in_notes.len(), dst_notes_num);
        
        // decrypt the memo from the sender side and check the result
        let decrypted_out = decrypt_out(eta1, &kappa1, encrypted.as_mut_slice(), params);
        let decrypted_acc = decrypted_out.as_ref().unwrap().0;
        let decrypted_notes = &decrypted_out.as_ref().unwrap().1;
        assert_eq!(decrypted_acc, account);
        assert_eq!(decrypted_notes.len(), notes.len());
        (0..notes.len()).for_each(|i: usize| {
            let src = notes.get(i).unwrap();
            let recovered = decrypted_notes.get(i).unwrap();
            assert_eq!(src, recovered);
        });
    }

    #[test_case(0, 0.0, Version::Original)]
    #[test_case(1, 0.0, Version::Original)]
    #[test_case(1, 1.0, Version::Original)]
    #[test_case(3, 0.5, Version::Original)]
    #[test_case(10, 0.5, Version::Original)]
    #[test_case(15, 0.0, Version::Original)]
    #[test_case(30, 1.0, Version::Original)]
    #[test_case(42, 0.5, Version::Original)]
    #[test_case(0, 0.0, Version::SymmetricEncryption)]
    #[test_case(1, 0.0, Version::SymmetricEncryption)]
    #[test_case(1, 1.0, Version::SymmetricEncryption)]
    #[test_case(3, 0.5, Version::SymmetricEncryption)]
    #[test_case(10, 0.5, Version::SymmetricEncryption)]
    #[test_case(15, 0.0, Version::SymmetricEncryption)]
    #[test_case(30, 1.0, Version::SymmetricEncryption)]
    #[test_case(42, 0.5, Version::SymmetricEncryption)]
    fn test_compliance(notes_count: u32, note_probability: f64, version: Version) {
        let params = &POOL_PARAMS.clone();
        let mut rng = OsRng::default();

        // sender
        let eta1 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        let kappa1 = derive_key_kappa(eta1);
        // receiver
        let eta2 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        let kappa2 = derive_key_kappa(eta2);
        // third-party
        let eta3 = derive_key_eta(derive_key_a(rng.gen(), params).x, params);
        let kappa3 =  derive_key_kappa(eta3);

        // output account
        let mut account: Account<Fr> = Account::sample(&mut rng, params);
        account.b = BoundedNum::new(Num::from(10000000000 as u64));
        account.e = BoundedNum::new(Num::from(12345 as u64));
        account.i = BoundedNum::new(Num::from(128 as u32));
        account.p_d = derive_key_p_d(account.d.to_num(), eta1, params).x;

        // output notes
        let mut dst_notes_num: usize = 0;
        let notes: Vec<Note<Fr>> = (0..notes_count as u64).map(|_| {
            let mut a_note = Note::sample(&mut rng, params);
            a_note.b = BoundedNum::new(Num::from(500000000 as u64));
            if rng.gen_bool(note_probability) {
                // a few notes to the receiver
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta2, params).x;
                dst_notes_num += 1;
            } else {
                // other notes are loopback
                a_note.p_d = derive_key_p_d(a_note.d.to_num(), eta1, params).x;
            }
            a_note
        }).collect();

        // encrypt account and notes with the sender key
        let entropy: [u8; 32] = rng.gen();
        let encrypted = match version {
            Version::Original => _encrypt_old(&entropy, eta1, account, notes.as_slice(), params),
            Version::SymmetricEncryption => encrypt(&entropy, &kappa1, account, notes.as_slice(), params),
            Version::DelegatedDeposit => unreachable!()
        };  

        // trying to restore chunks and associated decryption keys from the sender side
        let sender_restored = symcipher_decryption_keys(eta1, &kappa1, encrypted.as_slice(), params).unwrap();
        assert!(sender_restored.len() == notes.len() + 1);
        sender_restored.iter().for_each(|(index, chunk, key)| {
            if *index == 0 {
                // decrypt account
                let decrypt_acc = decrypt_account(key.as_slice(), chunk.as_slice(), account.hash(params), params).unwrap();
                assert_eq!(decrypt_acc, account);
            } else {
                // decrypt note
                let orig_note = notes.get((index - 1) as usize).unwrap();
                let decrypt_note = decrypt_note(key.as_slice(), chunk.as_slice(), orig_note.hash(params), params).unwrap();
                assert_eq!(decrypt_note, *orig_note);
            }
        });

        // trying to restore chunks and associated decryption keys from the receiver side
        let receiver_restored = symcipher_decryption_keys(eta2, &kappa2, encrypted.as_slice(), params).unwrap();
        assert!(receiver_restored.len() == dst_notes_num);
        receiver_restored.iter().for_each(|(index, chunk, key)| {
            assert_ne!(*index, 0); // account shouldn't be decrypted on receiver side
            // decrypt note
            let orig_note = notes.get((index - 1) as usize).unwrap();
            let decrypt_note = decrypt_note(key.as_slice(), chunk.as_slice(), orig_note.hash(params), params).unwrap();
            assert_eq!(decrypt_note, *orig_note);
        });

        // trying to restore memo from the third-party actor
        let thirdparty_restored = symcipher_decryption_keys(eta3, &kappa3, encrypted.as_slice(), params).unwrap();
        assert_eq!(thirdparty_restored.len(), 0);
    }
}