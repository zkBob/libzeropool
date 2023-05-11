use sha3::{Digest, Keccak256};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::AeadMutInPlace, XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::aead::heapless::Vec as HeaplessVec;

use crate::constants;

/// Wrapper for HeaplessVec (if buffer size is less or equals to N) or Vec otherwise
pub(crate) enum Buffer<T, const N: usize> {
    HeapBuffer(Vec<T>),
    HeaplessBuffer(HeaplessVec<T, N>)
}

impl<T, const N: usize> Buffer<T, N> {
    pub(crate) fn as_slice(&self) -> &[T] {
        match self {
            Self::HeapBuffer(vec) => vec.as_slice(),
            Self::HeaplessBuffer(heapless_vec) => heapless_vec.as_slice()
        }
    }
}

pub(crate) fn keccak256(data:&[u8])->[u8; constants::U256_SIZE] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut res = [0u8; constants::U256_SIZE];
    res.iter_mut().zip(hasher.finalize().into_iter()).for_each(|(l,r)| *l=r);
    res
}

/// Key stricly assumed to be unique for all messages. Using this function with multiple messages and one key is insecure!
pub(crate) fn encrypt_chacha_constant_nonce(key:&[u8], data:&[u8]) -> Vec<u8> {
    assert!(key.len() == constants::U256_SIZE);

    let nonce = Nonce::from_slice(&constants::ENCRYPTION_NONCE);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(nonce, data.as_ref()).unwrap()
}

/// Decrypts message in place if `ciphertext.len()` is less or equals to N, otherwise allocates memory in heap.
pub(crate) fn decrypt_chacha_constant_nonce<const N: usize>(key: &[u8], ciphertext: &[u8]) -> Option<Buffer<u8, N>> {
    assert!(key.len() == constants::U256_SIZE);

    let nonce = Nonce::from_slice(&constants::ENCRYPTION_NONCE);
    let mut cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    if ciphertext.len() <= N {
        let mut buffer = HeaplessVec::<u8, N>::from_slice(ciphertext).ok()?;
        cipher.decrypt_in_place(nonce, b"", &mut buffer).ok()?;
        Some(Buffer::HeaplessBuffer(buffer))
    } else {
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        Some(Buffer::HeapBuffer(plain))
    }
}

/// (key, nonce) pair stricly assumed to be unique for all messages. Using this function with multiple messages and one (key, nonce) pair is insecure!
pub(crate) fn encrypt_xchacha(key: &[u8], nonce: &[u8], data:&[u8]) -> Vec<u8> {
    assert!(key.len() == constants::U256_SIZE);
    assert!(nonce.len() == constants::XCHACHA20_POLY1305_NONCE_SIZE);

    let nonce = XNonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(nonce, data.as_ref()).unwrap()
}

/// Decrypts message in place if `ciphertext.len()` is less or equals to N, otherwise allocates memory in heap.
pub(crate) fn decrypt_xchacha<const N: usize>(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Option<Buffer<u8, N>> {
    assert!(key.len() == constants::U256_SIZE);
    assert!(nonce.len() == constants::XCHACHA20_POLY1305_NONCE_SIZE);

    let nonce = XNonce::from_slice(nonce);
    let mut cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    if ciphertext.len() <= N {
        let mut buffer = HeaplessVec::<u8, N>::from_slice(ciphertext).ok()?;
        cipher.decrypt_in_place(nonce, b"", &mut buffer).ok()?;
        Some(Buffer::HeaplessBuffer(buffer))
    } else {
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        Some(Buffer::HeapBuffer(plain))
    }
}