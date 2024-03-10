
use openssl::symm::{Cipher, Crypter, Mode};

pub trait Decryptor {
    // the return value maybe change to another type
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}


pub struct AesCbc128Sha256Decryptor {
    key: Vec<u8>,
    iv: Vec<u8>,
}


// todo 将加密算法独立出来，作为参数传进来，方便后续的统一处理
impl AesCbc128Sha256Decryptor {
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        AesCbc128Sha256Decryptor { key, iv }
    }
}

impl Decryptor for AesCbc128Sha256Decryptor {
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let cipher = Cipher::aes_128_cbc();

        let bingding = data[0..cipher.block_size()].to_vec();
        let iv= bingding.as_ref();
        let data = &data[cipher.block_size()..];
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &*self.key, Some(iv)).unwrap();

        let mut decrypted_data = vec![0; data.len() + cipher.block_size()];
        let mut count = decrypter.update(data, &mut decrypted_data).unwrap();

        count += decrypter.finalize(&mut decrypted_data[count..]).unwrap();
        decrypted_data.truncate(count);

        return decrypted_data
    }
}