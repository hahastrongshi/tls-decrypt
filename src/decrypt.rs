use openssl::symm::{Cipher, Crypter, Mode};
use ring::aead;
use std::fmt;


pub trait Decryptor: fmt::Debug {
    // the return value maybe change to another type
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
    fn block_size(&self) -> usize;
}

pub struct AesCbc128Sha256Decryptor {
    key: Vec<u8>,
    cipher: Cipher,
}

impl fmt::Debug for AesCbc128Sha256Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AesCbc128Sha256Decryptor")
            .field("key", &self.key)
            .field("cipher", &"Cipher Omitted")
            .finish()
    }
}

impl AesCbc128Sha256Decryptor {
    pub fn new(key: Vec<u8>, _iv: Vec<u8>) -> Self {
        let cipher = Cipher::aes_128_cbc();
        AesCbc128Sha256Decryptor { key, cipher }
    }
}

impl Decryptor for AesCbc128Sha256Decryptor {
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        //let cipher = Cipher::aes_128_cbc();

        let bingding = data[0..self.cipher.block_size()].to_vec();
        let iv = bingding.as_ref();
        let data = &data[self.cipher.block_size()..];
        let mut decrypter = Crypter::new(self.cipher, Mode::Decrypt, &*self.key, Some(iv)).unwrap();

        let mut decrypted_data = vec![0; data.len() + self.cipher.block_size()];
        let mut count = decrypter.update(data, &mut decrypted_data).unwrap();

        count += decrypter.finalize(&mut decrypted_data[count..]).unwrap();
        decrypted_data.truncate(count);

        return decrypted_data;
    }
}


pub struct AesGCM128Sha256Decryptor {
    key: Vec<u8>,
    iv: Vec<u8>,
    // less_safe_key: aead::LessSafeKey,
    cipher: Cipher,
    tag_size: usize,
}

impl fmt::Debug for AesGCM128Sha256Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AesGCM128Sha256Decryptor")
            .field("key", &self.key)
            .field("cipher", &"Cipher Omitted")
            .finish()
    }
}

impl AesGCM128Sha256Decryptor {
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        let cipher = Cipher::aes_128_gcm();
        AesGCM128Sha256Decryptor { key, iv, cipher, tag_size: 16}
    }
}

impl Decryptor for AesGCM128Sha256Decryptor {
    fn block_size(&self) -> usize {
        8
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {

        let nonce_len = 8;
        // 从 encrypted_data 中提取 nonce、
        // 在 nonce 前面添加 1, 138, 209, 110
        let nonce_new = &data[..nonce_len];
        let nonce = [ &self.iv, nonce_new].concat();

        let mut c = Crypter::new(self.cipher, Mode::Decrypt, &*self.key, Some(&*nonce)).unwrap();

        let encrypted_data = Vec::from(&data[nonce_len..]);

        let additional_data = [0, 0, 0, 0, 0, 0, 0, 1, 17, 3, 3];

        // 将 additional_data 扩展为包含数据长度的信息
        let mut final_additional_data = Vec::from(additional_data);


        let data_len = encrypted_data.len() - self.tag_size;
        final_additional_data.push((data_len >> 8) as u8);
        final_additional_data.push((data_len & 0xff) as u8);

        let mut out = vec![0; encrypted_data.len() + self.cipher.block_size()];
        // 解密数据
        c.aad_update(&*final_additional_data).unwrap();
        let count = c.update(&*encrypted_data, &mut out).unwrap();
        out.truncate(count - self.tag_size);

        // 返回解密结果
        out
    }
}