use openssl::symm::{Cipher, Crypter, Mode};
use ring::aead;

pub trait Decryptor {
    // the return value maybe change to another type
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub struct AesCbc128Sha256Decryptor {
    key: Vec<u8>,
    cipher: Cipher,
}

impl AesCbc128Sha256Decryptor {
    pub fn new(key: Vec<u8>, _iv: Vec<u8>) -> Self {
        let cipher = Cipher::aes_128_cbc();
        AesCbc128Sha256Decryptor { key, cipher }
    }
}

impl Decryptor for AesCbc128Sha256Decryptor {
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
    less_safe_key: aead::LessSafeKey,
}

impl AesGCM128Sha256Decryptor {
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        // 将密钥转换为 `ring` 库的密钥类型
        let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap();

        // 将 `UnboundKey` 转换为 `LessSafeKey`
        let less_safe_key = aead::LessSafeKey::new(unbound_key);
        AesGCM128Sha256Decryptor { key, iv, less_safe_key }
    }
}

impl Decryptor for AesGCM128Sha256Decryptor {
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {

        let nonce_len = 8;
        // 从 encrypted_data 中提取 nonce、
        // 在 nonce 前面添加 1, 138, 209, 110
        let nonce_new = &data[..nonce_len];
        let nonce = [ &self.iv, nonce_new].concat();

        // 将 Nonce 转换为 `ring` 库的 Nonce 类型
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce).unwrap();

        let mut encrypted_data = Vec::from(&data[nonce_len..]);

        let additional_data = [0, 0, 0, 0, 0, 0, 0, 1, 17, 3, 3];

        // 将 additional_data 扩展为包含数据长度的信息
        let mut final_additional_data = Vec::from(additional_data);

        let tag_size = aead::AES_128_GCM.tag_len();
        let data_len = encrypted_data.len() - tag_size;
        final_additional_data.push((data_len >> 8) as u8);
        final_additional_data.push((data_len & 0xff) as u8);

        // 解密数据
        let decrypted_data = self.less_safe_key.open_in_place(nonce, aead::Aad::from(final_additional_data), &mut encrypted_data).unwrap();

        // 返回解密结果
        decrypted_data.to_vec()
    }
}