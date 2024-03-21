use openssl::rsa::{Padding, Rsa};
use ring::{hmac};
use ring::hmac::Tag;

pub fn decrypt_premaster_secret(encrypted_premaster: Vec<u8>, private_key_pem: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 从PEM格式加载私钥
    let rsa = Rsa::private_key_from_pem(private_key_pem)?;

    // 解密premaster secret
    let mut decrypted_premaster = vec![0; rsa.size() as usize];
    let _ = rsa.private_decrypt(&*encrypted_premaster, &mut decrypted_premaster, Padding::PKCS1)?;

    // 移除解密后的premaster secret中的填充数据
    Ok(decrypted_premaster.into_iter().filter(|&x| x != 0).collect())
}

pub fn prf_raw(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let mut hmac_key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut current_a = sign(&hmac_key, &[label, seed]);

    let chunk_size = hmac_key.algorithm().digest_algorithm().output_len();
    for chunk in out.chunks_mut(chunk_size) {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let p_term = sign(&hmac_key,  &[current_a.as_ref(), label, seed]);
        chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

        // A(i+1) = HMAC_hash(secret, A(i))
        current_a = sign(&hmac_key, &[current_a.as_ref()])  ;
    }

}

fn sign(hmac_key: &hmac::Key, data: &[&[u8]]) -> Tag {
    let first = &[];
    let last = &[];
    let mut ctx = hmac::Context::with_key(hmac_key);
    ctx.update(first);
    for d in data {
        ctx.update(d);
    }
    ctx.update(last);
    ctx.sign()
}


pub fn derive_key_material(master_secret: &[u8], client_random: &[u8], server_random: &[u8], key_material_length: usize) -> Vec<u8> {
    let label = b"key expansion";

    let mut seed = Vec::new();
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let mut out = vec![0u8; key_material_length];

    prf_raw(master_secret, label.as_ref(), seed.as_ref(), &mut out);
    out
}

fn generate_master_secret(premaster_secret: &[u8], client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    let label = b"master secret";

    let mut seed = Vec::new();
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let mut master_secret = [0u8; 48];

    prf_raw(premaster_secret, label.as_ref(), seed.as_ref(), &mut master_secret);
    Vec::from(master_secret)
}