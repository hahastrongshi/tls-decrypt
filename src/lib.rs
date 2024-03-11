pub mod decrypt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}


#[cfg(test)]
mod tests {
    use crate::decrypt::Decryptor;
    use super::*;


    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn gcm_128_sha256() {
        let client_write_iv_str = b"018ad16e";
        let client_write_key_str = b"7dc3cebbcfdd17dce17bf30dbb6cba83";

        let client_write_iv = hex::decode(client_write_iv_str).unwrap();
        let client_write_key = hex::decode(client_write_key_str).unwrap();

        let encode_data_str = "0000000000000001af0cf892a0a55bfc2c0256045a9a543d86211cfe885d08195c205b0db50c07f94af7c10d38f18977607c62d231324c3a157ac91a71e64ea48c31f2967906d9e38ab1c210c5115f47f4d94341f46f5c6a928ba155d449bbc3a8c7efc2175773da699860a6d5df14b20a3afabb998b0d8f57358134ecac34";
        let encode_data = match hex::decode(encode_data_str) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("解码时出错: {}", e);
                return;
            }
        };

        let gcm_128_sha256_decryptor = decrypt::AesGCM128Sha256Decryptor::new(client_write_key.clone(), client_write_iv.clone());
        let decrypt_data = gcm_128_sha256_decryptor.decrypt(&*encode_data.clone());
        println!("解密后的数据: {:?}", decrypt_data);

        let newline = b"\r\n";
        // 将 decrypt_data 按照 newline 进行切割
        let mut result = Vec::new();
        let mut start = 0;
        for (i, &item) in decrypt_data.iter().enumerate() {
            if item == newline[0] {
                if decrypt_data[i + 1] == newline[1] {
                    result.push(&decrypt_data[start..i]);
                    // 将 截取 的数据转换为 utf8 格式输出
                    let s = std::str::from_utf8(&decrypt_data[start..i]).unwrap();
                    println!("s: {}", s);
                    start = i + 2;
                }
            }
        }
    }
}
