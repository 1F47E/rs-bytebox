use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use generic_array::{typenum::U32, GenericArray};

use hkdf::Hkdf;
use sha2::Sha256;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = env!("CARGO_PKG_NAME");
// define enum with commands
enum Command {
    Encrypt,
    Decrypt,
}

fn main() {
    // get input from user
    let command_str = env::args().nth(1);
    let file_key = env::args().nth(2);
    let file_data = env::args().nth(3);

    let welcome_msg = format!("{NAME} v{VERSION}\n\nUsage: ./{NAME} <command> <file_key> <file_to_encrypt>\nCommands: encrypt | decrypt");
    // check command
    // convert command to enum
    let command_opt = match command_str.unwrap().as_str() {
        "encrypt" => Some(Command::Encrypt),
        "decrypt" => Some(Command::Decrypt),
        // panic
        _ => None,
    };
    let command = command_opt.unwrap();
    // chek if we have full user input
    if file_key.is_none() || file_data.is_none() {
        println!("{}", welcome_msg);
        return;
    }
    // unwrap user input
    let file_key = file_key.unwrap();
    let file_data = file_data.unwrap();
    println!("File key: {}", file_key);
    println!("File with data: {}", file_data);
    // read files
    let key = read_file(&file_key);
    println!("key file is {} bytes", key.len());
    let salt = b"some_salt";
    let key_bytes = derive_key(&key, salt, 32);
    // let password_hex = hex::encode(password);
    // println!("aes key for the file is {}", password_hex);
    // match command
    match command {
        Command::Encrypt => {
            // encrypt file
            let data = read_file(&file_data);
            println!("data file is {} bytes", data.len());
            let enc_data = encrypt(&data, &key_bytes).unwrap();
            file_write("enc.bin", &enc_data.to_vec());
            println!("encrypted file is enc.bin");
        }
        Command::Decrypt => {
            // decrypt file
            let data = read_file(&file_data);
            println!("data file is {} bytes", data.len());
            let dec_data = decrypt(&data, &key_bytes).unwrap();
            file_write("plain.txt", &dec_data.to_vec());
            println!("decrypted file is plain.txt");
        }
    }

    // if command == Command::Encrypt {
    //     // encrypt file
    //     let data = read_file(&file_data);
    //     println!("data file is {} bytes", data.len());
    //     let enc_data = encrypt(&data, &key_bytes).unwrap();
    //     file_write("enc.bin", &enc_data.to_vec());
    //     println!("encrypted file is enc.bin");
    // } else if command == Command::Decrypt {
    //     // decrypt file
    //     let data = read_file(&file_data);
    //     println!("data file is {} bytes", data.len());
    //     let dec_data = decrypt(&data, &key_bytes).unwrap();
    //     file_write("plain.txt", &dec_data.to_vec());
    //     println!("decrypted file is plain.txt");
    // }

    // DEBUG STUFF WIP
    // let key = Aes256Gcm::generate_key(&mut OsRng);
    // let cipher = Aes256Gcm::new(&key);
    // let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    // let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
    // let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    // // assert_eq!(&plaintext, b"plaintext message");
    // println!("ciphertext: {}", ciphertext);
    // let res = encrypt_decrypt_demo();

    // let res_vec = encrypt().unwrap();
    // let res_bytes = res_vec.as_slice();
    // file_write("enc.bin", &res_vec);
    // println!("encrypted file is enc.bin");
    //
    // // decrypt file
    // let bin = read_file("enc.bin");
    // let decryp_res = decrypt(bin).unwrap();

    // println!("decrypt res: {:?}", res);
    // file_write("plain.txt", &decryp_res.unwrap());
    // println!("decrypted file is plain.txt");
}

/// encrypt the bytes with bytes
fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    // let key = Aes256Gcm::generate_key(&mut OsRng);
    // let cipher = Aes256Gcm::new(&key);
    let gcm_key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(gcm_key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, data.as_ref())?;
    // convert to bec bytes
    let res = ciphertext.to_vec();
    Ok(res)
}

/// decrypt the bytes with bytes
fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    // create key from bytes
    // let slice = b"some 32-byte key for AES-256-GCM";
    let gcm_key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(gcm_key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let decoded_data = cipher.decrypt(nonce, data.as_ref())?;
    // convert bytes to string
    // let txt = String::from_utf8(plaintext.to_vec()).unwrap();
    // println!("plaintext string: {}", txt);
    // let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())?;
    let res = decoded_data.to_vec();
    Ok(res)
}

/// write bytes to file
fn file_write(filename: &str, data: &[u8]) {
    let mut file = File::create(filename).unwrap();
    file.write_all(data).unwrap();
}

/// read file and return it as a vector of bytes
fn read_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).unwrap();
    let mut buffer = Vec::new();
    // read the file to the buffer
    file.read_to_end(&mut buffer).unwrap();
    buffer
}

/// derive a key from a file bytes
fn derive_key(input: &[u8], salt: &[u8], output_key_len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
    let mut key = vec![0u8; output_key_len];
    hkdf.expand(&[], &mut key).expect("Error deriving key");
    key
}
