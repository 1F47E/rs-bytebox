use hkdf::Hkdf;
use sha2::Sha256;
use std::env;
use std::fs::File;
use std::io::Read;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = env!("CARGO_PKG_NAME");
fn main() {
    // get input from user
    let file_key = env::args().nth(1);
    let file_to_encrypt = env::args().nth(2);
    // chek if we have full user input
    if file_key.is_none() || file_to_encrypt.is_none() {
        println!("{} v{}\n\n", NAME, VERSION);
        println!("Usage: ./{NAME} <file_key> <file_to_encrypt>");
        return;
    }
    // unwrap user input
    let file_key = file_key.unwrap();
    let file_to_encrypt = file_to_encrypt.unwrap();
    println!("File key: {}", file_key);
    println!("File to encrypt: {}", file_to_encrypt);
    // read files
    let key = read_file(&file_key);
    println!("key file is {} bytes", key.len());
    let salt = b"some_salt";
    let password = derive_key(&key, salt, 32);
    let password_hex = hex::encode(password);
    println!("aes key for the file is {}", password_hex);
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
