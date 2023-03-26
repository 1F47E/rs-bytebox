use std::env;
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const NAME: &'static str = env!("CARGO_PKG_NAME");
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
}
