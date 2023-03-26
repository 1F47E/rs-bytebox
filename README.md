  ```
       _           _       _               
      | |         | |     | |              
      | |__  _   _| |_ ___| |__   _____  __
      | '_ \| | | | __/ _ \ '_ \ / _ \ \/ /
      | |_) | |_| | ||  __/ |_) | (_) >  < 
      |_.__/ \__, |\__\___|_.__/ \___/_/\_\
              __/ |                        
             |___/            
     
```

A command line tool written in Rust for encrypting and decrypting files

## What it's all about

To generate a strong 32-byte key from a user-provided file, Bytebox uses the scrypt key derivation function. Key derivation functions like [scrypt](https://godoc.org/golang.org/x/crypto/scrypt), PBKDF2, and bcrypt are specifically designed to make brute-force attacks more difficult. They do this by introducing a work factor (also known as iteration count or cost factor) which slows down the process of deriving a key from a password.

For the actual encryption and decryption, Bytebox relies on the [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)  in [Galois/Counter Mode (GCM)](https://en.wikipedia.org/wiki/Galois/Counter_Mode). AES-GCM is a popular choice for symmetric key cryptographic block ciphers because it ensures both data confidentiality and authenticity.





