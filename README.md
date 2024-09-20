# RSA File Encryptor/Decryptor

This is a command-line tool for encrypting and decrypting files using RSA encryption. It allows you to generate RSA key pairs, encrypt files using a public key, and decrypt files using a private key.

## Features

- Generate RSA key pairs
- Encrypt files using RSA public key
- Decrypt files using RSA private key
- Minimum key size of 10000 bits for enhanced security

## Building the Project

To build the project, you need to have Rust and Cargo installed on your system. If you don't have them installed, you can get them from [https://rustup.rs/](https://rustup.rs/).

Once you have Rust and Cargo installed, follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/yourusername/rsa-file-encryptor.git
cd rsa-file-encryptor
```

2. Build the project:

```
cargo build --release
```

The executable will be created in the `target/release` directory.

## Usage

### Generating a Key Pair

```bash
./target/release/cipher_file generate 10000
```

This will generate two files in the current directory:
- `private_key.pem`: The private key (keep this secure!)
- `public_key.pem`: The public key (can be shared)

### Encrypting a File

```bash
./target/release/cipher_file encrypt file.txt public_key.pem
```


This command encrypts the file `file.txt` using the public key stored in `public_key.pem`. The encrypted content will replace the original content in `file.txt`.

### Decrypting a File

```bash
./target/release/cipher_file decrypt file.txt private_key.pem
```

This command decrypts the file `file.txt` using the private key stored in `private_key.pem`. The decrypted content will replace the encrypted content in `file.txt`.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.