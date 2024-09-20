# RSA File Encryptor/Decryptor

This is a command-line tool for encrypting and decrypting files using RSA encryption. It allows you to generate RSA key pairs, encrypt files using a public key, and decrypt files using a private key.

## Features

- Generate RSA key pairs
- Encrypt files using RSA public key
- Decrypt files using RSA private key
- Minimum key size of 2048 bits for enhanced security

## Building the Project

To build the project, you need to have Rust and Cargo installed on your system. If you don't have them installed, you can get them from [https://rustup.rs/](https://rustup.rs/).

Once you have Rust and Cargo installed, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cipher_file.git
   cd cipher_file
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

The executable will be created in the `target/release` directory.

## Usage

### Generating a Key Pair

```bash
cipher_file generate [key_size]
```

This will generate two files in the current directory:
- `private_key.pem`: The private key (keep this secure!)
- `public_key.pem`: The public key (can be shared)

### Key Sizes

The following table shows the allowed key sizes, sorted by security level, with commentary and examples:

| Key Size | Security Level | Commentary | Example Usage |
|----------|----------------|------------|---------------|
| 2048 bits | Minimal | Suitable for short-term protection. Not recommended for new applications. | `cipher_file generate 2048` |
| 3072 bits | Medium | Provides adequate security for most current applications. | `cipher_file generate 3072` |
| 4096 bits | High (Default) | Recommended for long-term protection. Balances security and performance. | `cipher_file generate` or `cipher_file generate 4096` |
| 16384 bits | Very High | Extremely secure but may impact performance. Use for highly sensitive data. | `cipher_file generate 16384` |

Notes:
- The default key size is 4096 bits if not specified.
- Larger key sizes provide more security but may increase encryption/decryption time and resource usage.
- Choose the key size based on your security requirements and performance considerations.

### Encrypting a File

```bash
cipher_file encrypt file.txt public_key.pem
```

This command encrypts the file `file.txt` using the public key stored in `public_key.pem`. The encrypted content will replace the original content in `file.txt`.

### Decrypting a File

```bash
cipher_file decrypt file.txt private_key.pem
```

This command decrypts the file `file.txt` using the private key stored in `private_key.pem`. The decrypted content will replace the encrypted content in `file.txt`.

## Installation

### Adding to PATH

#### Linux and macOS

1. Copy the executable to a directory in your PATH. A common choice is `/usr/local/bin`:
   ```bash
   sudo cp target/release/cipher_file /usr/local/bin/
   ```

2. Make sure the executable has the right permissions:
   ```bash
   sudo chmod +x /usr/local/bin/cipher_file
   ```

Alternatively, for a user-specific installation:

1. Create a bin directory in your home folder if it doesn't exist:
   ```bash
   mkdir -p ~/bin
   ```

2. Copy the executable to your bin directory:
   ```bash
   cp target/release/cipher_file ~/bin/
   ```

3. Add your bin directory to PATH. Add this line to your `~/.bashrc` or `~/.zshrc`:
   ```bash
   export PATH="$HOME/bin:$PATH"
   ```

4. Reload your shell configuration:
   ```bash
   source ~/.bashrc  # or source ~/.zshrc if you're using Zsh
   ```

#### Windows

1. Create a new folder for your executables, e.g., `C:\Users\YourUsername\bin`

2. Copy the `cipher_file.exe` from `target\release` to this folder.

3. Add the folder to your PATH:
   - Right-click on 'This PC' or 'My Computer' and choose 'Properties'
   - Click on 'Advanced system settings'
   - Click on 'Environment Variables'
   - Under 'User variables', find and edit 'Path'
   - Click 'New' and add the path to your bin folder (e.g., `C:\Users\YourUsername\bin`)

4. Open a new command prompt for the changes to take effect.

### Verifying Installation

To verify the installation, open a new terminal or command prompt and run:

```bash
cipher_file --version
```

This should display the version of the tool.

Now you can run `cipher_file` from any directory in your terminal or command prompt.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.