use rsa::{
    RsaPublicKey, RsaPrivateKey, Oaep,
    pkcs8::{LineEnding, EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey},
};
use std::fs::{self, File};
use std::path::Path;
use clap::{Command, Arg};
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, CryptoRng};

fn encrypt(pub_key: &RsaPublicKey, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read input file
    let input_data = fs::read(file_path)?;

    // Encrypt data
    let mut rng = ChaCha20Rng::from_entropy();
    let padding = Oaep::new::<Sha256>();
    let encrypted_data = pub_key.encrypt(&mut rng, padding, &input_data)?;

    // Write encrypted data back to the same file
    fs::write(file_path, &encrypted_data)?;

    println!("File encrypted successfully!");
    Ok(())
}

fn decrypt(priv_key: &RsaPrivateKey, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read encrypted file
    let encrypted_data = fs::read(file_path)?;

    // Decrypt data
    let padding = Oaep::new::<Sha256>();
    let decrypted_data = priv_key.decrypt(padding, &encrypted_data)
        .map_err(|e| format!("Decryption failed: {}. This could be due to an invalid private key or corrupted input data.", e))?;

    // Write decrypted data back to the same file
    fs::write(file_path, &decrypted_data)?;

    println!("File decrypted successfully!");
    Ok(())
}

fn check_file_permissions(path: &str, check_write: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    
    if !path.exists() {
        return Err(format!("File does not exist: {}", path.display()).into());
    }

    if !path.is_file() {
        return Err(format!("Path is not a file: {}", path.display()).into());
    }

    let metadata = fs::metadata(path)?;

    if metadata.permissions().readonly() && check_write {
        return Err(format!("File is not writable: {}", path.display()).into());
    }

    // Check if the file is readable
    File::open(path)?;

    Ok(())
}

fn generate_key_pair(bits: usize) -> Result<(), Box<dyn std::error::Error>> {
    let allowed_sizes = vec![2048, 3072, 4096, 8192, 16384, 30000];
    if !allowed_sizes.contains(&bits) {
        return Err(format!("Invalid key size. Allowed sizes are: {:?}", allowed_sizes).into());
    }

    let mut rng = ChaCha20Rng::from_entropy();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    // Save private key
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    fs::write("private_key.pem", private_pem.as_bytes())?;

    // Save public key
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)?;
    fs::write("public_key.pem", public_pem.as_bytes())?;

    println!("Key pair generated successfully!");
    println!("Private key saved as: {}", std::env::current_dir()?.join("private_key.pem").display());
    println!("Public key saved as: {}", std::env::current_dir()?.join("public_key.pem").display());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = Command::new("RSA File Encryptor/Decryptor")
        .version("1.0")
        .author("Djetic Alexandre")
        .about("Encrypts or decrypts files using RSA")
        .subcommand(Command::new("encrypt")
            .about("Encrypts a file using RSA public key")
            .arg(Arg::new("file")
                .help("Path to the file to encrypt")
                .required(true)
                .index(1))
            .arg(Arg::new("public_key")
                .help("Path to the RSA public key file (PEM format)")
                .required(true)
                .index(2)))
        .subcommand(Command::new("decrypt")
            .about("Decrypts a file using RSA private key")
            .arg(Arg::new("file")
                .help("Path to the file to decrypt")
                .required(true)
                .index(1))
            .arg(Arg::new("private_key")
                .help("Path to the RSA private key file (PEM format)")
                .required(true)
                .index(2)))
        .subcommand(Command::new("generate")
            .about("Generates a new RSA key pair")
            .arg(Arg::new("bits")
                .help("Key size in bits (allowed values: 2048, 3072, 4096, 8192, 16384, 30000)")
                .default_value("16384")
                .required(false)
                .index(1)))
        .after_help("Usage:\n\
            - Encrypt:  cipher_file encrypt file.txt public_key.pem\n\
            - Decrypt:  cipher_file decrypt file.txt private_key.pem\n\
            - Generate: cipher_file generate [key_size]\n\
            Key sizes: 2048, 3072, 4096, 8192, 16384 (default), 30000");

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let file_path = sub_matches.get_one::<String>("file").unwrap();
            let pub_key_path = sub_matches.get_one::<String>("public_key").unwrap();

            // Check file permissions
            check_file_permissions(file_path, true)?;
            check_file_permissions(pub_key_path, false)?;

            // Read public key
            let pub_key_str = fs::read_to_string(pub_key_path)?;
            let pub_key = RsaPublicKey::from_public_key_pem(&pub_key_str)?;

            encrypt(&pub_key, file_path)?;
        }
        Some(("decrypt", sub_matches)) => {
            let file_path = sub_matches.get_one::<String>("file").unwrap();
            let priv_key_path = sub_matches.get_one::<String>("private_key").unwrap();

            // Check file permissions
            check_file_permissions(file_path, true)?;
            check_file_permissions(priv_key_path, false)?;

            // Read private key
            let priv_key_str = fs::read_to_string(priv_key_path)?;
            let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_key_str)?;

            decrypt(&priv_key, file_path)?;
        }
        Some(("generate", sub_matches)) => {
            let bits = sub_matches.get_one::<String>("bits")
                .unwrap_or(&String::from("16384"))
                .parse::<usize>()?;
            generate_key_pair(bits)?;
        }
        _ => {
            // Print help if no subcommand is provided
            app.print_help()?;
            println!(); // Add a newline after the help message
        }
    }

    Ok(())
}