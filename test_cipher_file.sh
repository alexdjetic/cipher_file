#!/bin/bash

set -e

# Build the project
cargo build --release

# Function to run the program
run_cipher_file() {
    ./target/release/cipher_file "$@"
}

# Generate key pair
echo "Generating key pair..."
run_cipher_file generate

# Check if key files were created
if [ ! -f "private_key.pem" ] || [ ! -f "public_key.pem" ]; then
    echo "Error: Key files were not generated"
    exit 1
fi

# Create a test message
echo "Creating test message..."
./create_big_file.sh

# Check if test message was created
if [ ! -f "test_message.txt" ]; then
    echo "Error: Test message file was not created"
    exit 1
fi

original_content=$(md5sum test_message.txt | awk '{ print $1 }')

# Encrypt the file
echo "Encrypting file..."
run_cipher_file encrypt test_message.txt public_key.pem

# Check if the file content has changed (it should be encrypted now)
if [ "$original_content" = "$(md5sum test_message.txt | awk '{ print $1 }')" ]; then
    echo "Error: File was not encrypted"
    exit 1
fi

# Decrypt the file
echo "Decrypting file..."
run_cipher_file decrypt test_message.txt private_key.pem

# Check if the file has been correctly decrypted
decrypted_content=$(md5sum test_message.txt | awk '{ print $1 }')
if [ "$original_content" != "$decrypted_content" ]; then
    echo "Error: File was not correctly decrypted"
    exit 1
fi

# Clean up
rm test_message.txt private_key.pem public_key.pem

echo "All tests passed successfully!"