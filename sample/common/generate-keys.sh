#!/bin/bash

# Set the directory for the keys
KEY_DIR="keys"

# Set file names for the private and public keys
PRIVATE_KEY="$KEY_DIR/issuer.prv"
PUBLIC_KEY="$KEY_DIR/issuer.pub"

# Set the bit size for the RSA key (2048 is commonly used)
KEY_SIZE=2048

# Create the 'private' directory if it doesn't exist
if [ ! -d "$KEY_DIR" ]; then
  mkdir -p "$KEY_DIR"
  echo "Directory '$KEY_DIR' created."
fi

# Generate the RSA private key using OpenSSL
openssl genpkey -algorithm RSA -out $PRIVATE_KEY -pkeyopt rsa_keygen_bits:$KEY_SIZE

# Generate the RSA public key from the private key
openssl rsa -pubout -in $PRIVATE_KEY -out $PUBLIC_KEY

# Notify the user
if [ $? -eq 0 ]; then
  echo "RSA private key generated successfully and saved as $PRIVATE_KEY"
  echo "RSA public key generated successfully and saved as $PUBLIC_KEY"
else
  echo "An error occurred while generating the RSA keys"
fi
