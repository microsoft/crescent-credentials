#!/bin/bash

# Define the source and target directories
SOURCE_DIR="../../creds/test-vectors/rs256"
TARGET_DIR="./data/creds"

echo "Copying $SOURCE_DIR to $TARGET_DIR"

# Create the target directory if it doesn't exist
mkdir -p "$TARGET_DIR"

# Copy the contents from the source directory to the target directory
cp -r "$SOURCE_DIR/"* "$TARGET_DIR"

echo "Done"
