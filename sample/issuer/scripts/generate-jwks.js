// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// function to generate JWK Thumbprint 'kid' (Key ID) following RFC7638 
function generateKid(buffer) {
    // Generate a SHA-256 hash of the key to use as 'kid'
    const kid = crypto.createHash('sha256').update(buffer).digest('base64url');
    return kid;
}

// function to convert PEM to JWK
function pemToJWK(pem) {
    // remove PEM header, footer, and line breaks
    const pemContents = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');
    const buffer = Buffer.from(pemContents, 'base64');
    const kid = generateKid(buffer);

    // use Node.js crypto module to decode the PEM
    const publicKey = crypto.createPublicKey({
        key: buffer,
        format: 'der',
        type: 'spki'
    });

    // extract key details
    const keyDetails = publicKey.export({ format: 'jwk' });
    keyDetails.kid = kid;

    // return the JWKS
    return {
        keys: [keyDetails]
    };
}

// read the PEM public key from file
function readPEMFile(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        console.error('Error reading the file:', err);
        process.exit(1);
    }
}

// write the JWKS to file
function writeJWKSToFile(jwkSet, outputPath) {
    try {
        // extract the directory path from outputPath
        const dirPath = path.dirname(outputPath);

        // create the directories if they don't exist
        fs.mkdirSync(dirPath, { recursive: true });

        // write the file
        fs.writeFileSync(outputPath, JSON.stringify(jwkSet, null, 2), 'utf8');
        console.log(`JWK set has been written to ${outputPath}`);
    } catch (err) {
        console.error('Error writing the JWKS file:', err);
        process.exit(1);
    }
}

// paths to the PEM file and output JWK file
const pemFilePath = 'keys/issuer.pub';
const outputJWKPath = '.well-known/jwks.json';

const pemPublicKey = readPEMFile(pemFilePath);
const jwkSet = pemToJWK(pemPublicKey);
writeJWKSToFile(jwkSet, outputJWKPath);
