import { readFile, writeFile } from 'fs/promises';
import { buildSigWitness } from '../circuits-mdl/nope/js/eccutil.js';
import { flattenEccSigAux } from  '../circuits-mdl/nope/js/util.js';

async function loadJsonFile(path) {
    try {
        const data = await readFile(path, 'utf-8');
        return JSON.parse(data);
    } catch (err) {
        console.error(`Error reading ${path}:`, err);
        throw err;
    }
}

async function main() {
    const path = process.argv[2];
    if (!path) {
        console.error('Usage: node script.js <path to prover_inputs.json>');
        process.exit(1);
    }

    const proverInputs = await loadJsonFile(path);
    const msg = trimShaPadding(proverInputs.message);
    const key64 = proverInputs.pubkey.slice(1, 65);

    // Do sanity signature check
    await verifySignature(msg, proverInputs.signature, proverInputs.pubkey)
        .then(isValid => {
            console.log('Signature is valid:', isValid);
        }).catch(err => {
            console.error('Error verifying signature:', err);
        });

    const precompSig = flattenEccSigAux(buildSigWitness(msg, proverInputs.signature, key64));

    delete proverInputs.signature; // Signature is no longer required in prover_inputs

    const updatedJson = {
        ...proverInputs,
        pubkey: key64,
        sig: precompSig
    };

    try {
        await writeFile(path, JSON.stringify(updatedJson, null, 2));
        console.log(`Successfully wrote to ${path}`);
    } catch (err) {
        console.error(`Error writing to ${path}:`, err);
    }
}

function base64UrlEncode(buffer) {
    return btoa(String.fromCharCode(...buffer))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function importRawEcdsaKey(rawKeyBytes) {
    const start = rawKeyBytes.length - 64;
    const x = rawKeyBytes.slice(start, start + 32);
    const y = rawKeyBytes.slice(start + 32, start + 64);
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: base64UrlEncode(x),
        y: base64UrlEncode(y),
        ext: true,
    };
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256', }, true, ['verify']);
}


async function verifySignature(data, signature, publicKey) {
    return importRawEcdsaKey(
        publicKey
    ).then(abPublicKey => {
        const u8signature = new Uint8Array(signature);
        const u8data = new Uint8Array(data);
        return crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, abPublicKey, u8signature, u8data);
    })
}

function trimShaPadding(data) {
    let endIndex = data.length - 1;
    while (endIndex >= 0 && data[endIndex] === 0) {
        endIndex--;
    }
    const len = (data[endIndex] + (data[--endIndex] * 256) + (data[--endIndex] * 0x10000) + (data[--endIndex] * 0x1000000)) / 8;
    return data.slice(0, len);
}

main();