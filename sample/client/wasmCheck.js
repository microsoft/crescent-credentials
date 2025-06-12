/* 
 * Check if a wasm file exists in ../../creds/pkg"
 * If not (because wasm build likely failed), create a dummy package.json
 * This way our own package.json does not need to be dynamically updated
 *   and can always have the same reference the crescent package.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

console.log('Checking for Crescent WASM file...');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmDir = path.join(__dirname, '../../creds/pkg');
const wasmFilePath = path.join(wasmDir, 'crescent_bg.wasm');

// if the wasm file exists, exit
if (fs.existsSync(wasmFilePath)) {
    console.log('\x1b[32mWASM found at:\x1b[0m', wasmFilePath)
    process.exit(0);
}

console.warn('\x1b[33m[WARNING]\x1b[0m No package.json found at ../../creds/pkg, creating a dummy package.json');


// make directory if it does not exist
fs.mkdirSync(wasmDir, { recursive: true })

// if it does not exist, generate a dummy package.json at that location
const dummyPackageJson = {
    name: 'crescent',
    version: '1.0.0',
    main: 'crescent_bg.wasm',
    type: 'module',
    description: 'Dummy package for Crescent WASM',
}

fs.writeFileSync(path.join(wasmDir, 'package.json'), JSON.stringify(dummyPackageJson, null, 2));

process.exit(0);