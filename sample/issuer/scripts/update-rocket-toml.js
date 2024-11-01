// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

const fs = require('fs');

// read the kid from the JWKS file
function readKidFromJwk(filePath) {
    try {
        const jwkSet = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        return jwkSet.keys[0].kid;
    } catch (err) {
        console.error('Error reading the file:', err);
        process.exit(1);
    }
}

// read the Rocket.toml file
function readRocketToml(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf8');
    }
    catch (err) {
        console.error('Error reading the file:', err);
        process.exit(1);
    }
}

function updateRocketToml(rocketTomlPath, rocketToml, kid) {
    // update the 'kid' in the Rocket.toml file
    const updatedRocketToml = rocketToml.replace(/issuer_kid = ".+"/, `kid = "${kid}"`);
   
    // write the updated Rocket.toml file
    fs.writeFileSync(rocketTomlPath, updatedRocketToml, 'utf8');
}

const jwksPath = '.well-known/jwks.json';
const rocketTomlPath = 'Rocket.toml';
let kid = readKidFromJwk(jwksPath);
let rocketToml = readRocketToml(rocketTomlPath);
updateRocketToml(rocketTomlPath, rocketToml, kid);
console.log(`Updated the 'kid' in the issuer's 'Rocket.toml' file: ${kid}`);
