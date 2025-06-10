exports.rightPadArrayTo = function (arr, len, padValue = 0) {
  let a = new Array(len).fill(padValue);
  // right pad
  for (let i = 0; i < arr.length && i < len; i++) {
    a[i] = arr[i];
  }
  return a;
}

exports.leftPadArrayTo = function (arr, len, padValue = 0) {
  let a = new Array(len).fill(padValue);
  // left pad
  for (let i = 0; i < arr.length && i < len; i++) {
    a[len - arr.length + i] = arr[i];
  }
  return a;
}

exports.sha256pad = function (msg) {
  // get length of array in bits
  const len = msg.length;
  // copy array to dynamic length array
  let padded = [];
  for (let i = 0; i < len; i++) {
    padded.push(msg[i]);
  }
  // append 0x80
  padded.push(0x80);
  // append 0s until length is 56 % 64 bytes
  while ((padded.length % 64) != 56) {
    padded.push(0);
  }
  // append length as 64-bit big-endian integer
  // assume top 32 bits are 0 because our messages aren't that long
  const binlen = len * 8;
  for (let i = 0; i < 4; i++) { padded.push(0); }
  for (let i = 0; i < 4; i++) {
    padded.push((binlen >> (24 - i * 8)) & 0xFF);
  }
  // turn padded into array and return
  const paddedArray = new Uint8Array(padded);
  return paddedArray;
}

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function ROTR(x, n) {
  return (x >>> n) | (x << (32 - n));
}

// perform sha256 on an array of bytes without padding
exports.sha256withoutpad = function (msg) {
  // check that msg has length 0 % 64 bytes
  if ((msg.length % 64) != 0) {
    throw "sha256withoutpad: msg must be a multiple of 64 bytes";
  }
  // create hash state
  let H = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  ];
  for (let i = 0; i < msg.length; i += 64) {
    // set up message schedule
    let W = [];
    for (let t = 0; t < 16; t++) {
      W.push(msg[i + t * 4 + 0] * 0x1000000 + msg[i + t * 4 + 1] * 0x10000 + msg[i + t * 4 + 2] * 0x100 + msg[i + t * 4 + 3]);
    }
    for (let t = 16; t < 64; t++) {
      let s0 = ROTR(W[t - 15], 7) ^ ROTR(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      let s1 = ROTR(W[t - 2], 17) ^ ROTR(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W.push((W[t - 16] + s0 + W[t - 7] + s1) >>> 0);
    }
    // initialize working variables
    let v = [];
    for (let j = 0; j < 8; j++) {
      v.push(H[j]);
    }
    // compression function
    for (let j = 0; j < 64; j++) {
      let s1 = ROTR(v[4], 6) ^ ROTR(v[4], 11) ^ ROTR(v[4], 25);
      let ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
      let temp1 = (v[7] + s1 + ch + K[j] + W[j]) >>> 0;
      let s0 = ROTR(v[0], 2) ^ ROTR(v[0], 13) ^ ROTR(v[0], 22);
      let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
      let temp2 = (s0 + maj) >>> 0;
      v[7] = v[6];
      v[6] = v[5];
      v[5] = v[4];
      v[4] = (v[3] + temp1) >>> 0;
      v[3] = v[2];
      v[2] = v[1];
      v[1] = v[0];
      v[0] = (temp1 + temp2) >>> 0;
    }
    // update hash state
    for (let j = 0; j < 8; j++) {
      H[j] = (H[j] + v[j]) >>> 0;
    }
  }
  // return hash state
  return H;
}

// convert each entry in arr into an array of bits (32)
// return array of arrays
exports.tobitsarr = function (arr) {
  const bitsarr = Array(arr.length);
  for (let i = 0; i < arr.length; i++) {
    bitsarr[i] = Array(32);
    for (let j = 0; j < 32; j++) {
      bitsarr[i][j] = (arr[i] >> (31 - j)) & 1;
    }
  }
  return bitsarr;
}

exports.uintArrToBytesArr = function (arr) {
  const bytesarr = Array(4 * arr.length);
  for (let i = 0; i < arr.length; i++) {
    bytesarr[4 * i + 0] = (arr[i] >> 24) & 0xFF;
    bytesarr[4 * i + 1] = (arr[i] >> 16) & 0xFF;
    bytesarr[4 * i + 2] = (arr[i] >> 8) & 0xFF;
    bytesarr[4 * i + 3] = (arr[i] >> 0) & 0xFF;
  }
  return bytesarr;
}

exports.parseDSForOffset = function (rec) {
  // skip first 18 bytes
  let offset = 18;
  // parse past wire formatted name
  while (rec[offset] != 0) {
    offset += rec[offset] + 1;
  }
  offset++;
  // parse past wire formatted name again
  while (rec[offset] != 0) {
    offset += rec[offset] + 1;
  }
  offset++;
  // parse past type, class, ttl, and length (10 bytes)
  offset += 10;
  // parse past key tag
  offset += 2;
  // arrived at algorithm, get length - 128 and subtract from offset to get final offset
  return offset - (rec.length - 128);
}

exports.strToWire = function (str) {
  // strip trailing dot if present
  if (str[str.length - 1] == ".") {
    str = str.slice(0, -1);
  }
  // split string into labels
  let labels = str.split(".");
  // create array of bytes [len, label, len, label, ...]
  let bytes = [];
  for (let i = 0; i < labels.length; i++) {
    bytes.push(labels[i].length);
    for (let j = 0; j < labels[i].length; j++) {
      bytes.push(labels[i].charCodeAt(j));
    }
  }
  // append 0 byte and return
  bytes.push(0);
  return bytes;
}

exports.paddedNamesFromStr = function (str, max_len) {
  // strip trailing dot if present
  if (str[str.length - 1] == ".") {
    str = str.slice(0, -1);
  }
  // split string into labels
  let labels = str.split(".");
  // create array of arrays
  const names = Array(labels.length + 1);
  const lengths = Array(labels.length + 1);
  for (let i = 0; i <= labels.length; i++) {
    names[i] = Array(max_len);
    for (let j = 0; j < max_len; j++) {
      names[i][j] = 0;
    }
    let idx = 0;
    for (let j = i; j < labels.length; j++) {
      names[i][idx++] = labels[j].length;
      for (let k = 0; k < labels[j].length; k++) {
        names[i][idx++] = labels[j].charCodeAt(k);
      }
    }
    lengths[i] = idx + 1;
  }
  return { names: names, real_name_byte_lens: lengths };
}

// boilerplate for converting a string to a padded array
exports.truncateOrPadBigIntArray = function (bigIntArray, max_len, padValue = BigInt(0)) {
  // Create a new array with the size of max_len
  let resultArray = new Array(max_len).fill(padValue);
  if (bigIntArray.length > max_len) {
    // Truncate the array if it's longer than max_len
    resultArray = bigIntArray.slice(0, max_len);
  } else {
    // Pad the array if it's shorter than max_len
    for (let i = 0; i < bigIntArray.length; i++) {
      resultArray[i] = bigIntArray[i];
    }
  }
  return resultArray;
}

// take an array of arrays, unfold, and pack
exports.packInputsForField = function (fields) {
  // unfold
  let unfolded = [];
  for (let i = 0; i < fields.length; i++) {
    for (let j = 0; j < fields[i].length; j++) {
      unfolded.push(fields[i][j]);
    }
  }
  const packed = new Array(Math.ceil(unfolded.length / 31)).fill(BigInt(0));
  for (let i = 0; i < packed.length; i++) {
    for (let j = 0; j < 31; j++) {
      if (i * 31 + j < unfolded.length) {
        packed[i] += BigInt(unfolded[i * 31 + j]) << BigInt(8 * j);
      }
    }
  }
  return packed;
}

exports.logCircuitStats = function (cir) {
  // print variable and constraint counts
  console.log("Variable count: ", cir.nVars);
  console.log("Constraint Count: ", cir.constraints.length);
}

exports.base64ToBytes = function (base64) {
  const binString = atob(base64);
  return Array.from(binString, (m) => m.codePointAt(0));
}

// given an array of arbitrary nested lists, flatten it
// recursive function
exports.flattenNested = function (arr) {
  let flat = [];
  for (let i = 0; i < arr.length; i++) {
    if (Array.isArray(arr[i])) {
      flat = flat.concat(exports.flattenNested(arr[i]));
    } else {
      flat.push(arr[i]);
    }
  }
  return flat;
}

// flatten ecc sig aux witness
exports.flattenEccSigAux = function (aux) {
  return exports.flattenNested([aux.sig_s_inv, aux.sig_rx, aux.sig_ry, aux.u, aux.u2sign, aux.AUX, aux.addres_x, aux.addres_y, aux.addadva, aux.addadvb]);
}

exports.strToDomainPair = function(str) {
  // add trailing dot if not present
  if (str[str.length - 1] != ".") {
    str += ".";
  }
  // get everything past first .
  const domain = str.slice(str.indexOf(".") + 1);
  // return both as a pair
  return [str, domain];
}