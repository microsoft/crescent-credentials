const {
  sha256pad, sha256withoutpad
} = require("./util.js");

// ECC
const curve = {
  p: BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
  a: BigInt("-3"),
  b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
  order: BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
  G: {
    x: BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
    y: BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
  },
  // 2^128 G
  Gprime: {
    x: BigInt("30978927491535595270285342502287618780579786685182435011955893029189825707397"),
    y: BigInt("20481551163499472379222416201371726725754635744576161296521936142531318405938")
  }
};

function to128Bits(u) {
  const ret = Array(128).fill(0);
  for (let i = 0; i < 128; i++) {
    ret[i] = u % 2n;
    u /= 2n;
  }
  return ret;
}

function absmod(u, n) {
  let r = u % n;
  if (r < 0n) { r += n; }
  if (n - r < r) { r = n - r; }
  return r;
}

function biglog2(u) {
  let b = 0;
  while (u > 0) {
    u /= 2n;
    b++;
  }
  return b;
}

// uses extended euclidean algorithm to find a v s.t
//  uv mod n is small and
//   v mod n is small
function centralGCD(u, n) {
  let s0 = 1n; let t0 = 0n; let r0 = n;
  let s1 = 0n; let t1 = 1n; let r1 = u;
  let bb = 256;
  let bv = 1n;
  while (r1 != 0n) {
    const q = r0 / r1;
    const r2 = r0 % r1;
    const s2 = s0 - q * s1;
    const t2 = t0 - q * t1;
    s0 = s1; t0 = t1; r0 = r1;
    s1 = s2; t1 = t2; r1 = r2;
    const v = absmod(t0, n);
    const uv = absmod(u * t0, n);
    const max = v < uv ? uv : v;
    const b = biglog2(max);
    // ensure t0 is positive
    if (b <= 128n) { return t0 >= 0 ? t0 : -t0; }
    if (b < bb) {
      bb = b;
      bv = t0;
    }
  }
  return bv;
}

function bytesToIntBigEndian(bytes) {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) + BigInt(bytes[i]);
  }
  return result;
}

function wordsToBytes(words) {
  const bytes = [];
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    bytes.push((word >> 24) & 0xFF);
    bytes.push((word >> 16) & 0xFF);
    bytes.push((word >> 8) & 0xFF);
    bytes.push(word & 0xFF);
  }
  return bytes;
}

// turn a 256 bit value p into two arrays of 32 bit words
function coordToWords(p, n = 8) {
  const q = p < 0n ? -p : p;
  const ret = Array(n).fill(0);
  const mask = (1n << 32n) - 1n;
  for (let i = 0; i < n; i++) {
    ret[i] = Number((q >> (32n * BigInt(i))) & mask);
  }
  // check that sum r[i] * 2^32^i = p
  let sum = 0n;
  for (let i = 0; i < n; i++) {
    sum += BigInt(ret[i]) << (32n * BigInt(i));
  }
  if (sum != q) {
    console.log("coordToWords failed p =", q, "sum =", sum);
  }
  if (p < 0n) {
    for (let i = 0; i < n; i++) {
      ret[i] *= -1;
    }
  }
  return ret;
}

function modExp(base, exp, mod) {
  let result = 1n;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    base = (base * base) % mod;
    exp /= 2n;
  }
  return result;
}

// kinda lazy, do this better later
function modInverse(a, m) {
  return modExp(a, m - 2n, m);
}

// function to take bigint x and break it into l chunks of bit length n
function tochunk(x, l = 8, n = 32) {
  let isNeg = false;
  if (x < 0) {
    x = -x;
    isNeg = true;
  }
  const mask = (1n << BigInt(n)) - 1n;
  const chunks = Array(l);
  for (let i = 0; i < l; i++) {
    chunks[i] = x & mask;
    if (isNeg) {
      chunks[i] = -chunks[i];
    }
    x = x >> BigInt(n);
  }
  return chunks;
}

// function to go from chunks of bitlength n to a number
function fromchunk(chunks, n = 32) {
  let x = 0n;
  for (let i = chunks.length - 1; i >= 0; i--) {
    x = (x << BigInt(n)) + chunks[i];
  }
  return x;
}

// given x and y as chunks, add them as chunks
function chunkadd(x, y) {
  let n = Math.max(x.length, y.length);
  const z = Array(n).fill(0n);
  for (let i = 0; i < x.length; i++) { z[i] = x[i]; }
  for (let i = 0; i < y.length; i++) { z[i] += y[i]; }
  return z;
}

// given x and y as chunks, sub them as chunks (x - y)
function chunksub(x, y) {
  let n = Math.max(x.length, y.length);
  const z = Array(n).fill(0n);
  for (let i = 0; i < x.length; i++) { z[i] = x[i]; }
  for (let i = 0; i < y.length; i++) { z[i] -= y[i]; }
  return z;
}

// given x and y as chunks, multiply them as chunks (i.e. treat them as polynomials)
function chunkmul(x, y) {
  const z = Array(x.length + y.length - 1).fill(0n);
  for (let i = 0; i < x.length; i++) {
    for (let j = 0; j < y.length; j++) {
      z[i + j] += x[i] * y[j];
    }
  }
  return z;
}

// given x as chunks and m as chunks and bit length n
// reduce x to fit within m
function chunkmod(x, m, n = 32) {
  const mb = fromchunk(m, n);
  let y = x.slice(0, m.length);
  for (let i = m.length; i < x.length; i++) {
    let t = tochunk((1n << BigInt(i * n)) % mb, m.length, n);
    y = chunkadd(y, chunkmul([x[i]], t));
  }
  return y;
}

function addFastAdvice(P, Q, R) {
  let l = chunkmod(
    chunkadd(
      chunkmul(
        chunksub(tochunk(Q.y), tochunk(P.y)),
        chunksub(tochunk(R.x), tochunk(Q.x))
      ), chunkmul(
        chunkadd(tochunk(R.y), tochunk(Q.y)),
        chunksub(tochunk(Q.x), tochunk(P.x))
      )), tochunk(curve.p));
  let ret = fromchunk(l) / curve.p;
  return ret;
}

function onCurveAdvice(P) {
  // on curve
  let l = chunkmod(
    chunksub(
      chunkmul(tochunk(P.y), tochunk(P.y)),
      chunkadd(
        chunkadd(
          chunkmul(tochunk(P.x), chunkmul(tochunk(P.x), tochunk(P.x))),
          chunkmul(tochunk(P.x), tochunk(curve.a))),
        tochunk(curve.b))), tochunk(curve.p));
  let res = fromchunk(l) / curve.p;
  return res;
}

function doubleAdvice(P, R) {
  return ((3n * P.x * P.x + curve.a) * (R.x - P.x) + 2n * P.y * (R.y + P.y)) / curve.p;
}

function pointDouble(P) {
  // point doubling
  const s = (3n * P.x * P.x + curve.a) * modInverse(2n * P.y, curve.p);
  const x = (s * s - 2n * P.x) % curve.p;
  const y = (s * (P.x - x) - P.y) % curve.p;
  return { x: (x + curve.p) % curve.p, y: (y + curve.p) % curve.p };
}

function pointAdd(P, Q) {
  // point addition
  // assume P != Q
  const s = ((Q.y - P.y) * modInverse(Q.x - P.x, curve.p)) % curve.p;
  const x = (s * s - P.x - Q.x) % curve.p;
  const y = (s * (P.x - x) - P.y) % curve.p;
  return { x: (x + curve.p) % curve.p, y: (y + curve.p) % curve.p };
}

function toBitArray(k) {
  const result = [];
  while (k > 0n) {
    result.push(k % 2n);
    k /= 2n;
  }
  return result;
}

function scalarMult(k, P) {
  let result = null;
  const bits = toBitArray(k);
  for (let i = bits.length - 1; i >= 0; i--) {
    if (result === null) {
      result = bits[i] === 1n ? P : null;
    } else {
      result = pointDouble(result);
      if (bits[i] === 1n) {
        result = pointAdd(result, P);
      }
    }
  }
  return result;
}

function makePointSubsets(Ps) {
  let subsets = [null, Ps[Ps.length - 1]];
  for (let i = Ps.length - 2; i >= 0; i--) {
    let newSubsets = [null, Ps[i]];
    for (let j = 1; j < subsets.length; j++) {
      newSubsets.push(subsets[j]);
      newSubsets.push(pointAdd(subsets[j], Ps[i]));
    }
    subsets = newSubsets;
  }
  return subsets;
}

function subsetSelection(ks) {
  const sel = [];
  for (let i = 0; i < ks.length; i++) {
    const bits = toBitArray(ks[i]);
    for (let j = 0; j < bits.length; j++) {
      const v = bits[j] ? (2 ** i) : 0;
      if (j < sel.length) {
        sel[j] += v
      } else {
        sel.push(v);
      }
    }
  }
  // reverse the array and return
  return sel.reverse();
}

// ks is an array of scalars
// Ps is an array of points
function multiScalarMult(ks, Ps) {
  // pre-compute all subsets of points
  const pointSubsets = makePointSubsets(Ps);
  // get subset selections
  const sel = subsetSelection(ks);
  // compute the result of the multi-scalar multiplication
  let P = pointSubsets[sel[0]];
  for (let i = 1; i < sel.length; i++) {
    P = pointDouble(P);
    if (sel[i] != 0) {
      P = pointAdd(P, pointSubsets[sel[i]]);
    }
  }
  return P;
}

// doubleless multi-scalar multiplication
function multiScalarMultExp(ks, Ps) {
  // pre-compute all subsets of points
  let pointSubsets = makePointSubsets(Ps);
  pointSubsets[0] = curve.G;
  for (let i = 1; i < pointSubsets.length; i++) {
    if (pointSubsets[i] == curve.G) {
      pointSubsets[i] = pointDouble(pointSubsets[i]);
    } else {
      pointSubsets[i] = pointAdd(pointSubsets[i], curve.G);
    }
  }
  // get subset selections
  const sel = subsetSelection(ks);
  // compute the result of the multi-scalar multiplication
  let P = pointSubsets[sel[0]];
  let nG = { x: curve.G.x, y: -curve.G.y };
  let G = nG;
  for (let i = 1; i < sel.length; i++) {
    let T = pointAdd(P, pointSubsets[sel[i]]);
    P = pointAdd(P, T);
    G = pointDouble(G);
    G = pointAdd(G, nG);
  }
  // get P + G
  P = pointAdd(P, G);
  return P;
}

/*
[u0, u1, u2, u3]
Anything involving only G and H is free
[0, 0, 0, 0] -> G
[0, 0, 0, 1] -> G + R
[0, 0, 1, 0] -> G + Q
[0, 0, 1, 1] -> G + Q + R
[0, 1, 0, 0] -> G + H
[0, 1, 0, 1] -> G + H + R
[0, 1, 1, 0] -> G + H + Q
[0, 1, 1, 1] -> G + H + Q + R
[1, 0, 0, 0] -> 2G
[1, 0, 0, 1] -> 2G + R
[1, 0, 1, 0] -> 2G + Q
[1, 0, 1, 1] -> 2G + Q + R
[1, 1, 0, 0] -> 2G + H
[1, 1, 0, 1] -> 2G + H + R
[1, 1, 1, 0] -> 2G + H + Q
[1, 1, 1, 1] -> 2G + H + Q + R
*/

function fourScalarMultLogAllAdd(u0, u1, u2, u3, G, H, Q, R) {
  let log = {
    // results and advice
    addres: [], addadva: [], addadvb: [],
  };
  // explicit make subset function
  const subsets = Array(16);
  for (let i = 0; i < 16; i++) {
    if (i == 0) {
      subsets[i] = G; // free
    } else if (i == 4) {
      subsets[i] = pointAdd(G, H); // free
    } else if (i == 8) {
      subsets[i] = pointDouble(G); // free
    } else if (i == 12) {
      subsets[i] = pointAdd(pointDouble(G), H); // free
    } else if (i % 2 == 1) {
      subsets[i] = pointAdd(subsets[i - 1], R);
      log.addres.push(subsets[i]);
      log.addadva.push(addFastAdvice(subsets[i - 1], R, subsets[i]));
      log.addadvb.push(onCurveAdvice(subsets[i]));
    } else {
      subsets[i] = pointAdd(subsets[i - 2], Q);
      log.addres.push(subsets[i]);
      log.addadva.push(addFastAdvice(subsets[i - 2], Q, subsets[i]));
      log.addadvb.push(onCurveAdvice(subsets[i]));
    }
  }
  // get subset selections 
  const sel = Array(128).fill(0);
  for (let i = 0; i < 128; i++) {
    sel[127 - i] = (u3 % 2n) + 2n * (u2 % 2n) + 4n * (u1 % 2n) + 8n * (u0 % 2n);
    u0 /= 2n; u1 /= 2n; u2 /= 2n; u3 /= 2n;
  }
  // compute the result of the multi-scalar multiplication without branching
  // and without doubling!
  let nG = { x: G.x, y: -G.y };
  let Ge = { x: H.x, y: -H.y };
  let P = H;
  for (let i = 0; i < 128; i++) {
    let T0 = pointAdd(P, subsets[sel[i]]);
    log.addres.push(T0);
    log.addadva.push(addFastAdvice(P, subsets[sel[i]], T0));
    log.addadvb.push(onCurveAdvice(T0));
    let T1 = pointAdd(P, T0);
    log.addres.push(T1);
    log.addadva.push(addFastAdvice(P, T0, T1));
    log.addadvb.push(onCurveAdvice(T1));
    P = T1;
    Ge = pointDouble(Ge);
    Ge = pointAdd(Ge, nG);
  }
  // get P + Ge (to cancel out the fact that we started P with H)
  let T2 = pointAdd(P, Ge);
  log.addres.push(T2);
  //log.addadv.push(addAdvice(P, Ge, T2));
  log.addadva.push(addFastAdvice(P, Ge, T2));
  log.addadvb.push(onCurveAdvice(T2));
  P = T2;
  return log;
}

function buildSigWitness(rec, sig, key) {
  // preprocess signature
  // new signature is (r, s_inv), combine into 64 byte array
  const r = bytesToIntBigEndian(sig.slice(0, 32));
  const s = bytesToIntBigEndian(sig.slice(32, 64));
  const s_inv = modInverse(s, curve.order);
  const l = key.length - 64;
  const P = {
    x: bytesToIntBigEndian(key.slice(l, l + 32)),
    y: bytesToIntBigEndian(key.slice(l + 32, l + 64))
  };
  // get hash of record
  const hash = sha256withoutpad(sha256pad(rec));
  const h = bytesToIntBigEndian(wordsToBytes(hash));
  // get u, v, and tmp
  const u = (h * s_inv) % curve.order;
  const v = (r * s_inv) % curve.order;
  const u3 = centralGCD(v, curve.order);
  const uu3 = (u * u3) % curve.order;
  const u0 = uu3 % (2n ** 128n);
  const u1 = uu3 / (2n ** 128n);
  const u2t = (v * u3) % curve.order;
  const u2 = absmod(u2t, curve.order);
  const Q = u2t == u2 ? P : { x: P.x, y: -P.y };
  const X = multiScalarMult([u, v], [curve.G, P]);
  // sanity check that X.x == r
  if (X.x != r) { console.log("Error Invalid Sig: X.x != r"); }
  // get advice values from log
  const msmlog = fourScalarMultLogAllAdd(u0, u1, u2, u3 - 1n, curve.G, curve.Gprime, Q, { x: X.x, y: curve.p - X.y });
  // return as a package
  return {
    // sig info
    sig_s_inv: coordToWords(s_inv),
    sig_rx: coordToWords(r),
    sig_ry: coordToWords(curve.p - X.y),
    // helpers for sig info
    u: [coordToWords(u0, 4), coordToWords(u1, 4),
    coordToWords(u2, 4), coordToWords(u3, 4)],
    u2sign: u2t == u2 ? 1 : -1,
    AUX: [
      coordToWords((s_inv * h * u3 - (u0 + u1 * (2n ** 128n))) / curve.order, 13),
      coordToWords((s_inv * r * u3 - (u2t == u2 ? 1n : -1n) * u2) / curve.order, 13)
    ],
    // values and advice for MSM
    addres_x: msmlog.addres.map(p => coordToWords(p.x)),
    addres_y: msmlog.addres.map(p => coordToWords(p.y)),
    addadva: msmlog.addadva.map(p => coordToWords(p, 3)),
    addadvb: msmlog.addadvb.map(p => coordToWords(p, 4))
  }
}

// compute k' G + sum (1 << w_i) G where
// k' is a max 12 bit number starting at bit i of the array k
// and w_i is all i mod 12 smaller than or equal to ws
// if ws + 12 >= 256, then we stop and k' has fewer than 12 bits
function gMulFromWindow(k, ws) {
  const G = curve.G;
  // double ws times
  let Q = curve.G;
  let R = G;
  for (let i = 0; i < ws; i++) {
    R = pointDouble(R);
    if ((i + 1) % 12 == 0) {
      Q = pointAdd(Q, R);
    }
  }
  // walk through the window and add the points
  for (let i = ws; i < 256 && i < ws + 12; i++) {
    if (k[i] == 1) {
      if (Q.x == R.x && Q.y == R.y) {
        Q = pointDouble(Q);
      } else {
        Q = pointAdd(Q, R);
      }
    }
    R = pointDouble(R);
  }
  return Q;
}

// assumes 22 12 bit chunks (top chunk 4 bits)
function gMulLog(k) {
  // construct the Gadv values
  const Gadv = Array(22);
  for (let i = 0; i < 22; i++) {
    Gadv[i] = gMulFromWindow(k, i * 12);
  }
  // iteratively add the Gadv values (keeping track of advice and results)
  // ensure that a final constant is subtracted at the end
  const addres = Array(22); // 22
  const addadva = Array(22); // 22
  const addadvb = Array(22); // 22
  // iterative addition
  for (let i = 0; i < 21; i++) {
    const P = (i == 0) ? Gadv[0] : addres[i - 1];
    const Q = Gadv[i + 1];
    addres[i] = pointAdd(P, Q);
    addadva[i] = addFastAdvice(P, Q, addres[i]);
    addadvb[i] = onCurveAdvice(addres[i]);
  }
  // subtract magic final constant
  const S = { x: 46431247717883781761885631845507343129346898080316457052779068246241091921087n, y: 95414078584676249149618150324565470906298037869671205054945231832901634469714n };
  addres[21] = pointAdd(addres[20], S);
  addadva[21] = addFastAdvice(addres[20], S, addres[21]);
  addadvb[21] = onCurveAdvice(addres[21]);
  return {
    Gadv: Gadv,
    addres: addres,
    addadva: addadva,
    addadvb: addadvb
  }
}

// key and constant, concats and builds witness for proof
function proofOfECCKey(cst) {
  var big = BigInt(0);
  for (var i = 0; i < 32; i++) {
    big = (big << BigInt(8)) + BigInt(cst[i]);
  }
  // k2 to bits (LSB to MSB)
  const k = Array(256).fill(0);
  for (let i = 0; i < 256; i++) {
    k[i] = (big >> BigInt(i)) & 1n;
  }
  // log of the multi-scalar multiplication + lookups
  const plog = gMulLog(k);
  // package for return
  const ret = {
    k: k,
    addres_x: plog.addres.map(p => coordToWords(p.x)).slice(0, 21),
    addres_y: plog.addres.map(p => coordToWords(p.y)).slice(0, 21),
    //addadv: plog.addadv.map(p => coordToWords(p, 9)),
    addadva: plog.addadva.map(p => coordToWords(p, 3)),
    addadvb: plog.addadvb.map(p => coordToWords(p, 4)),
    Gadv_x: plog.Gadv.map(p => coordToWords(p.x)),
    Gadv_y: plog.Gadv.map(p => coordToWords(p.y))
  };
  return ret;
}

module.exports = {
  curve,
  to128Bits,
  absmod,
  modInverse,
  centralGCD,
  bytesToIntBigEndian,
  wordsToBytes,
  coordToWords,
  modExp,
  pointDouble,
  addFastAdvice,
  onCurveAdvice,
  pointAdd,
  scalarMult,
  multiScalarMult,
  multiScalarMultExp,
  makePointSubsets,
  subsetSelection,
  fourScalarMultLogAllAdd,
  buildSigWitness,
  gMulLog,
  proofOfECCKey
}