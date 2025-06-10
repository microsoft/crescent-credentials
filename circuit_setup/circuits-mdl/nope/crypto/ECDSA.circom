pragma circom 2.0.0;

include "sha256.circom";
include "../bigint/ecc.circom";

template ECDSAP256ValidateHash() {
  signal input hash[32];
  signal input key[64];
  signal input sig_s_inv[8];
  signal input sig_rx[8];
  signal input sig_ry[8];
  signal input u[4][4]; // all unsigned 32 bit words (so 4 128 bit numbers)
  signal input u2sign; // -1 or 1
  signal input AUX[2][13]; // TO DO, check if this should be 12 instead of 13
  // ensure u2sign is -1 or 1
  (1 + u2sign) * (1 - u2sign) === 0;
  // ensure sig_s_inv, sig_rx, and sig_ry have limbs with 32 bit words
  component Check256[3];
  Check256[0] = BigLimbCheck(8, 32); Check256[0].A <== sig_s_inv;
  Check256[1] = BigLimbCheck(8, 32); Check256[1].A <== sig_rx;
  Check256[2] = BigLimbCheck(8, 32); Check256[2].A <== sig_ry;
  // ensure AUX has limbs with 32 bit words
  component CheckAUX[2];
  CheckAUX[0] = BigLimbCheck(13, 32); CheckAUX[0].A <== AUX[0];
  CheckAUX[1] = BigLimbCheck(13, 32); CheckAUX[1].A <== AUX[1];
  // turn hash into 8 limbs of 32 bit words (flip endianness) (call that h)
  signal h[8];
  for (var i = 0; i < 8; i++) {
    h[i] <== hash[31 - i * 4] + 256 * hash[30 - i * 4] +
      (256 ** 2) * hash[29 - i * 4] + (256 ** 3) * hash[28 - i * 4];
  }
  // turn key into pair of 8 limbs of 32 bit words
  // (flip endianness) (multiply Qy by sign) (call that Q)
  signal Qx[8]; signal Qy[8];
  for (var i = 0; i < 8; i++) {
    Qx[i] <== key[31 - i * 4] + 256 * key[30 - i * 4] +
      (256 ** 2) * key[29 - i * 4] + (256 ** 3) * key[28 - i * 4];
    Qy[i] <== u2sign * (key[63 - i * 4] + 256 * key[62 - i * 4] +
      (256 ** 2) * key[61 - i * 4] + (256 ** 3) * key[60 - i * 4]);
  }
  // sig_s_inv * h * u3 - AUX0 * curve.order = U (becomes u0 and u1)
  // we will reuse Mul0!
  component Mul0 = BigMul(8, 4);
  Mul0.A <== sig_s_inv; Mul0.B <== u[3];
  component Mul1 = BigMul(11, 8);
  Mul1.A <== Mul0.C; Mul1.B <== h;
  component CMul0 = MulO(13);
  CMul0.A <== AUX[0];
  component Zero0 = BigIsZero(20, 32, 3 * 32 + 2 * 5 + 1);
  for (var i = 0; i < 20; i++) {
    if (i < 4) {
      Zero0.A[i] <== Mul1.C[i] - CMul0.C[i] - u[0][i];
    } else if (i < 8) {
      Zero0.A[i] <== Mul1.C[i] - CMul0.C[i] - u[1][i - 4];
    } else if (i < 18) {
      Zero0.A[i] <== Mul1.C[i] - CMul0.C[i];
    } else {
      Zero0.A[i] <== -CMul0.C[i];
    }
  }
  // sig_s_inv * sig_rx * u3 - AUX1 * curve.order = SIGN * u2
  // Mul0 reused here
  component Mul2 = BigMul(11, 8);
  Mul2.A <== Mul0.C; Mul2.B <== sig_rx;
  component CMul1 = MulO(13);
  CMul1.A <== AUX[1];
  component Zero1 = BigIsZero(20, 32, 3 * 32 + 2 * 5 + 1);
  for (var i = 0; i < 20; i++) {
    if (i < 4) {
      Zero1.A[i] <== Mul2.C[i] - CMul1.C[i] - u2sign * u[2][i];
    } else if (i < 18) {
      Zero1.A[i] <== Mul2.C[i] - CMul1.C[i];
    } else {
      Zero1.A[i] <== -CMul1.C[i];
    }
  }
  // convert u, u1, u2, and (u3 - 1) to 128bit binary arrays
  component To128[4];
  To128[0] = WordArrToBitArr(4, 32); To128[0].A <== u[0];
  To128[1] = WordArrToBitArr(4, 32); To128[1].A <== u[1];
  To128[2] = WordArrToBitArr(4, 32); To128[2].A <== u[2];
  To128[3] = WordArrToBitArr(4, 32);
  To128[3].A[0] <== u[3][0] - 1;
  for (var i = 1; i < 4; i++) { To128[3].A[i] <== u[3][i]; }
  // check quadmsm with u, u1, u2, (u3 - 1), Qx, Qy, sig_rx, sig_ry
  component QuadMSM = CheckQuadMSMAllAdd();
  QuadMSM.u0 <== To128[0].B; QuadMSM.u1 <== To128[1].B;
  QuadMSM.u2 <== To128[2].B; QuadMSM.u3 <== To128[3].B;
  QuadMSM.Qx <== Qx; QuadMSM.Qy <== Qy;
  QuadMSM.Rx <== sig_rx; QuadMSM.Ry <== sig_ry;
  // subset values and advice
  // values and advice
  signal input addres_x[269][8];
  signal input addres_y[269][8];
  signal input addadva[269][3];
  signal input addadvb[269][4];
  // redirect everything above into QuadMSM
  QuadMSM.addres_x <== addres_x;
  QuadMSM.addres_y <== addres_y;
  QuadMSM.addadva <== addadva;
  QuadMSM.addadvb <== addadvb;
}

// ECDSAP256SHA256SuffixVerify
template ECDSAP256SHA256SuffixVerify(SUFFIX_BLOCKS) {
  // hash inputs
  signal input suffix[SUFFIX_BLOCKS][64];
  signal input prev_hash_bits[8][32];
  // key and sig helpers
  signal input key[64];
  signal input sig_s_inv[8];
  signal input sig_rx[8];
  signal input sig_ry[8];
  signal input u[4][4];
  signal input u2sign;
  signal input AUX[2][13];
  // values and advice
  signal input addres_x[269][8];
  signal input addres_y[269][8];
  signal input addadva[269][3];
  signal input addadvb[269][4];
  // get hash of suffix
  component Hash[SUFFIX_BLOCKS];
  for (var i = 0; i < SUFFIX_BLOCKS; i++) {
    Hash[i] = SHAChunk();
    Hash[i].chunk_bytes <== suffix[i];
    if (i == 0) {
      Hash[i].prev_hash_bits <== prev_hash_bits;
    } else {
      Hash[i].prev_hash_bits <== Hash[i - 1].hash_bits;
    }
  }
  // check signature
  component ValidateHash = ECDSAP256ValidateHash();
  ValidateHash.hash <== Hash[SUFFIX_BLOCKS - 1].hash_bytes;
  ValidateHash.key <== key;
  ValidateHash.sig_s_inv <== sig_s_inv;
  ValidateHash.sig_rx <== sig_rx;
  ValidateHash.sig_ry <== sig_ry;
  ValidateHash.u <== u;
  ValidateHash.u2sign <== u2sign;
  ValidateHash.AUX <== AUX;
  ValidateHash.addres_x <== addres_x;
  ValidateHash.addres_y <== addres_y;
  ValidateHash.addadva <== addadva;
  ValidateHash.addadvb <== addadvb;
}


template ECDSAP256SHA256Verify(MAX_MSG_BYTES) {
  /* Inputs */
  signal input msg[MAX_MSG_BYTES];
  signal input real_msg_byte_len;
  signal input key[64];
  signal input sig_s_inv[8];
  signal input sig_rx[8];
  signal input sig_ry[8];
  signal input u[4][4];
  signal input u2sign;
  signal input AUX[2][13];
  // values and advice
  signal input addres_x[269][8];
  signal input addres_y[269][8];
  signal input addadva[269][3];
  signal input addadvb[269][4];
  /* No Outputs, validity checked */
  signal output result;
  /* Components */
  // get hash of message
  component Hash = SHA256(MAX_MSG_BYTES);
  Hash.msg <== msg;
  Hash.real_byte_len <== real_msg_byte_len;
  // check signature
  component ValidateHash = ECDSAP256ValidateHash();
  ValidateHash.hash <== Hash.hash;
  ValidateHash.key <== key;
  ValidateHash.sig_s_inv <== sig_s_inv;
  ValidateHash.sig_rx <== sig_rx;
  ValidateHash.sig_ry <== sig_ry;
  ValidateHash.u <== u;
  ValidateHash.u2sign <== u2sign;
  ValidateHash.AUX <== AUX;
  ValidateHash.addres_x <== addres_x;
  ValidateHash.addres_y <== addres_y;
  ValidateHash.addadva <== addadva;
  ValidateHash.addadvb <== addadvb;

  result <== 1; // if we reach here, the signature is valid
}

// no constraints, just makes our lives easier
template ECDSAP256SHA256SigUnpack() {
  // input
  signal input sig[6254];
  // sig helpers
  signal output sig_s_inv[8];
  signal output sig_rx[8];
  signal output sig_ry[8];
  signal output u[4][4];
  signal output u2sign;
  signal output AUX[2][13];
  // values and advice
  signal output addres_x[269][8];
  signal output addres_y[269][8];
  signal output addadva[269][3];
  signal output addadvb[269][4];
  // unpack sig, and redirect to outputs in order
  var idx = 0;
  for (var i = 0; i < 8; i++) {
    sig_s_inv[i] <== sig[idx]; idx++;
  }
  for (var i = 0; i < 8; i++) {
    sig_rx[i] <== sig[idx]; idx++;
  }
  for (var i = 0; i < 8; i++) {
    sig_ry[i] <== sig[idx]; idx++;
  }
  for (var i = 0; i < 4; i++) {
    for (var j = 0; j < 4; j++) {
      u[i][j] <== sig[idx]; idx++;
    }
  }
  u2sign <== sig[idx]; idx++;
  for (var i = 0; i < 13; i++) {
    AUX[0][i] <== sig[idx]; idx++;
  }
  for (var i = 0; i < 13; i++) {
    AUX[1][i] <== sig[idx]; idx++;
  }
  for (var i = 0; i < 269; i++) {
    for (var j = 0; j < 8; j++) {
      addres_x[i][j] <== sig[idx]; idx++;
    }
  }
  for (var i = 0; i < 269; i++) {
    for (var j = 0; j < 8; j++) {
      addres_y[i][j] <== sig[idx]; idx++;
    }
  }
  for (var i = 0; i < 269; i++) {
    for (var j = 0; j < 3; j++) {
      addadva[i][j] <== sig[idx]; idx++;
    }
  }
  for (var i = 0; i < 269; i++) {
    for (var j = 0; j < 4; j++) {
      addadvb[i][j] <== sig[idx]; idx++;
    }
  }
}

template ECDSAPrivKeyVerify() {
  signal input key[64];
  signal input k[256];
  signal input addres_x[21][8];
  signal input addres_y[21][8];
  signal input addadva[22][3];
  signal input addadvb[22][4];
  signal input Gadv_x[22][8];
  signal input Gadv_y[22][8];
  // first check that each signal in k is a bit
  for (var i = 0; i < 256; i++) {
    k[i] * (1 - k[i]) === 0;
  }
  // next compute GMul
  component gMul = ComputeGMul();
  gMul.u <== k;
  for (var i = 0; i < 21; i++) {
    gMul.addres_x[i] <== addres_x[i];
    gMul.addres_y[i] <== addres_y[i];
  }
  // check that GMul result is the same as key (pack bytes to words)
  for (var i = 0; i < 8; i++) {
    gMul.addres_x[21][i] <== key[31 - i * 4] + 256 * key[30 - i * 4] +
      (256 ** 2) * key[29 - i * 4] + (256 ** 3) * key[28 - i * 4];
    gMul.addres_y[21][i] <== key[63 - i * 4] + 256 * key[62 - i * 4] +
      (256 ** 2) * key[61 - i * 4] + (256 ** 3) * key[60 - i * 4];
  }
  gMul.addadva <== addadva;
  gMul.addadvb <== addadvb;
  gMul.Gadv_x <== Gadv_x;
  gMul.Gadv_y <== Gadv_y;
}