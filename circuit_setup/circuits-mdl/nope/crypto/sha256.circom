pragma circom 2.0.0;

// includes
include "../util/buffer.circom";
include "../util/bits.circom";

// shift an array of N elements to the right S places
template ShiftRight(N, S) {
  signal input arr[N];
  signal output shifted[N];
  for (var i = 0; i < N; i++) {
    if (i < S) {
      shifted[i] <== 0;
    } else {
      shifted[i] <== arr[i - S];
    }
  }
}

// rotate an array of N elements to the right S places
template RotateRight(N, S) {
  signal input arr[N];
  signal output rotated[N];
  for (var i = 0; i < N; i++) {
    rotated[i] <== arr[(N + i - S) % N];
  }
}

// compute the entrywise xor of 3 arrays (assumed to be binary)
template Xor_3(N) {
  signal input a[N];
  signal input b[N];
  signal input c[N];
  signal output out[N];
  signal axorb[N];
  for (var i = 0; i < N; i++) {
    axorb[i] <== a[i] + b[i] - 2 * a[i] * b[i];
    out[i] <== axorb[i] + c[i] - 2 * axorb[i] * c[i];
  }
}

// add M N-bit numbers (Big Endian) and get the sum as an N-bit number
// ignore overflow
template SHASumToBits(N, M) {
  signal input v[M][N];
  signal output o[N];
  // get ceil log_2 of M
  var logM = 1;
  var tmp = M - 1;
  while (tmp > 1) {
    tmp = tmp \ 2;
    logM += 1;
  }
  // overflow
  signal dbits[logM];
  // compute
  var lc = 0;
  for (var i = 0; i < N; i++) {
    for (var j = 0; j < M; j++) {
      lc += v[j][i] * (1 << (N - i - 1));
    }
  }
  // set bits
  var lc2 = 0;
  for (var i = 0; i < N; i++) {
    o[i] <-- (lc >> (N - 1 - i)) & 1;
    o[i] * (1 - o[i]) === 0;
    lc2 += o[i] * (1 << (N - 1 - i));
  }
  for (var i = 0; i < logM; i++) {
    dbits[i] <-- (lc >> (N + logM - 1 - i)) & 1;
    dbits[i] * (1 - dbits[i]) === 0;
    lc2 += dbits[i] * (1 << (N + logM - 1 - i));
  }
  // check equality
  lc2 === lc;
}

template SHAMsgScheduleStep() {
  signal input wm16[32];
  signal input wm15[32];
  signal input wm7[32];
  signal input wm2[32];
  signal output w[32];
  component RotR[4];
  component SftR[2];
  component TXor[2];
  // calculate S0
  RotR[0] = RotateRight(32, 7);
  RotR[1] = RotateRight(32, 18);
  SftR[0] = ShiftRight(32, 3);
  TXor[0] = Xor_3(32);
  RotR[0].arr <== wm15;
  RotR[1].arr <== wm15;
  SftR[0].arr <== wm15;
  TXor[0].a <== RotR[0].rotated;
  TXor[0].b <== RotR[1].rotated;
  TXor[0].c <== SftR[0].shifted;
  // calculate S1
  RotR[2] = RotateRight(32, 17);
  RotR[3] = RotateRight(32, 19);
  SftR[1] = ShiftRight(32, 10);
  TXor[1] = Xor_3(32);
  RotR[2].arr <== wm2;
  RotR[3].arr <== wm2;
  SftR[1].arr <== wm2;
  TXor[1].a <== RotR[2].rotated;
  TXor[1].b <== RotR[3].rotated;
  TXor[1].c <== SftR[1].shifted;
  // calculate w, reduce to bits, ignore overflow
  component Sum4 = SHASumToBits(32, 4);
  Sum4.v[0] <== wm16;
  Sum4.v[1] <== TXor[0].out;
  Sum4.v[2] <== wm7;
  Sum4.v[3] <== TXor[1].out;
  w <== Sum4.o;
}

template SHAS1() {
  signal input v[32];
  signal output o[32];
  component RotR[3];
  component TXor;
  RotR[0] = RotateRight(32, 6);
  RotR[1] = RotateRight(32, 11);
  RotR[2] = RotateRight(32, 25);
  TXor = Xor_3(32);
  RotR[0].arr <== v;
  RotR[1].arr <== v;
  RotR[2].arr <== v;
  TXor.a <== RotR[0].rotated;
  TXor.b <== RotR[1].rotated;
  TXor.c <== RotR[2].rotated;
  o <== TXor.out;
}

template SHACh() {
  signal input v4[32];
  signal input v5[32];
  signal input v6[32];
  signal output o[32];
  for (var i = 0; i < 32; i++) {
    // (v[4] & v[5]) ^ (~v[4] & v[6])
    // = v[4] * v[5] + (1 - v[4]) * v[6] - 2 * v[4] * v[5] * (1 - v[4]) * v[6]
    // Note v[4] * (1 - v[4]) == 0
    // So = v[4] * v[5] + (1 - v[4]) * v[6]
    // = v[4] * v[5] + v[6] - v[4] * v[6]
    // = v[4] * (v[5] - v[6]) + v[6]
    o[i] <== v4[i] * (v5[i] - v6[i]) + v6[i];
  }
}

template SHAS0() {
  signal input v[32];
  signal output o[32];
  component RotR[3];
  component TXor;
  RotR[0] = RotateRight(32, 2);
  RotR[1] = RotateRight(32, 13);
  RotR[2] = RotateRight(32, 22);
  TXor = Xor_3(32);
  RotR[0].arr <== v;
  RotR[1].arr <== v;
  RotR[2].arr <== v;
  TXor.a <== RotR[0].rotated;
  TXor.b <== RotR[1].rotated;
  TXor.c <== RotR[2].rotated;
  o <== TXor.out;
}

template SHAMaj() {
  signal input v0[32];
  signal input v1[32];
  signal input v2[32];
  signal output o[32];
  // v0 v1 ^ v0 v2 ^ v1 v2
  // v0 (v1 ^ v2) ^ v1 v2
  // v0 * (v1 + v2 - 2 * v1 * v2) + v1 * v2
  signal t[32];
  for (var i = 0; i < 32; i++) {
    t[i] <== v1[i] * v2[i];
    o[i] <== v0[i] * (v1[i] + v2[i] - 2 * t[i]) + t[i];
  }
}

// perform a single compression step
template SHAComp() {
  signal input w[32];
  signal input h[8][32];
  signal output s1[32];
  signal output ch[32];
  signal output s0[32];
  signal output maj[32];
  // calculate S1
  component S1 = SHAS1();
  S1.v <== h[4];
  s1 <== S1.o;
  // calculate ch
  component Ch = SHACh();
  Ch.v4 <== h[4];
  Ch.v5 <== h[5];
  Ch.v6 <== h[6];
  ch <== Ch.o;
  // calculate S0
  component S0 = SHAS0();
  S0.v <== h[0];
  s0 <== S0.o;
  // calculate maj
  component Maj = SHAMaj();
  Maj.v0 <== h[0];
  Maj.v1 <== h[1];
  Maj.v2 <== h[2];
  maj <== Maj.o;
}

template SHACompInner() {
  signal input w[32];
  signal input h[8][32];
  signal input K[32];
  signal output hp[8][32];
  component SHACompStep = SHAComp();
  SHACompStep.w <== w;
  SHACompStep.h <== h;
  // shift
  hp[7] <== h[6];
  hp[6] <== h[5];
  hp[5] <== h[4];
  // sum
  component Sum1 = SHASumToBits(32, 6);
  Sum1.v[0] <== h[3];
  Sum1.v[1] <== h[7];
  Sum1.v[2] <== SHACompStep.s1;
  Sum1.v[3] <== SHACompStep.ch;
  Sum1.v[4] <== K;
  Sum1.v[5] <== w;
  hp[4] <== Sum1.o;
  // shift
  hp[3] <== h[2];
  hp[2] <== h[1];
  hp[1] <== h[0];
  // sum
  component Sum2 = SHASumToBits(32, 7);
  Sum2.v[0] <== h[7];
  Sum2.v[1] <== SHACompStep.s1;
  Sum2.v[2] <== SHACompStep.ch;
  Sum2.v[3] <== K;
  Sum2.v[4] <== w;
  Sum2.v[5] <== SHACompStep.s0;
  Sum2.v[6] <== SHACompStep.maj;
  hp[0] <== Sum2.o;
}

template SHACompFinal() {
  signal input w[32];
  signal input h[8][32];
  signal input p[8][32];
  signal input K[32];
  signal output hp[8][32];
  component SHACompStep = SHAComp();
  SHACompStep.w <== w;
  SHACompStep.h <== h;
  // shift
  //hp[7] <== h[6];
  component Sum7 = SHASumToBits(32, 2);
  Sum7.v[0] <== p[7];
  Sum7.v[1] <== h[6];
  hp[7] <== Sum7.o;
  //hp[6] <== h[5];
  component Sum6 = SHASumToBits(32, 2);
  Sum6.v[0] <== p[6];
  Sum6.v[1] <== h[5];
  hp[6] <== Sum6.o;
  //hp[5] <== h[4];
  component Sum5 = SHASumToBits(32, 2);
  Sum5.v[0] <== p[5];
  Sum5.v[1] <== h[4];
  hp[5] <== Sum5.o;
  // sum
  component Sum4 = SHASumToBits(32, 7);
  Sum4.v[0] <== h[3];
  Sum4.v[1] <== h[7];
  Sum4.v[2] <== SHACompStep.s1;
  Sum4.v[3] <== SHACompStep.ch;
  Sum4.v[4] <== K;
  Sum4.v[5] <== w;
  Sum4.v[6] <== p[4];
  hp[4] <== Sum4.o;
  // shift
  //hp[3] <== h[2];
  component Sum3 = SHASumToBits(32, 2);
  Sum3.v[0] <== p[3];
  Sum3.v[1] <== h[2];
  hp[3] <== Sum3.o;
  //hp[2] <== h[1];
  component Sum2 = SHASumToBits(32, 2);
  Sum2.v[0] <== p[2];
  Sum2.v[1] <== h[1];
  hp[2] <== Sum2.o;
  //hp[1] <== h[0];
  component Sum1 = SHASumToBits(32, 2);
  Sum1.v[0] <== p[1];
  Sum1.v[1] <== h[0];
  hp[1] <== Sum1.o;
  // sum
  component Sum0 = SHASumToBits(32, 8);
  Sum0.v[0] <== h[7];
  Sum0.v[1] <== SHACompStep.s1;
  Sum0.v[2] <== SHACompStep.ch;
  Sum0.v[3] <== K;
  Sum0.v[4] <== w;
  Sum0.v[5] <== SHACompStep.s0;
  Sum0.v[6] <== SHACompStep.maj;
  Sum0.v[7] <== p[0];
  hp[0] <== Sum0.o;
}

template SHAChunk() {
  signal input chunk_bytes[64];
  signal input prev_hash_bits[8][32];
  signal output hash_bytes[32];
  signal output hash_bits[8][32];
  // set up message schedule (64 32 bit words)
  signal w[64][32];
  component ChunkWBin[16];
  // first 16 words are the chunk
  for (var i = 0; i < 16; i++) {
    ChunkWBin[i] = SigToBinaryBigEndian(32);
    ChunkWBin[i].val <== chunk_bytes[4 * i + 3] +
                   256 * chunk_bytes[4 * i + 2] +
                 65536 * chunk_bytes[4 * i + 1] +
              16777216 * chunk_bytes[4 * i];
    w[i] <== ChunkWBin[i].bits;
  }
  // the rest are computed from the first 16
  component MsgScheduleStep[48];
  for (var i = 16; i < 64; i++) {
    MsgScheduleStep[i - 16] = SHAMsgScheduleStep();
    MsgScheduleStep[i - 16].wm16 <== w[i - 16];
    MsgScheduleStep[i - 16].wm15 <== w[i - 15];
    MsgScheduleStep[i - 16].wm7 <== w[i - 7];
    MsgScheduleStep[i - 16].wm2 <== w[i - 2];
    w[i] <== MsgScheduleStep[i - 16].w;
  }
  // 64 compression function steps
  var K[64] = [
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
  component SHACompIStep[63];
  for (var i = 0; i < 63; i++) {
    SHACompIStep[i] = SHACompInner();
    SHACompIStep[i].w <== w[i];
    if (i == 0) {
      SHACompIStep[i].h <== prev_hash_bits;
    } else {
      SHACompIStep[i].h <== SHACompIStep[i - 1].hp;
    }
    for (var j = 0; j < 32; j++) {
      SHACompIStep[i].K[j] <== (K[i] >> (31 - j)) & 1;
    }
  }
  component SHACompFStep = SHACompFinal();
  SHACompFStep.w <== w[63];
  SHACompFStep.h <== SHACompIStep[62].hp;
  for (var j = 0; j < 32; j++) {
    SHACompFStep.K[j] <== (K[63] >> (31 - j)) & 1;
  }
  SHACompFStep.p <== prev_hash_bits;
  hash_bits <== SHACompFStep.hp;
  // and convert hash_bits to bytes
  for (var i = 0; i < 8; i++) {
    for (var j = 0; j < 4; j++) {
      var lc = 0;
      for (var k = 0; k < 8; k++) {
        lc += hash_bits[i][8 * j + k] * (1 << (7 - k));
      }
      hash_bytes[4 * i + j] <== lc;
    }
  }
}

// 3 formatting steps applied to the message
// 1. add a single 0x80 byte
// 2. add 0x00 bytes until the number of bytes is -8 mod 64
// 3. add the length of the message in bits as a 64 bit big endian integer
// assume that MAX_BYTES is less than 2^16 - 8 so the length can be stored in the final 2 bytes
template SHA256Format(MAX_BYTES) {
  /* inputs and outputs */
  signal input msg[MAX_BYTES];
  signal input real_byte_len; // real length in bytes
  var max_fmt_msg_chunks = 1 + ((8 + MAX_BYTES) \ 64);
  signal output fmt_msg[max_fmt_msg_chunks][64];
  signal output real_num_chunks; // the actual number of chunks

  // flag for end of msg
  //signal is_byte_final[MAX_BYTES + 1];
  component ByteFinal = SigBoolSelect(MAX_BYTES + 1);
  ByteFinal.index <== real_byte_len;
  component ByteFinalBeyond = PrefixSum(MAX_BYTES + 1);
  ByteFinalBeyond.arr <== ByteFinal.flag;

  // set real_num_chunks
  // intutively it is 1 + floor((len + 8) / 64)
  // get len + 8 as a 16 bit integer
  component LenBits = SigToBinary(16);
  LenBits.val <== real_byte_len + 8;
  var bitsum = LenBits.bits[15];
  for (var i = 14; i >= 6; i--) {
    bitsum = 2 * bitsum + LenBits.bits[i];
  }
  real_num_chunks <== bitsum;

  // flag for last chunk
  //signal is_chunk_final[1 + ((8 + MAX_BYTES) / 64)];
  component ChunkFinal = SigBoolSelect(max_fmt_msg_chunks);
  ChunkFinal.index <== real_num_chunks;

  // get real length in bits as 2 bytes
  component LenBytes = SigToBytes(16);
  LenBytes.val <== 8 * real_byte_len;

  // create components to allow below to compile
  signal tmp[max_fmt_msg_chunks][66];

  // loop over chunks
  var is_over_len = 0;
  for (var i = 0; i < max_fmt_msg_chunks; i++) {
    // loop over the contents of the chunk and add the appropriate bytes
    for (var j = 0; j < 64; j++) {
      var id = 64 * i + j;
      // if in the last two bytes, possibly add length
      if (j == 62 || j == 63) {
        if (id < MAX_BYTES) {
          tmp[i][j] <== ChunkFinal.flag[i] * LenBytes.bytes[63 - j];
          tmp[i][j + 2] <== (1 - ByteFinalBeyond.psum[id]) * msg[id];
          fmt_msg[i][j] <== tmp[i][j] +
                            tmp[i][j + 2] +
                            ByteFinal.flag[id] * 0x80;
        } else if (id <= MAX_BYTES) {
          tmp[i][j] <== ChunkFinal.flag[i] * LenBytes.bytes[63 - j];
          fmt_msg[i][j] <== tmp[i][j] +
                            ByteFinal.flag[id] * 0x80;
        } else {
          fmt_msg[i][j] <== ChunkFinal.flag[i] * LenBytes.bytes[63 - j];
        }
      // if not in the last two bytes but under max length, possibly part of message
      } else if (id < MAX_BYTES) {
        tmp[i][j] <== (1 - ByteFinalBeyond.psum[id]) * msg[id];
        fmt_msg[i][j] <== tmp[i][j] +
                          ByteFinal.flag[id] * 0x80;
      } else if (id <= MAX_BYTES) {
        fmt_msg[i][j] <== ByteFinal.flag[id] * 0x80;
      } else {
        fmt_msg[i][j] <== 0;
      }
    }
  }
}

// hash on dynamic length input
template SHA256(MAX_BYTES) {
  /* inputs and outputs */
  // input is the message as an array of bytes
  // this is followed by the actual number of bytes in the messags
  signal input msg[MAX_BYTES];
  signal input real_byte_len; // real length in bytes
  signal output hash[32];
  /* constants */
  // initial hash values
  var H[8] = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  ];
  /* components */
  component fmt = SHA256Format(MAX_BYTES);
  fmt.msg <== msg;
  fmt.real_byte_len <== real_byte_len;

  var max_fmt_msg_chunks = 1 + ((8 + MAX_BYTES) \ 64);
  component SHAChunks[max_fmt_msg_chunks];
  for (var i = 0; i < max_fmt_msg_chunks; i++) {
    SHAChunks[i] = SHAChunk();
    SHAChunks[i].chunk_bytes <== fmt.fmt_msg[i];
    // if the first chunk, use the initial hash values
    if (i == 0) {
      for (var j = 0; j < 8; j++) {
        for (var k = 0; k < 32; k++) {
          SHAChunks[i].prev_hash_bits[j][k] <== (H[j] >> (31 - k)) & 1;
        }
      }
    } else {
      SHAChunks[i].prev_hash_bits <== SHAChunks[i - 1].hash_bits;
    }
  }
  // group rows (purely a relabeling)
  signal hashes[max_fmt_msg_chunks][32];
  for (var i = 0; i < max_fmt_msg_chunks; i++) {
    hashes[i] <== SHAChunks[i].hash_bytes;
  }
  // select proper SHAChunk output based on real_num_chunks
  // this can be optimized later by packing bytes, but it is minor cost
  component RowSelect = SigRowSelect(max_fmt_msg_chunks, 32);
  RowSelect.rows <== hashes;
  RowSelect.index <== fmt.real_num_chunks;
  for (var j = 0; j < 32; j++) {
    hash[j] <== RowSelect.sel_row[j];
  }
}

// given an input of fixed size, compute the hash
// then convert the hash to single field element
// and compare it to the expected hash
template SHA256InputConfirm(BYTES) {
  signal input msg[BYTES];
  signal input expected;
  // initial hash values
  var H[8] = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  ];
  var total_chunks = 1 + ((8 + BYTES) \ 64);
  // format message (no real constraints here, just variable relabeling)
  signal padded_msg[total_chunks][64];
  for (var i = 0; i < total_chunks; i++) {
    for (var j = 0; j < 64; j++) {
      if (i * 64 + j < BYTES) {
        padded_msg[i][j] <== msg[i * 64 + j];
      } else if (i * 64 + j == BYTES) {
        padded_msg[i][j] <== 0x80;
      } else if (j % 64 >= 56) {
        padded_msg[i][j] <== ((BYTES * 8) >> (8 * (63 - j))) % 256; 
      } else {
        padded_msg[i][j] <== 0;
      }
    }
  }
  // hash chunks
  component SHAChunks[total_chunks];
  for (var i = 0; i < total_chunks; i++) {
    SHAChunks[i] = SHAChunk();
    SHAChunks[i].chunk_bytes <== padded_msg[i];
    // if the first chunk, use the initial hash values
    if (i == 0) {
      for (var j = 0; j < 8; j++) {
        for (var k = 0; k < 32; k++) {
          SHAChunks[i].prev_hash_bits[j][k] <== (H[j] >> (31 - k)) & 1;
        }
      }
    } else {
      SHAChunks[i].prev_hash_bits <== SHAChunks[i - 1].hash_bits;
    }
  }
  // check equality between first 253 bits of sha and expected
  var lc = 0;
  for (var i = 0; i < 253; i++) {
    lc += SHAChunks[total_chunks - 1].hash_bits[i \ 32][31 - (i % 32)] * (1 << i);
  }
  lc === expected;
}