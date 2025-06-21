pragma circom 2.0.0;

// given an N-bit number,
// returns a list of N bits
template SigToBinary(N) {
  signal input val;
  signal output bits[N];
  var lc = 0;
  var e = 1;
  for (var i = 0; i < N; i++) {
    bits[i] <-- (val >> i) & 1;
    bits[i] * (1 - bits[i]) === 0;
    lc += bits[i] * e;
    e *= 2;
  }
  lc === val;
}

template IsNBits(N) {
  signal input val;
  signal bits[N];
  var lc = 0;
  var e = 1;
  for (var i = 0; i < N; i++) {
    bits[i] <-- (val >> i) & 1;
    bits[i] * (1 - bits[i]) === 0;
    lc += bits[i] * e;
    e *= 2;
  }
  lc === val;
}

// assert that a signal is an N bit signed integer (+ 1 bit for sign)
template IsSignedNBits(N) {
  signal input val;
  signal bits[N + 1];
  var lc = 0;
  var e = 1;
  var top = 1 << N;
  for (var i = 0; i <= N; i++) {
    bits[i] <-- ((val + top) >> i) & 1;
    bits[i] * (1 - bits[i]) === 0;
    lc += bits[i] * e;
    e *= 2;
  }
  lc === val + top;
}

template SigToBinaryBigEndian(N) {
  signal input val;
  signal output bits[N];
  var lc = 0;
  for (var i = 0; i < N; i++) {
    bits[i] <-- (val >> (N - 1 - i)) & 1;
    bits[i] * (1 - bits[i]) === 0;
    lc += bits[i] * (1 << (N - 1 - i));
  }
  lc === val;
}

// given an N-bit signal,
// returns a list of ceil(N / 8) bytes
template SigToBytes(N) {
  signal input val;
  signal output bytes[1 + (N - 1) \ 8];
  component ToBinary = SigToBinary(N);
  ToBinary.val <== val;
  for (var i = 0; i < 1 + (N - 1) \ 8; i++) {
    var lc = 0;
    for (var j = 0; j < 8; j++) {
      if (i * 8 + j < N) {
        lc += ToBinary.bits[i * 8 + j] * (1 << j);
      }
    }
    bytes[i] <== lc;
  }
}

// pack N bits into a single field element
template BinToBigEndian(N) {
  signal input bits[N];
  signal output val;
  var lc = 0;
  for (var i = 0; i < N; i++) {
    lc += bits[i] * (1 << (N - 1 - i));
  }
  val <== lc;
}

// N words with n bits each, turn them into a single bit array of N * n bits
// LSB to MSB
template WordArrToBitArr(N, n) {
  signal input A[N];
  signal output B[N * n];
  component ToBin[N];
  for (var i = 0; i < N; i++) {
    ToBin[i] = SigToBinary(n);
    ToBin[i].val <== A[i];
    for (var j = 0; j < n; j++) {
      B[n * i + j] <== ToBin[i].bits[j];
    }
  }
}