pragma circom 2.0.0;

include "../util/bits.circom";

// utility functions for working with arrays

// get slice of array a starting at L and ending at R - 1
// result is stored in array b
// this requires no constraints and is just a helper function
template Slice(N, L, R) {
  signal input a[N];
  signal output b[R - L];
  for (var i = L; i < R; i++) {
    b[i - L] <== a[i];
  }
}

// given an input of length N
// and a flag
// either copy it or shift it by M
// the shift should occur if the flag is set
template SigCondShiftLeft(N, M) {
  signal input a[N];
  signal input flag;
  signal output b[N];
  for (var i = 0; i < N; i++) {
    if (i + M < N) {
      b[i] <-- (flag ? a[i + M] : a[i]);
      b[i] - a[i] === flag * (a[i + M] - a[i]);
    } else {
      b[i] <== (1 - flag) * a[i];
    }
  }
}

template SigCondShiftAndPack(N, N2, M) {
  signal input a[N];
  signal input flag;
  signal output b[N2];
  signal tmp[N];
  for (var i = 0; i < N - 1; i++) {
    tmp[i] <-- (flag ? a[i + 1] : a[i]);
    tmp[i] - a[i] === flag * (a[i + 1] - a[i]);
  }
  tmp[N - 1] <-- (1 - flag) * a[N - 1];
  for (var i = 0; i < N2; i++) {
    if (2 * i + 1 < N) {
      b[i] <== (1 << M) * tmp[2 * i] + tmp[2 * i + 1];
    } else {
      b[i] <== (1 << M) * tmp[2 * i];
    }
  }
}

// given an input of length N, shift it between 0 and M - 1 spaces
// actually shift distance is a signal dist
// does not perform bounds checking
// content beyond N is 0s
template SigBarrelShift(N, M) {
  signal input a[N];
  signal input dist;
  signal output b[N];
  // get ceil(log_2(M))
  var logM = 0;
  var tmpM = M;
  while (tmpM > 0) {
    tmpM = tmpM \ 2;
    logM += 1;
  }
  // turn dist into a binary array
  component ToBinary = SigToBinary(logM);
  ToBinary.val <== dist;
  // repeat ceil(log_2(M)) times
  component CondShift[logM];
  for (var i = 0; i < logM; i++) {
    CondShift[i] = SigCondShiftLeft(N, 1 << i);
    CondShift[i].flag <== ToBinary.bits[i];
    if (i == 0) {
      CondShift[i].a <== a;
    } else {
      CondShift[i].a <== CondShift[i - 1].b;
    }
    if (i == logM - 1) {
      b <== CondShift[i].b;
    }
  }
}

// given a byte array of length N
// and a subarray b of length M
// both assumed to be verified to be byte arrays elsewhere
// validate the claim that the subarray matches a[dist, dist + M)
// assume N - M > 16
// TO DO, can be made even more efficient, but this is such a low order cost for us for now
// N2 through N16 is a circom hack to allow this to compile
template SigSliceMatch(N, M, N2, N4, N8, N16) {
  signal input a[N];
  signal input b[M];
  signal input dist;
  // get ceil(log_2(N - M))
  var lg = 0;
  var tmp = N - M;
  while (tmp > 0) {
    tmp = tmp \ 2;
    lg += 1;
  }
  // turn dist into a binary array
  component ToBinary = SigToBinary(lg);
  ToBinary.val <== dist;
  // shrink in circuit
  // repeat 4 times, shift and pack
  // unrolled because circom doesn't like it otherwise
  component CSP0 = SigCondShiftAndPack(N, N2, 8);
  CSP0.a <== a; CSP0.flag <== ToBinary.bits[0];
  component CSP1 = SigCondShiftAndPack(N2, N4, 16);
  CSP1.a <== CSP0.b; CSP1.flag <== ToBinary.bits[1];
  component CSP2 = SigCondShiftAndPack(N4, N8, 32);
  CSP2.a <== CSP1.b; CSP2.flag <== ToBinary.bits[2];
  component CSP3 = SigCondShiftAndPack(N8, N16, 64);
  CSP3.a <== CSP2.b; CSP3.flag <== ToBinary.bits[3];
  // shift packed elements
  component CondShift[lg - 4];
  for (var i = 0; i + 4 < lg; i++) {
    CondShift[i] = SigCondShiftLeft(N16, 1 << i);
    CondShift[i].flag <== ToBinary.bits[i + 4];
    if (i == 0) {
      CondShift[i].a <== CSP3.b;
    } else {
      CondShift[i].a <== CondShift[i - 1].b;
    }
  }
  // check that CondShift[logM - 5].b matches b when bytes are repacked
  for (var i = 0; i + 16 < M; i += 16) {
    var sum = 0;
    for (var j = 0; j < 16; j++) {
      sum += (1 << (8 * (15 - j))) * b[i + j];
    }
    CondShift[lg - 5].b[i \ 16] === sum;
  }
  var sum = 0;
  for (var i = 16 * (M \ 16); i < M; i++) {
    sum += (1 << (8 * (15 - (i % 16)))) * b[i];
  }
  // verify that the rest fits in the remaining bytes
  component ToBinaryFinal = IsNBits(8 * (16 - (M % 16)));
  ToBinaryFinal.val <== CondShift[lg - 5].b[M \ 16] - sum;
}

// given a max input size N
// and a signal input index
// return a 1D array of size N with all 0s except for the index'th element
template SigBoolSelect(N) {
  /* inputs and outputs */
  signal input index;
  signal output flag[N];
  /* internal signals */
  // lightweight iszero, any value if the index matches, 0 otherwise
  // this forces non-matching indices to be 0
  var sum = 0;
  for (var i = 0; i < N; i++) {
    flag[i] <-- (i == index ? 1 : 0);
    flag[i] * (i - index) === 0;
    sum += flag[i];
  }
  // sum of elements in a must be 1
  // since only one index matches, this forces the matching index to be 1
  sum === 1;
}

// given a 2D of size N x M and a signal input index
// return the index'th row
// this should be used when index is not a constant
template SigRowSelect(N, M) {
  /* inputs and outputs */
  signal input rows[N][M];
  signal input index;
  signal output sel_row[M];
  /* internal signals */
  component select = SigBoolSelect(N);
  select.index <== index;
  signal tmp[N][M];
  for (var i = 0; i < M; i++) {
    var sum = 0;
    for (var j = 0; j < N; j++) {
      tmp[j][i] <== rows[j][i] * select.flag[j];
      sum += tmp[j][i];
    }
    sel_row[i] <== sum;
  }
}

// does not generate constraints
// takes an array of size N
// returns an array of size N of prefix sums
template PrefixSum(N) {
  signal input arr[N];
  signal output psum[N];
  var sum = 0;
  for (var i = 0; i < N; i++) {
    sum += arr[i];
    psum[i] <== sum;
  }
}

// assert that the first real_len elements of a are equal to the first real_len elements of b
// assume inputs are the same size and real_len <= N
// also if STRICT != 0 assert that the remaining elements of b are 0
template AssertPrefixMatch(N, STRICT) {
  signal input a[N];
  signal input b[N];
  signal input real_len;
  // SigBoolSelect + PrefixSum to mask out elements we don't care about
  component select = SigBoolSelect(N + 1);
  select.index <== real_len;
  component prefixsum = PrefixSum(N + 1);
  prefixsum.arr <== select.flag;
  // assert that (1 - prefixsum.psum[i]) * (a[i] - b[i]) === 0 for all i < N
  // this checks that a[i] === b[i] for all i < real_len
  for (var i = 0; i < N; i++) {
    (1 - prefixsum.psum[i]) * (a[i] - b[i]) === 0;
  }
  if (STRICT) {
    // assert that prefixsum.psum[i] * b[i] === 0 for all i >= N
    // this checks that b[i] === 0 for all i >= real_len
    for (var i = 0; i < N; i++) {
      prefixsum.psum[i] * b[i] === 0;
    }
  }
}

// warning! this assumes all elements of bytes get range-checked somewhere else in the circuit
// this also ensures non-malleability of the compressed inputs
template AssertPubDecompress(N) {
  signal input packs[1 + (N - 1) \ 31];
  signal input bytes[N];
  // decompress the bytes
  for (var i = 0; i < 1 + (N - 1) \ 31; i++) {
    var lc = 0;
    for (var j = 0; j < 31; j++) {
      if (i * 31 + j < N) {
        lc += bytes[i * 31 + j] * (1 << (8 * j));
      }
    }
    packs[i] === lc;
  }
  // ensure non-malleability
  // circom optimizes out 0 * packs[i] === 0, so we will do this instead
  var tmp = 0;
  for (var i = 0; i < 1 + (N - 1) \ 31; i++) {
    tmp = tmp + packs[i];
  }
  signal m;
  m <== tmp * tmp;
}

// boilerplate from circomlib
// template IsZero() {
//   signal input in;
//   signal output out;
//   signal inv;
//   inv <-- in!=0 ? 1/in : 0;
//   out <== -in*inv +1;
//   in*out === 0;
// }
