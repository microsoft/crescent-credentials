pragma circom 2.0.0;

include "../util/bits.circom";

function varmax(a, b) {
  if (a > b) {
    return a;
  } else {
    return b;
  }
}

function varmin(a, b) {
  if (a < b) {
    return a;
  } else {
    return b;
  }
}

// large integer addition
// given two large integers A and B
// where A is an large integer of Na limbs
// and B is an large integer of Nb limbs
// compute A + B as an large integer of max(Na, Nb) limbs of size max(na, nb) + 1
template BigAdd(Na, Nb) {
  signal input A[Na];
  signal input B[Nb];
  signal output C[varmax(Na, Nb)];
  for (var i = 0; i < varmin(Na, Nb); i++) {
    C[i] <== A[i] + B[i];
  }
  if (Na > Nb) {
    for (var i = Nb; i < Na; i++) {
      C[i] <== A[i];
    }
  } else {
    for (var i = Na; i < Nb; i++) {
      C[i] <== B[i];
    }
  }
}

// large integer multiplication
// given two large integers A and B
// where A is an large integer of Na limbs
// and B is an large integer of Nb limbs
// compute A * B as an large integer of Na + Nb - 1 limbs
template BigMul(Na, Nb) {
  signal input A[Na];
  signal input B[Nb];
  signal output C[Na + Nb - 1];
  var AB[Na + Nb - 1];
  // first calculate C without constraints (polynomial multiplication)
  for (var i = 0; i < Na + Nb - 1; i++) {
    AB[i] = 0;
  }
  for (var i = 0; i < Na; i++) {
    for (var j = 0; j < Nb; j++) {
      AB[i + j] = AB[i + j] + A[i] * B[j];
    }
  }
  for (var i = 0; i < Na + Nb - 1; i++) {
    C[i] <-- AB[i];
  }
  // now add constraints to ensure that C is the correct result
  var S_A[Na + Nb - 1]; // A as a polynomial evaluated at 0, 1, 2, ...
  var S_B[Na + Nb - 1]; // B as a polynomial evaluated at 0, 1, 2, ...
  var S_C[Na + Nb - 1]; // C as a polynomial evaluated at 0, 1, 2, ...
  for (var i = 0; i < Na + Nb - 1; i++) {
    S_A[i] = 0; S_B[i] = 0; S_C[i] = 0;
    for (var j = 0; j < Na; j++) {
      S_A[i] = S_A[i] + A[j] * (i ** j);
    }
    for (var j = 0; j < Nb; j++) {
      S_B[i] = S_B[i] + B[j] * (i ** j);
    }
    for (var j = 0; j < Na + Nb - 1; j++) {
      S_C[i] = S_C[i] + C[j] * (i ** j);
    }
    S_C[i] === S_A[i] * S_B[i];
  }
}

// given large integer A with N limbs
// convert to a normalized large integer (N + 1) limbs with n bits per limb
// helper function, doesn't generate constraints
function BigVarNormalize(N, n, A) {
  var B[200]; // N + 1
  var r = 0;
  for (var i = 0; i < N; i++) {
    B[i] = ((A[i] + r) % (2 ** n));
    r = (A[i] + r) >> n;
  }
  B[N] = r;
  return B;
}

// multiply two large integers A and B and normalize the result (carries)
function BigVarMul(Na, Nb, A, B, n) {
  var C[200]; // Na + Nb - 1
  for (var i = 0; i < Na + Nb - 1; i++) {
    C[i] = 0;
  }
  for (var i = 0; i < Na; i++) {
    for (var j = 0; j < Nb; j++) {
      C[i + j] = C[i + j] + A[i] * B[j];
    }
  }
  return BigVarNormalize(Na + Nb - 1, n, C);
}

// given large integers A and M (A potentially not normalized)
// compute R = A % M and Q = A / M
// where R is an large integer of Nm limbs
// and Q is an large integer of Na - Nm + 1 limbs
// does not generate constraints, just computes the result
// TO DO, maybe turn this into a function instead of a template to avoid warnings
template BigVarDiv(Na, Nm, n) {
  signal input A[Na];
  signal input M[Nm];
  signal output R[Nm];
  signal output Q[Na - Nm + 1];
  var ANorm[200] = BigVarNormalize(Na, n, A); // Na + 1
  var r = 0;
  for (var ii = 0; ii <= Na - Nm; ii++) {
    var i = Na - Nm - ii;
    // determine the ith limb of Q by binary search
    // this could be swapped for something faster but its not the bottleneck
    var l = 0;
    var h = 2 ** n;
    while (l + 1 < h) {
      var m = (l + h) / 2;
      var tmp[200] = BigVarMul(Nm, 1, M, [m], n); // Nm + 1
      // check if tmp <= ANorm[i:]
      var larger = 0;
      var done = 0;
      for (var jj = 0; jj <= Nm && done == 0; jj++) {
        var j = Nm - jj;
        if ((i + j > Na && tmp[j] > 0) ||
            (i + j <= Na && tmp[j] > ANorm[i + j])) {
          larger = 1;
          done = 1;
        } else if (i + j <= Na && tmp[j] < ANorm[i + j]) {
          done = 1;
        }
      }
      if (larger == 0) {
        l = m;
      } else {
        h = m;
      }
    }
    Q[i] <-- l;
    // subtract M * Q[i] from a slice of ANorm
    var tmp[200] = BigVarMul(Nm, 1, M, [Q[i]], n); // Nm + 1
    for (var j = 0; j < Nm + 1 && i + j < Na + 1; j++) {
      if (ANorm[i + j] < tmp[j]) {
        ANorm[i + j] = ANorm[i + j] + (2 ** n) - tmp[j];
        tmp[j + 1] = tmp[j + 1] + 1;
      } else {
        ANorm[i + j] = ANorm[i + j] - tmp[j];
      }
    }
  }
  // copy the lower Nm limbs of ANorm into R
  for (var i = 0; i < Nm; i++) {
    R[i] <-- ANorm[i];
  }
}

template BigLimbCheck(N, n) {
  signal input A[N];
  component isbits[N];
  for (var i = 0; i < N; i++) {
    isbits[i] = IsNBits(n);
    isbits[i].val <== A[i];
  }
}

template BigLimbToBits(N, n) {
  signal input A[N];
  signal output B[N * n];
  component ToBits[N];
  for (var i = 0; i < N; i++) {
    ToBits[i] = SigToBinary(n);
    ToBits[i].val <== A[i];
    for (var j = 0; j < n; j++) {
      B[i * n + j] <== ToBits[i].bits[j];
    }
  }
}

template BigIsZero(N, n, m) {
  // check if a number is 0 with:
  // N limbs
  // n clean bits per limb
  // m total bits
  // limbs can be negative
  signal input A[N];
  // get number of limbs that can be grouped together
  var g = (253 - (m - n) - 1) \ n;
  var l = (N - 1) \ g;
  signal Zero[l];
  for (var i = 0; g * i < N; i++) {
    var lc = 0;
    if (i != 0) {
      lc = Zero[i - 1];
    }
    for (var j = 0; j < g && g * i + j < N; j++) {
      lc += A[g * i + j] * (2 ** (n * j));
    }
    if (g * (i + 1) < N) {
      Zero[i] <== lc / (2 ** (n * g));
    } else {
      lc === 0;
    }
  }
  // check that all Zero[i] are m - n bit signed integers
  component safe[l];
  for (var i = 0; i < l; i++) {
    safe[i] = IsSignedNBits(m - n);
    safe[i].val <== Zero[i];
  }
}

// only use after a single multiplication, not generic!
template BigEq(N, n) {
  signal input A[N];
  signal input B[N];
  // get ceil log2 N
  var logN = 0;
  var tmp = N;
  while (tmp > 0) {
    logN++;
    tmp >>= 1;
  }
  var k = ((253 - logN) \ n) - 1;
  var l = ((N - 1) \ k);
  signal Zero[l];
  for (var i = 0; k * i < N; i++) {
    var lc = 0;
    if (i != 0) {
      lc = Zero[i - 1];
    }
    for (var j = 0; j < k && k * i + j < N; j++) {
      lc += (A[k * i + j] - B[k * i + j]) * (2 ** (n * j));
    }
    if (k * (i + 1) < N) {
      Zero[i] <== lc / (2 ** (n * k));
    } else {
      lc === 0;
    }
  }
  component safe[l];
  for (var i = 0; i < l; i++) {
    safe[i] = IsSignedNBits(n + logN);
    safe[i].val <== Zero[i];
  }
}

// given large integers A and M
// where A is an large integer of Na limbs
// and M is an large integer of Nm limbs
// compute R = A % M with some flexibility in the size of C
// namely R can be larger than M, but it must fit within Nm limbs of size n
template BigRelaxMod(Na, Nm, n) {
  signal input A[Na];
  signal input M[Nm];
  signal output R[Nm];
  signal Q[Na - Nm + 1];
  // A = Q * M + R
  // first calculate Q and R without constraints via long division
  component longDiv = BigVarDiv(Na, Nm, n);
  longDiv.A <== A;
  longDiv.M <== M;
  Q <== longDiv.Q;
  R <== longDiv.R;
  // check that A = Q * M + R
  component mul = BigMul(Na - Nm + 1, Nm);
  mul.A <== Q;
  mul.B <== M;
  component add = BigAdd(Na, Nm);
  add.A <== mul.C;
  add.B <== R;
  // check equality
  component eq = BigEq(Na, n);
  eq.A <== add.C;
  eq.B <== A;
  // check that R fits in Nm limbs of with n bits each
  component limbCheckR = BigLimbCheck(Nm, n);
  limbCheckR.A <== R;
  // check that Q fits in Na - Nm + 1 limbs of with n bits each
  component limbCheckQ = BigLimbCheck(Na - Nm + 1, n);
  limbCheckQ.A <== Q;
}

template BigModMul(N, n) {
  signal input A[N];
  signal input B[N];
  signal input M[N];
  signal output C[N];
  component mul = BigMul(N, N);
  mul.A <== A;
  mul.B <== B;
  component mod = BigRelaxMod(N + N - 1, N, n);
  mod.A <== mul.C;
  mod.M <== M;
  C <== mod.R;
}

// large integer modular exponentiation
// given a large integer A and modulus M, both as arrays of N limbs of size n
// compute A^e mod M for some small integer e (typically 65537)
template BigModExp(N, n, e) {
  signal input A[N];
  signal input M[N];
  signal output C[N];
  // determine number of intermediate signals and components to use
  var et = e;
  var squareCount = 0;
  var resCount = 0;
  while (et > 0) {
    if (et % 2 == 1) {
      resCount++;
    }
    if (et != 1) {
      squareCount++;
    }
    et >>= 1;
  }
  // create modMul components and tmp variables
  component modmul[squareCount + resCount - 1];
  signal B[squareCount + 1][N];
  signal R[resCount][N];
  for (var i = 0; i < N; i++) {
    B[0][i] <== A[i];
  }
  var s = 0;
  var r = 0;
  var first = 0;
  while (e > 0) {
    if (e % 2 == 1) {
      if (first == 0) {
        for (var i = 0; i < N; i++) {
          R[0][i] <== B[s][i];
        }
        first = 1;
      } else {
        modmul[s + r] = BigModMul(N, n);
        modmul[s + r].A <== R[r];
        modmul[s + r].B <== B[s];
        modmul[s + r].M <== M;
        R[r + 1] <== modmul[s + r].C;
        r++;
      }
    }
    if (e != 1) {
      modmul[s + r] = BigModMul(N, n);
      modmul[s + r].A <== B[s];
      modmul[s + r].B <== B[s];
      modmul[s + r].M <== M;
      B[s + 1] <== modmul[s + r].C;
      s++;
    }
    e >>= 1;
  }
  C <== R[r];
}

// modulus is M limbs of size n
// other inputs are N limbs of size n
// ensure proper bitness of A, P, and Q
// prove that A = P * Q and P and Q aren't 1
template NonTrivialFact(M, N, n) {
  signal input A[M];
  signal input P[N];
  signal input Q[N];
  var B = 2 * N - 1;
  if (M > B) {
    B = M;
  }
  // check that A = P * Q
  component mul = BigMul(N, N);
  mul.A <== P;
  mul.B <== Q;
  // get ceil log2 N
  // this gets used a lot (TO DO, lift to a function)
  var logN = 0;
  var tmp = N;
  while (tmp > 0) {
    logN++;
    tmp >>= 1;
  }
  component zero = BigIsZero(B, n, 2 * n + logN);
  for (var i = 0; i < B; i++) {
    if (i < 2 * N - 1 && i < M) {
      zero.A[i] <== mul.C[i] - A[i];
    } else if (i >= 2 * N - 1) {
      zero.A[i] <== - A[i];
    } else {
      zero.A[i] <== mul.C[i];
    }
  }
  // reduce limbs of A, P, and Q to bits
  component ModToBits;
  component FactToBits[2];
  ModToBits = BigLimbCheck(M, n);
  ModToBits.A <== A;
  FactToBits[0] = BigLimbToBits(N, n);
  FactToBits[0].A <== P;
  FactToBits[1] = BigLimbToBits(N, n);
  FactToBits[1].A <== Q;
  // check that P and Q aren't 1
  // to do this, check that sum of bits of P is > 1 and same with Q
  var sum[2] = [-1, -1];
  for (var i = 0; i < N * n; i++) {
    sum[0] = sum[0] + FactToBits[0].B[i];
    sum[1] = sum[1] + FactToBits[1].B[i];
  }
  signal inv[2];
  inv[0] <-- 1 / sum[0];
  inv[1] <-- 1 / sum[1];
  // check that sum * inv === 1
  sum[0] * inv[0] === 1;
  sum[1] * inv[1] === 1;
}