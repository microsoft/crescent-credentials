pragma circom 2.0.0;

include "arith.circom";
include "../util/bits.circom";
include "../util/buffer.circom";
include "../lookup/rom12.circom";

// elliptic curve arithmetic functions for NIST P-256
// as 32 bit limbs,
// p = [ 4294967295, 4294967295, 4294967295, 0, 0, 0, 1, 4294967295 ]
/*
G
[ 3633889942, 4104206661,  770388896, 1996717441,
  1671708914, 4173129445, 3777774151, 1796723186]
[  935285237, 3417718888, 1798397646,  734933847,
  2081398294, 2397563722, 4263149467, 1340293858]
H = 2^128 G
[ 3616128389, 1472745417, 3264735939, 4231397245,
  2294707822, 4221054933, 4007353959, 1149072283]
[ 1927437106,  209597385, 2818237696, 1026857877,
   977973239, 3777928597, 2202087918,  759702955]
G + H
[  706557567,  328506515,  436867511, 4018126123, 
  3105750112, 3720742539, 2325508863, 4019525938]
[ 1937168552,  425735591, 2513049408,  588790536,
    36446620, 3253639175, 2109418651, 1629396931]
*/

// N limbs
// n bits max per limb (excluding top limb)
// k bits for top limb
// limbs can be negative!
template DoLimbsCombineToKBits(N, n, k) {
  signal input A[N];
  component isbits[N - 1];
  for (var i = 0; i < N - 1; i++) {
    isbits[i] = IsSignedNBits(n);
    isbits[i].val <== A[i];
  }
  component top = IsSignedNBits(k);
  top.val <== A[N - 1];
}

// hacky and assumes 32 bit limbs, if we want to change N we need to modify p here
template MulO(N) {
  // multiply an integer with N limbs by curve.order
  signal input A[N];
  signal output C[N + 7];
  var sums[N + 7];
  var o[8] = [ 4234356049, 4089039554, 2803342980, 3169254061,
               4294967295, 4294967295,          0, 4294967295 ];
  for (var i = 0; i < N + 7; i++) { sums[i] = 0; }
  for (var i = 0; i < N; i++) {
    for (var j = 0; j < 8; j++) {
      sums[i + j] += A[i] * o[j];
    }
  }
  for (var i = 0; i < N + 7; i++) {
    C[i] <== sums[i];
  }
}

// hacky and assumes 32 bit limbs, if we want to change N we need to modify p here
template MulP(N) {
  // multiply an integer with N limbs by curve.p
  signal input A[N];
  signal output C[N + 7];
  var sums[N + 7];
  var p[8] = [ 4294967295, 4294967295, 4294967295, 0, 0, 0, 1, 4294967295 ];
  for (var i = 0; i < N + 7; i++) { sums[i] = 0; }
  for (var i = 0; i < N; i++) {
    for (var j = 0; j < 8; j++) {
      sums[i + j] += A[i] * p[j];
    }
  }
  for (var i = 0; i < N + 7; i++) {
    C[i] <== sums[i];
  }
}

template WeakCurveMod(N) {
  signal input x[N];
  signal output r[8];
  var p[14][8] = [
    [1, 0, 0, 4294967295, 4294967295, 4294967295, 4294967294, 0],
    [0, 1, 0, 0, 4294967295, 4294967295, 4294967295, 4294967294],
    [4294967295, 0, 1, 1, 4294967295, 4294967294, 0, 4294967294],
    [4294967294, 4294967295, 0, 3, 0, 4294967295, 0, 4294967294],
    [4294967294, 4294967294, 4294967295, 2, 2, 0, 1, 4294967294],
    [4294967294, 4294967294, 4294967294, 1, 2, 2, 2, 4294967294],
    [4294967295, 4294967294, 4294967294, 4294967295, 0, 2, 3, 0],
    [0, 4294967295, 4294967294, 4294967294, 4294967295, 0, 2, 3],
    [3, 0, 4294967295, 4294967291, 4294967294, 4294967295, 4294967293, 4],
    [5, 3, 0, 4294967290, 4294967291, 4294967294, 4294967290, 2],
    [2, 5, 3, 4294967294, 4294967289, 4294967291, 4294967292, 4294967292],
    [4294967293, 2, 5, 6, 4294967293, 4294967289, 4294967294, 4294967288],
    [4294967289, 4294967293, 2, 12, 5, 4294967293, 0, 4294967287],
    [4294967287, 4294967289, 4294967293, 11, 11, 5, 6, 4294967287]
  ];
  //log(N);
  var sums[8];
  for (var i = 0; i < 8; i++) { sums[i] = x[i]; }
  for (var i = 8; i < N; i++) {
    for (var j = 0; j < 8; j++) {
      sums[j] += x[i] * p[i - 8][j];
    }
  }
  for (var i = 0; i < 8; i++) { r[i] <== sums[i]; }
}

template CheckSlope() {
  signal input Px[8]; signal input Py[8];
  signal input Qx[8]; signal input Qy[8];
  signal input Rx[8]; signal input Ry[8];
  signal input a[3]; // advice (66? bits)
  // ((Q.y - P.y) * (R.x - Q.x) + (R.y + Q.y) * (Q.x - P.x))
  component Mul[2];
  Mul[0] = BigMul(8, 8);
  Mul[1] = BigMul(8, 8);
  for (var i = 0; i < 8; i++) {
    Mul[0].A[i] <== Qy[i] - Py[i];
    Mul[0].B[i] <== Rx[i] - Qx[i];
    Mul[1].A[i] <== Ry[i] + Qy[i];
    Mul[1].B[i] <== Qx[i] - Px[i];
  }
  component WeakMod = WeakCurveMod(15);
  for (var i = 0; i < 15; i++) {
    WeakMod.x[i] <== Mul[0].C[i] + Mul[1].C[i];
  }
  component CMul = MulP(3); CMul.A <== a;
  component Zero = BigIsZero(10, 32, 102);
  for (var i = 0; i < 8; i++) {
    Zero.A[i] <== WeakMod.r[i] - CMul.C[i];
  }
  Zero.A[8] <== -CMul.C[8];
  Zero.A[9] <== -CMul.C[9];
}

template CheckOnCurve() {
  signal input x[8]; signal input y[8];
  signal input a[4]; // advice (101 bits)
  // check y^2 - x^3 - 3x - ? == 0 mod p
  component Y2 = BigMul(8, 8);
  Y2.A <== y;
  Y2.B <== y;
  component X2 = BigMul(8, 8);
  X2.A <== x;
  X2.B <== x;
  component X3 = BigMul(15, 8);
  X3.A <== X2.C;
  X3.B <== x;
  component WeakMod = WeakCurveMod(22);
  var b[8] = [668098635, 1003371582, 3428036854, 1696401072, 1989707452, 3018571093, 2855965671, 1522939352];
  for (var i = 0; i < 8; i++) {
    WeakMod.x[i] <== Y2.C[i] - X3.C[i] + 3 * x[i] - b[i];
  }
  for (var i = 8; i < 15; i++) {
    WeakMod.x[i] <== Y2.C[i] - X3.C[i];
  }
  for (var i = 15; i < 22; i++) {
    WeakMod.x[i] <== -X3.C[i];
  }
  component CMul = MulP(4); CMul.A <== a;
  component Zero = BigIsZero(11, 32, 136);
  for (var i = 0; i < 11; i++) {
    if (i < 8) {
      Zero.A[i] <== WeakMod.r[i] - CMul.C[i];
    } else {
      Zero.A[i] <== -CMul.C[i];
    }
  }
}

// assumes 32 bits per limb
// Note, it is possible to decrease the number of bits per limb to optimize this a bit
template CheckAddFast() {
  signal input Px[8]; signal input Py[8];
  signal input Qx[8]; signal input Qy[8];
  signal input Rx[8]; signal input Ry[8];
  signal input a[3]; // advice (? bits)
  signal input b[4]; // advice (? bits)
  // check that Rx and Ry are 256 bit integers (N limbs of 256/N bits each)
  component Check256[2];
  Check256[0] = BigLimbCheck(8, 32);
  Check256[1] = BigLimbCheck(8, 32);
  Check256[0].A <== Rx;
  Check256[1].A <== Ry;
  // check that a is 66 bits (2 limbs of 32, one limb of 4)
  component CheckExtra0 = DoLimbsCombineToKBits(3, 32, 4);
  CheckExtra0.A <== a;
  // check that b is ? bits (2 limbs of 32, one limb of 8)
  // debug print b
  component CheckExtra1 = DoLimbsCombineToKBits(4, 32, 8);
  CheckExtra1.A <== b;
  // check constraints on addition
  component Slope = CheckSlope();
  Slope.Px <== Px; Slope.Py <== Py;
  Slope.Qx <== Qx; Slope.Qy <== Qy;
  Slope.Rx <== Rx; Slope.Ry <== Ry;
  Slope.a <== a;
  // check that Rx and Ry are on the curve
  component OnCurve = CheckOnCurve();
  OnCurve.x <== Rx; OnCurve.y <== Ry;
  OnCurve.a <== b;
}

// P, Q, and R are 2D points with N limbs
template CheckAdd(N) {
  signal input Px[N];
  signal input Py[N];
  signal input Qx[N];
  signal input Qy[N];
  signal input Rx[N];
  signal input Ry[N];
  signal input a[N + 1];
  // check that Rx, Ry, and a are 256 bit integers (N limbs of 256/N bits each)
  component Check256[2];
  Check256[0] = BigLimbCheck(N, 256 \ N);
  Check256[1] = BigLimbCheck(N, 256 \ N);
  Check256[0].A <== Rx;
  Check256[1].A <== Ry;
  // TO DO, check if 3 is right here or if it can be larger or smaller
  component CheckExtra = DoLimbsCombineToKBits(N + 1, 256 \ N, 3);
  CheckExtra.A <== a;
  // check that ((Q.y - P.y) * (R.x - Q.x) + (R.y + Q.y) * (Q.x - P.x)) - a * curve.p is 0
  component Mul[2];
  Mul[0] = BigMul(N, N);
  Mul[1] = BigMul(N, N);
  for (var i = 0; i < N; i++) {
    Mul[0].A[i] <== Qy[i] - Py[i];
    Mul[0].B[i] <== Rx[i] - Qx[i];
    Mul[1].A[i] <== Ry[i] + Qy[i];
    Mul[1].B[i] <== Qx[i] - Px[i];
  }
  component CMul = MulP(N + 1);
  CMul.A <== a;
  // get ceil log2 N
  var logN = 0;
  var tmp = N;
  while (tmp > 0) {
    logN++;
    tmp >>= 1;
  }
  // Mul[*].C has 2N - 1 limbs with 2n + lg(N) bits each
  component Zero = BigIsZero(2 * N, (256 \ N), 2 * (256 \ N) + logN);
  for (var i = 0; i < 2 * N - 1; i++) {
    Zero.A[i] <== Mul[0].C[i] + Mul[1].C[i] - CMul.C[i];
  }
  Zero.A[2 * N - 1] <== -CMul.C[2 * N - 1];
}

// ((3n * P.x * P.x + curve.a) * (R.x - P.x) + 2n * P.y * (R.y + P.y)) % curve.p == 0n;
template CheckDouble(N) {
  signal input Px[N];
  signal input Py[N];
  signal input Rx[N];
  signal input Ry[N];
  signal input a[2 * N + 1];
  // check that Rx and Ry are 256 bit integers (N limbs of 256/N bits each)
  component Check256[2];
  Check256[0] = BigLimbCheck(N, 256 \ N);
  Check256[1] = BigLimbCheck(N, 256 \ N);
  Check256[0].A <== Rx;
  Check256[1].A <== Ry;
  // check that a fits in 2N limbs (256/N bits per limb)
  // paying a few extra constraints here on the top limp, TO DO maybe clean this up later
  // TO DO, the sign bit should be universal across all limbs, so we are paying extra for it per limb here, maybe refactor later to remove it (minor cost)
  component CheckHigh = DoLimbsCombineToKBits(2 * N + 1, 256 \ N, 2);
  CheckHigh.A <== a;
  // check eqn
  component Mul[3];
  Mul[0] = BigMul(N, N); // Px * Px
  for (var i = 0; i < N; i++) {
    Mul[0].A[i] <== Px[i];
    Mul[0].B[i] <== Px[i];
  }
  Mul[1] = BigMul(2 * N - 1, N); // (3n * Px * Px + curve.a) * (Rx - Px)
  Mul[1].A[0] <== 3 * Mul[0].C[0] - 3;
  for (var i = 1; i < 2 * N - 1; i++) {
    Mul[1].A[i] <== 3 * Mul[0].C[i];
  }
  for (var i = 0; i < N; i++) {
    Mul[1].B[i] <== Rx[i] - Px[i];
  }
  Mul[2] = BigMul(N, N); // Py * (R.y + P.y)
  for (var i = 0; i < N; i++) {
    Mul[2].A[i] <== Py[i];
    Mul[2].B[i] <== Ry[i] + Py[i];
  }
  component CMul = MulP(2 * N + 1);
  CMul.A <== a;
  // get ceil log2 N
  var logN = 0;
  var tmp = N;
  while (tmp > 0) {
    logN++;
    tmp >>= 1;
  }
  // zero check
  component Zero = BigIsZero(3 * N, (256 \ N), 3 * (256 \ N) + 2 * logN + 1);
  for (var i = 0; i < 2 * N - 1; i++) {
    Zero.A[i] <== Mul[1].C[i] + 2 * Mul[2].C[i] - CMul.C[i];
  }
  for (var i = 2 * N - 1; i < 3 * N - 2; i++) {
    Zero.A[i] <== Mul[1].C[i] - CMul.C[i];
  }
  Zero.A[3 * N - 2] <== -CMul.C[3 * N - 2];
  Zero.A[3 * N - 1] <== -CMul.C[3 * N - 1];
}

// given K pairs (x,y) of N limbs, and an index
// return the Mth pair
template PointSelect(K, N) {
  signal input ix[K][N];
  signal input iy[K][N];
  signal input index;
  signal output x[N];
  signal output y[N];
  component select = SigBoolSelect(K);
  select.index <== index;
  signal tmpx[K][N];
  signal tmpy[K][N];
  for (var i = 0; i < N; i++) {
    var sumx = 0;
    var sumy = 0;
    for (var j = 0; j < K; j++) {
      tmpx[j][i] <== ix[j][i] * select.flag[j];
      tmpy[j][i] <== iy[j][i] * select.flag[j];
      sumx += tmpx[j][i];
      sumy += tmpy[j][i];
    }
    x[i] <== sumx;
    y[i] <== sumy;
  }
}

template EqZero() {
  signal input v;
  signal output r;
  signal i;
  r <-- v == 0 ? 1 : 0;
  i <-- v == 0 ? 0 : 1 / v;
  0 === v * r;
  1 - r === v * i;
  //log(v, r);
}

// check u0 * G + u1 * G' + u2 * Q + u3 * R is 0
// in the code below we call G' H
// take u0, u1, u2, and u3 as 128 bit integers
/* in each step we double and select based on the bits:
[u0, u1, u2, u3]
[0, 0, 0, 0] -> null <- free
[0, 0, 0, 1] -> R <- free
[0, 0, 1, 0] -> Q <- free
[0, 0, 1, 1] -> Q + R <- requires verification
[0, 1, 0, 0] -> G' <- free
[0, 1, 0, 1] -> G' + R <- requires verification
[0, 1, 1, 0] -> G' + Q <- requires verification
[0, 1, 1, 1] -> G' + Q + R <- requires verification
[1, 0, 0, 0] -> G <- free
[1, 0, 0, 1] -> G + R <- requires verification
[1, 0, 1, 0] -> G + Q <- requires verification
[1, 0, 1, 1] -> G + Q + R <- requires verification
[1, 1, 0, 0] -> G + G' <- free
[1, 1, 0, 1] -> G + G' + R <- requires verification
[1, 1, 1, 0] -> G + G' + Q <- requires verification
[1, 1, 1, 1] -> G + G' + Q + R <- requires verification
This adds an additional 10 point additions
But it drops the total number of point additions/multiplications in the core loop from 256 to 128. 
*/

/*
G: [
  3633889942, 4104206661,
   770388896, 1996717441,
  1671708914, 4173129445,
  3777774151, 1796723186
] [
   935285237, 3417718888,
  1798397646,  734933847,
  2081398294, 2397563722,
  4263149467, 1340293858
]
G + H: [
   706557567,  328506515,
   436867511, 4018126123,
  3105750112, 3720742539,
  2325508863, 4019525938
] [
  1937168552,  425735591,
  2513049408,  588790536,
    36446620, 3253639175,
  2109418651, 1629396931
]
2G: [
  1197906296, 2785757436,
  2012355381, 3230231010,
    78977731, 2320644099,
  2365804414, 2096266008
] [
   578319313, 2651109277,
  1021936169, 3128798694,
  2675192027,  691903174,
  3683569728,  125261072
]
2G + H: [
  1698729797, 4042000547,
   942118951, 3066173167,
  3972075465,  292257768,
  2771380314, 1766334169
] [
   498405700,  141072137,
  1322584940, 2575368526,
  2277505068, 2649900690,
  2195467560,  916465210
]
*/

template CheckQuadMSMAllAdd() {
  // 4 128 bits, all unsigned
  signal input u0[128];
  signal input u1[128];
  signal input u2[128];
  signal input u3[128];
  // Q (part of pubkey) and R (from the signature)
  signal input Qx[8]; signal input Qy[8];
  signal input Rx[8]; signal input Ry[8];
  // intermediate values and advice
  // 12 + 2 * 128 + 1
  signal input addres_x[269][8];
  signal input addres_y[269][8];
  signal input addadva[269][3];
  signal input addadvb[269][4];
  // additions
  component Add[269];
  var idx = 0;
  // construct subsets
  signal Sx[16][8]; signal Sy[16][8];
  for (var i = 0; i < 16; i++) {
    if (i == 0) { // G
      Sx[i] <== [ 3633889942, 4104206661, 770388896, 1996717441,
                  1671708914, 4173129445, 3777774151, 1796723186];
      Sy[i] <== [ 935285237, 3417718888, 1798397646, 734933847,
                  2081398294, 2397563722, 4263149467, 1340293858];
    } else if (i == 4) { // G + H
      Sx[i] <== [ 706557567, 328506515, 436867511, 4018126123,
                  3105750112, 3720742539, 2325508863, 4019525938];
      Sy[i] <== [ 1937168552, 425735591, 2513049408, 588790536,
                  36446620, 3253639175, 2109418651, 1629396931];
    } else if (i == 8) { // 2G
      Sx[i] <== [ 1197906296, 2785757436, 2012355381, 3230231010,
                  78977731, 2320644099, 2365804414, 2096266008];
      Sy[i] <== [ 578319313, 2651109277, 1021936169, 3128798694,
                  2675192027, 691903174, 3683569728, 125261072];
    } else if (i == 12) { // 2G + H
      Sx[i] <== [ 1698729797, 4042000547, 942118951, 3066173167,
                  3972075465, 292257768, 2771380314, 1766334169];
      Sy[i] <== [ 498405700, 141072137, 1322584940, 2575368526,
                  2277505068, 2649900690, 2195467560, 916465210];
    } else {
      Sx[i] <== addres_x[idx];
      Sy[i] <== addres_y[idx];
      Add[idx] = CheckAddFast();
      if (i % 2 == 1) {
        Add[idx].Px <== Sx[i - 1];
        Add[idx].Py <== Sy[i - 1];
        Add[idx].Qx <== Rx;
        Add[idx].Qy <== Ry;
      } else {
        Add[idx].Px <== Sx[i - 2];
        Add[idx].Py <== Sy[i - 2];
        Add[idx].Qx <== Qx;
        Add[idx].Qy <== Qy;
      }
      Add[idx].Rx <== addres_x[idx];
      Add[idx].Ry <== addres_y[idx];
      Add[idx].a <== addadva[idx];
      Add[idx].b <== addadvb[idx];
      idx++;
    }
  }
  component Sel16[128];
  // main ladder (two adds per)
  for (var i = 0; i < 128; i++) {
    // select
    Sel16[i] = PointSelect(16, 8);
    Sel16[i].ix <== Sx; Sel16[i].iy <== Sy;
    Sel16[i].index <== u3[127 - i] + 2 * u2[127 - i] + 4 * u1[127 - i] + 8 * u0[127 - i];
    // add (P + subset)
    Add[idx] = CheckAddFast();
    if (i == 0) {
      // start with H to avoid early accidental point doubling
      Add[idx].Px <== [ 3616128389, 1472745417, 3264735939, 4231397245,
                        2294707822, 4221054933, 4007353959, 1149072283];
      Add[idx].Py <== [ 1927437106, 209597385, 2818237696, 1026857877,
                        977973239, 3777928597, 2202087918, 759702955];
    } else {
      Add[idx].Px <== addres_x[idx - 1];
      Add[idx].Py <== addres_y[idx - 1];
    }
    Add[idx].Qx <== Sel16[i].x;
    Add[idx].Qy <== Sel16[i].y;
    Add[idx].Rx <== addres_x[idx];
    Add[idx].Ry <== addres_y[idx];
    Add[idx].a <== addadva[idx];
    Add[idx].b <== addadvb[idx];
    idx++;
    // P + previous
    Add[idx] = CheckAddFast();
    if (i == 0) {
      // start with H to avoid early accidental point doubling
      Add[idx].Px <== [ 3616128389, 1472745417, 3264735939, 4231397245,
                        2294707822, 4221054933, 4007353959, 1149072283];
      Add[idx].Py <== [ 1927437106, 209597385, 2818237696, 1026857877,
                        977973239, 3777928597, 2202087918, 759702955];
    } else {
      Add[idx].Px <== addres_x[idx - 2];
      Add[idx].Py <== addres_y[idx - 2];
    }
    Add[idx].Qx <== addres_x[idx - 1];
    Add[idx].Qy <== addres_y[idx - 1];
    Add[idx].Rx <== addres_x[idx];
    Add[idx].Ry <== addres_y[idx];
    Add[idx].a <== addadva[idx];
    Add[idx].b <== addadvb[idx];
    idx++;
  }
  // final addition to cancel out our starting choice of H
  Add[idx] = CheckAddFast();
  Add[idx].Px <== addres_x[idx - 1];
  Add[idx].Py <== addres_y[idx - 1];
  Add[idx].Qx <== [ 3344669367, 478489584, 1365695363, 1177269113,
                    1989578046, 2995114323, 3272807451, 760269898];
  Add[idx].Qy <== [ 703426786, 1889716087, 4202633397, 1407233598,
                    2174823998, 112976657, 4232609723, 1333103311];
  Add[idx].Rx <== addres_x[idx];
  Add[idx].Ry <== addres_y[idx];
  Add[idx].a <== addadva[idx];
  Add[idx].b <== addadvb[idx];
  // check that R matches the result post selection, limb for limb
  for (var i = 0; i < 8; i++) {
    Rx[i] === addres_x[idx][i];
  }
}

// powers of G (compute kG for a 256 bit u)
// assume specific ROM packing and 32 bit limbs
// performs 3x22 lookups and 21 core additions (with 1 final addition to remove accumulated junk)
// u is 256 LSB to MSB
template ComputeGMul() {
  signal input u[256];
  signal input addres_x[22][8];
  signal input addres_y[22][8];
  signal input addadva[22][3];
  signal input addadvb[22][4];
  signal input Gadv_x[22][8];
  signal input Gadv_y[22][8];
  // split u into 22 12 bit chunks (upacked) (top chunk is actually 4 bits)
  signal upacked[22];
  for (var i = 0; i < 22; i++) {
    var sum = 0;
    for (var j = 0; j < 12 && i * 12 + j < 256; j++) {
      sum += u[i * 12 + j] * (1 << j);
    }
    upacked[i] <== sum;
  }
  // pack Gadv x, y, and kpacked into 3 signals to perform lookups
  signal lookupvals[22][3][65];
  for (var i = 0; i < 22; i++) {
    var sum[3] = [0, 0, 0];
    for (var j = 0; j < 5; j++) {
      sum[0] += Gadv_x[i][j] * (1 << (32 * j + 12));
      sum[1] += Gadv_y[i][j] * (1 << (32 * j + 12));
    }
    for (var j = 0; j < 3; j++) {
      sum[2] += Gadv_x[i][5 + j] * (1 << (32 * j + 12));
      sum[2] += Gadv_y[i][5 + j] * (1 << (32 * (3 + j) + 12));
    }
    for (var j = 0; j < 3; j++) {
      sum[j] += upacked[i];
    }
    for (var j = 0; j < 3; j++) {
      lookupvals[i][j][0] <== 1;
      for (var k = 1; k < 65; k++) {
        lookupvals[i][j][k] <== sum[j] * lookupvals[i][j][k - 1];
      }
    }
  }
  // check lookups
  signal dp[22][3][64];
  for (var i = 0; i < 22; i++) {
    for (var j = 0; j < 3; j++) {
      // dp[i][j][k] is the dot product of lookupvals[i][j] and GROM12(i, j)[k]
      // multiplied by dp[i][j][k - 1] if k > 0
      var tbl[64][65] = GROM12(i, j);
      //log(tbl);
      for (var k = 0; k < 64; k++) {
        var sum = 0;
        for (var l = 0; l < 65; l++) {
          sum += lookupvals[i][j][l] * tbl[k][l];
        }
        if (k > 0) {
          dp[i][j][k] <== sum * dp[i][j][k - 1];
        } else {
          dp[i][j][k] <== sum;
        }
      }
      //log(i, j, upacked[i], dp[i][j][63]);
      // check that dp[i][j][63] is 0
      dp[i][j][63] === 0;
    }
  }
  // check additions
  component Add[22];
  // check 21 core additions + 1 final addition
  for (var i = 0; i < 22; i++) {
    Add[i] = CheckAddFast();
    if (i == 0) {
      Add[i].Px <== Gadv_x[0];
      Add[i].Py <== Gadv_y[0];
    } else {
      Add[i].Px <== addres_x[i - 1];
      Add[i].Py <== addres_y[i - 1];
    }
    if (i < 21) {
      Add[i].Qx <== Gadv_x[i + 1];
      Add[i].Qy <== Gadv_y[i + 1];
    } else {
      Add[i].Qx <== [
        2622891199,  326727234, 3928270622, 1298531275,
        2285285235, 3640002658,  827460708, 1722230696
      ];
      Add[i].Qy <== [
        3624906578, 1779415008,  425102705,  278971719,
        3418268433, 1387363372, 2081088488, 3539104871
      ];
    }
    Add[i].Rx <== addres_x[i];
    Add[i].Ry <== addres_y[i];
    Add[i].a <== addadva[i];
    Add[i].b <== addadvb[i];
  }
}
