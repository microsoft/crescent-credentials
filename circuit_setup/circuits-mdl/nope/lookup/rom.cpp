
// compile with C++11: g++ -O3 -std=c++11 -lgmpxx -lgmp rom.cpp -o rom
// build circom ROM for multiples of G
// given a positive integer l
// compute ceil(256/l) ROMs
// each one (i) contains the values 2^{il} * [0,2^l - 1] * G + 1 G
// the X and Y coordinates are packed

#include <iostream>
#include <vector>
#include <array>
#include "gmpxx.h"

// order of the curve
// in hex
/*const mpz_class a(-3);
const mpz_class p("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const mpz_class gx("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const mpz_class gy("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");*/
mpz_class a, p, gx, gy, pF;
// ECC point
struct Point {
  mpz_class x, y;
  Point() : x(gx), y(gy) {}
  // compute kG
  Point(mpz_class k) {
    bool first = true;
    Point Q, R;
    for (int i = 0; i < 256; i++) {
      if (mpz_tstbit(k.get_mpz_t(), i)) {
        if (first) {
          Q = R;
          first = false;
        } else {
          Q = Q + R;
        }
      }
      R = R + R;
    }
    x = Q.x;
    y = Q.y;
  }
  Point(const mpz_class &x, const mpz_class &y) : x(x), y(y) {}
  std::array<mpz_class, 3> toPacked() const {
    std::array<mpz_class, 3> res;
    // get lowest 160 bits of x, y (5x32)
    // and then the top 3 bits of each (combined to a 6x32 bit number)
    mpz_class mask;
    mask = (mpz_class(1) << (5 * 32)) - 1;
    res[0] = x & mask;
    res[1] = y & mask;
    mask = (mpz_class(1) << (3 * 32)) - 1;
    res[2] = (x >> (5 * 32)) | ((y >> (5 * 32)) << (3 * 32));
    return res;
  }
  Point operator+(const Point &other) const {
    Point res;
    mpz_class lambda;
    if (x == other.x && y == other.y) {
      mpz_class numerator = 3 * x * x + a;
      mpz_class denominator = 2 * y;
      mpz_invert(denominator.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
      lambda = numerator * denominator % p;
    } else {
      mpz_class numerator = other.y - y;
      mpz_class denominator = other.x - x;
      mpz_invert(denominator.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
      lambda = numerator * denominator % p;
    }
    res.x = (lambda * lambda - x - other.x) % p;
    res.y = (lambda * (x - res.x) - y) % p;
    if (res.x < 0) { res.x += p; }
    if (res.y < 0) { res.y += p; }
    return res;
  }
};

//const mpz_class pF("30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001");

// TO DO, this is far more complex than it needs to be
// instead of solving a linear system
// we can compute the coefficients directly if we know vals are the zeros
std::vector<mpz_class> buildRom(const std::vector<mpz_class> &vals, const int l) {
  // for each value compute 1, v, v^2, v^3, ..., v^(2^(l/2))
  // modulus the proof field size
  std::vector<std::vector<mpz_class>> M;
  for (const mpz_class &v : vals) {
    std::vector<mpz_class> tmp;
    mpz_class cur(1);
    for (int i = 0; i <= (1 << (l / 2)); i++) {
      tmp.push_back(cur);
      cur = (cur * v) % pF;
    }
    M.push_back(tmp);
  }
  // solve the linear system M * x = 0 mod pF
  // force x.back() = 1 to make the solution non-trivial
  std::vector<mpz_class> x((1 << (l / 2)) + 1, 0);
  // gaussian elimination
  for (int i = 0; i < (1 << (l / 2)); i++) {
    // find a row with a non-zero in the i-th column
    int j = i;
    while (j < (1 << (l / 2)) && M[j][i] == 0) {
      j++;
    }
    if (j == (1 << (l / 2))) {
      std::cerr << "Matrix is singular" << std::endl;
      return std::vector<mpz_class>();
    }
    // swap rows i and j
    std::swap(M[i], M[j]);
    // divide row i by M[i][i]
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), M[i][i].get_mpz_t(), pF.get_mpz_t());
    for (int j = i; j <= (1 << (l / 2)); j++) {
      M[i][j] = (M[i][j] * inv) % pF;
    }
    // subtract row i from all other following rows
    for (int j = i + 1; j < (1 << (l / 2)); j++) {
      mpz_class factor = M[j][i];
      for (int k = i; k <= (1 << (l / 2)); k++) {
        M[j][k] = (M[j][k] - factor * M[i][k]) % pF;
      }
    }
  }
  // back substitute
  x[(1 << (l / 2))] = 1;
  for (int i = (1 << (l / 2)) - 1; i >= 0; i--) {
    mpz_class sum;
    for (int j = i + 1; j <= (1 << (l / 2)); j++) {
      sum = (sum + M[i][j] * x[j]) % pF;
    }
    x[i] = (pF - sum) % pF;
  }
  // return x
  return x;
}

// build the ROM for a specific k and l
// technically 3 roms
// break coords into 16 32 bit chunks
// 5, 6, 5 chunks for 3 roms
void buildRomSet(int k, int l) {
  std::vector<Point> powsOfG;
  // repeat k times
  Point base = Point(1);
  for (int i = 1; i <= k; i++) {
    base = base + Point(mpz_class(1) << (i * l));
  }
  // repeat 2^l times
  powsOfG.push_back(base);
  for (int i = 1; i < (1 << l); i++) {
    //powsOfG.push_back(Point(1 + i + (1 << l) * k));
    powsOfG.push_back(base + Point(i * (mpz_class(1) << (k * l))));
  }
  // for each 2^(l/2) points, make 3 roms
  std::array<std::vector<std::vector<mpz_class>>, 3> roms;
  for (int i = 0; i < (1 << (l / 2)); i++) {
    std::array<std::vector<mpz_class>, 3> packed;
    for (int j = 0; j < (1 << (l / 2)); j++) {
      std::array<mpz_class, 3> tmp = powsOfG[i * (1 << (l / 2)) + j].toPacked();
      int idx = j + (i << (l / 2));
      packed[0].push_back((tmp[0] << l) + idx);
      packed[1].push_back((tmp[1] << l) + idx);
      packed[2].push_back((tmp[2] << l) + idx);
    }
    roms[0].push_back(buildRom(packed[0], l));
    roms[1].push_back(buildRom(packed[1], l));
    roms[2].push_back(buildRom(packed[2], l));
  }

  // print the roms
  for (int r = 0; r < 3; r++) {
    if (r != 0 || k != 0) {
      std::cout << "\t} else if";
    } else {
      std::cout << "\tif";
    }
    std::cout << "(i == " << k << " && r == " << r << ") {" << std::endl;
    std::cout << "\t\treturn [" << std::endl;
    for (int i = 0; i < (1 << (l / 2)); i++) {
      std::cout << "\t\t\t[";
      for (int j = 0; j <= (1 << (l / 2)); j++) {
        std::cout << roms[r][i][j] << (j == (1 << (l / 2)) ? "" : ",");
      }
      std::cout << (i == (1 << (l / 2)) - 1 ? "]" : "],") << std::endl;
    }
    std::cout << "\t\t];" << std::endl;
  }
}

void buildAndPrintAll(int l) {
  //std::cout << "l = " << l << std::endl;
  std::cout << "pragma circom 2.0.0;" << std::endl << std::endl;
  std::cout << "function GROM" << l << "(i, r) {" << std::endl;
  for (int k = 0; k <= 256 / l; k++) {
    //std::cout << "k = " << k << std::endl;
    buildRomSet(k, l);
  }
  std::cout << "\t} else { return [[0],[0]]; }" << std::endl;
  std::cout << "}" << std::endl;
}

void localTest(int l) {
  for (int i = 0; i < (1 << l); i++) {
    Point P = Point(1 + i);
    std::cout << P.x << " " << P.y << std::endl;
  }
  std::cout << pF << std::endl;
}

// 10
int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " l" << std::endl;
    return 1;
  }
  int l = std::stoi(argv[1]);
  if (l < 1 || l > 16 || l % 2 != 0) {
    std::cerr << "l must be an even number between 1 and 16" << std::endl;
    return 1;
  }
  a = mpz_class(-3);
  p = mpz_class("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  gx = mpz_class("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
  gy = mpz_class("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  pF = mpz_class("0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001");
  buildAndPrintAll(l);
  // local test
  //localTest(l);
  return 0;
}