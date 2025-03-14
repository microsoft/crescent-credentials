//! This file implements a group whose order is q = 2^255 - 19. It is
//! internally backed by an elliptic curve of order 2*q. All operations
//! use complete formulas and are constant-time, unless specified explicitly
//! otherwise.

// Projective/fractional coordinates traditionally use uppercase letters,
// using lowercase only for affine coordinates.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use core::borrow::Borrow;
use crrl::field::ModInt256;

// Tentative API expected by the rest of the code.
// pub type GroupElement = Point;
// pub type CompressedGroup = [u8; 32];

// Modulus is p = 2^256 - 451024951810263391379330922557034374877
type GFp = ModInt256<0x20CD9255FD615923u64, 0xACAFC103CD968A25u64,
                     0xFFFFFFFFFFFFFFFEu64, 0xFFFFFFFFFFFFFFFFu64>;

/// A curve point (group element).
#[derive(Clone, Copy, Debug)]
pub struct Point {
    // Field is GF(p) with:
    //   p = 2^256 - 451024951810263391379330922557034374877
    // (p is prime; note that p = 3 mod 4).
    //
    // Curve equation is y^2 = x*(x^2 + a*x + b) for two specific constants:
    //   a = 0x83d55b3ef1207cbb74ada704e61adf4dabaed20eae494cc45293fdcefdd1183d
    //   b = 0x341b58146036cb9911638f4cf4ac3bed671e867f1b14831c1af9cd915591b64c
    // We use extended coordinates on the Jacobi quartic curve with
    // equation:
    //   e^2 = (a^2 - 4*b)*u^4 - 2*a*u^2 + 1
    // The map from the base curve is defined as:
    //   u = x/y
    //   e = u^2*(x - b/x)
    // The curve constants have been chosen so that a^2 - 4*b = -1.
    // For the point (0,0) (the neutral in the group, which is the
    // unique point of order 2 on the curve), we set u = 0 and e = -1.
    // From the curve equation, e = (x^2 - b)/(x^2 + a*x + b), so that
    // it is always defined and non-zero, and e = -1 for x = 0; as for u,
    // it is the inverse of the slope of the line from (0,0) to the point,
    // so the extreme case for (0,0) itself is a vertical tangent, which
    // is why we use u = 0. Since addition of (0,0) on the curve becomes
    // on the quartic the transform (e,u) -> (-e,-u), we can also map
    // the point-at-infinity of the initial curve into (1,0) on the quartic.
    //
    // In extended coordinates, we have:
    //   Z != 0 and E != 0 for all points
    //   e = E/Z
    //   u = U/Z
    //   u^2 = T/Z   (hence U^2 = T*Z)
    E: GFp,
    Z: GFp,
    U: GFp,
    T: GFp,
}

// The whole curve has order 2*q, with q = 2^255 - 19. The implementation
// defines a group of order q, which is really the quotient of the curve
// by the subgroup {inf,N} (with inf = point-at-infinity and N = unique
// point of order 2). Scalars are integers modulo q.
pub type Scalar = crrl::field::GF25519;

impl Point {

    /// The group neutral element.
    pub const NEUTRAL: Self = Self {
        E: GFp::MINUS_ONE,
        Z: GFp::ONE,
        U: GFp::ZERO,
        T: GFp::ZERO,
    };

    /// The curve `a` constant.
    const A: GFp = GFp::w64be(
        0x83D55B3EF1207CBB, 0x74ADA704E61ADF4D,
        0xABAED20EAE494CC4, 0x5293FDCEFDD1183D);

    /// a' = -2*a
    const Ap: GFp = GFp::w64be(
        0xF85549821DBF0689, 0x16A4B1F633CA4162,
        0x0201DDEA3E9A7AC1, 0x9C73290DFF2081CC);

    /// The curve `b` constant.
    const B: GFp = GFp::w64be(
        0x341B58146036CB99, 0x11638F4CF4AC3BED,
        0x671E867F1B14831C, 0x1AF9CD915591B64C);

    /// 16*b
    const Bx16: GFp = GFp::w64be(
        0x41B58146036CB991, 0x1638F4CF4AC3BEDA,
        0x6BD924E648849352, 0x4D34221360F75957);

    /// a^2
    const AA: GFp = GFp::w64be(
        0xD06D605180DB2E64, 0x458E3D33D2B0EFB5,
        0x9C7A19FC6C520C70, 0x6BE736455646D92F);

    /* unused
    /// b' = a^2 - 4*b
    const Bp: GFp = GFp::MINUS_ONE;
    */

    /// The conventional base point (group generator).
    ///
    /// This point generates the whole group, which as prime order r
    /// (integers modulo r are represented by the `Scalar` type).
    pub const BASE: Self = Self {
        // We use the point with u = 2 (smallest non-zero u that maps to
        // a valid group element).
        E: GFp::w64be(
            0x80EECF52DB5F5A44, 0xF50CA81BDD9B2756,
            0x1B9488E2D8D6D550, 0x8E570EABE5552C04),
        Z: GFp::ONE,
        U: GFp::w64be(0, 0, 0, 2),
        T: GFp::w64be(0, 0, 0, 4),
    };

    /// Tries to decode a point from bytes.
    ///
    /// If the source slice has not length exactly 32 bytes, then
    /// decoding fails. If the source bytes are not a valid, canonical
    /// encoding of a group element, then decoding fails. On success,
    /// 0xFFFFFFFF is returned; on failure, 0x00000000 is returned. On
    /// failure, this point is set to the neutral.
    ///
    /// If the source length is exactly 32 bytes, then the decoding
    /// outcome (success or failure) should remain hidden from
    /// timing-based side channels.
    pub fn set_decode(&mut self, buf: &[u8]) -> u32 {
        // Check that the input length is correct.
        if buf.len() != 32 {
            *self = Self::NEUTRAL;
            return 0;
        }

        // Decode the u coordinate.
        let (u, mut r) = GFp::decode32(buf);

        // e^2 = (a^2-4*b)*u^4 - 2*a*u^2 + 1
        let uu = u.square();
        let ee = -uu.square() + uu * Self::Ap + GFp::ONE;
        let (e, r2) = ee.sqrt();
        r &= r2;
        // GFp::sqrt() already returns the non-negative root, we do
        // not have to test the sign of e and adjust.

        // We have the point in affine coordinates, except on failure,
        // in which case we have to adjust the values.
        self.E = GFp::select(&GFp::MINUS_ONE, &e, r);
        self.Z = GFp::ONE;
        self.U = GFp::select(&GFp::ZERO, &u, r);
        self.T = GFp::select(&GFp::ZERO, &uu, r);
        r
    }

    /// Tries to decode a point from some bytes.
    ///
    /// Decoding succeeds only if the source slice has length exactly 32
    /// bytes, and contains the canonical encoding of a valid curve
    /// point. Sicne this method returns an `Option<Point>`, it
    /// inherently leaks (through timing-based side channels) whether
    /// decoding succeeded or not; to avoid that, consider using
    /// `set_decode()`. The decoded point itself, however, does not leak.
    pub fn decode(buf: &[u8]) -> Option<Point> {
        let mut P = Point::NEUTRAL;
        if P.set_decode(buf) != 0 {
            Some(P)
        } else {
            None
        }
    }

    /// Encodes this point into exactly 32 bytes.
    ///
    /// Encoding is always canonical.
    pub fn encode(self) -> [u8; 32] {
        // - Choose the element representant whose e coordinate is
        //   non-negative.
        // - Encode the u coordinate of that point.
        let C = GFp::ONE / self.Z;
        let mut u = self.U * C;
        let sgn = (((self.E * C).encode32()[0] & 1) as u32).wrapping_neg();
        u.set_cond(&-u, sgn);
        u.encode32()
    }

    /// Creates a point by converting a point in extended affine
    /// coordinates (e, u, u^2).
    fn from_affine_extended(P: &PointAffineExtended) -> Self {
        Self {
            E: P.e,
            Z: GFp::ONE,
            U: P.u,
            T: P.t,
        }
    }

    /// Adds another point (`rhs`) to this point.
    fn set_add(&mut self, rhs: &Self) {
        let (E1, Z1, U1, T1) = (&self.E, &self.Z, &self.U, &self.T);
        let (E2, Z2, U2, T2) = (&rhs.E, &rhs.Z, &rhs.U, &rhs.T);

        // Generic case (8M+3S):
        //   constants on the dual curve:
        //      a' = -2*a
        //      b' = a^2 - 4*b     (here: b' = -1)
        //   e1e2 = E1*E2
        //   z1z2 = Z1*Z2
        //   u1u2 = U1*U2
        //   t1t2 = T1*T2
        //     zt = (Z1 + T1)*(Z2 + T2) - z1z2 - t1t2
        //     eu = (E1 + U1)*(E2 + U2) - e1e2 - u1u2
        //     hd = z1z2 - b'*t1t2
        //     E3 = (z1z2 + b'*t1t2)*(e1e2 + a'*u1u2) + 2*b'*u1u2*zt
        //     Z3 = hd^2
        //     T3 = eu^2
        //     U3 = ((hd + eu)^2 - Z3 - T3)/2  # Or: U3 = hd*eu
        let e1e2 = E1 * E2;
        let u1u2 = U1 * U2;
        let z1z2 = Z1 * Z2;
        let t1t2 = T1 * T2;
        let eu = (E1 + U1) * (E2 + U2) - e1e2 - u1u2;
        let zt = (Z1 + T1) * (Z2 + T2) - z1z2 - t1t2;
        let hd = z1z2 + t1t2;   // Z1*Z2 - (a^2 - 4*b)*T1*T2
        let T3 = eu.square();
        let Z3 = hd.square();
        let E3 = (z1z2 - t1t2) * (e1e2 + u1u2 * Self::Ap) - u1u2.mul2() * zt;
        let U3 = hd * eu;  // faster than: ((hd + eu)^2 - Z3 - T3)/2
        self.E = E3;
        self.Z = Z3;
        self.U = U3;
        self.T = T3;
    }

    /// Specialized point addition routine when the other operand is in
    /// affine extended coordinates (used in the pregenerated tables for
    /// multiples of the base point).
    fn set_add_affine_extended(&mut self, rhs: &PointAffineExtended) {
        let (E1, Z1, U1, T1) = (&self.E, &self.Z, &self.U, &self.T);
        let (e2, u2, t2) = (&rhs.e, &rhs.u, &rhs.t);

        // Generic case (7M+3S):
        //   constants on the dual curve:
        //      a' = -2*a
        //      b' = a^2 - 4*b     (here: b' = -1)
        //   e1e2 = E1*E2
        //   u1u2 = U1*U2
        //   t1t2 = T1*T2
        //     zt = Z1*t2 + T1
        //     eu = (E1 + U1)*(E2 + U2) - e1e2 - u1u2
        //     hd = Z1 - b'*t1t2
        //     E3 = (Z1 + b'*t1t2)*(e1e2 + a'*u1u2) + 2*b'*u1u2*zt
        //     Z3 = hd^2
        //     T3 = eu^2
        //     U3 = ((hd + eu)^2 - Z3 - T3)/2  # Or: U3 = hd*eu
        let e1e2 = E1 * e2;
        let u1u2 = U1 * u2;
        let t1t2 = T1 * t2;
        let eu = (E1 + U1) * (e2 + u2) - e1e2 - u1u2;
        let zt = Z1 * t2 + T1;
        let hd = Z1 + t1t2;   // Z1*Z2 - (a^2 - 4*b)*T1*T2
        let T3 = eu.square();
        let Z3 = hd.square();
        let E3 = (Z1 - t1t2) * (e1e2 + u1u2 * Self::Ap) - u1u2.mul2() * zt;
        let U3 = hd * eu;  // faster than: ((hd + eu)^2 - Z3 - T3)/2
        self.E = E3;
        self.Z = Z3;
        self.U = U3;
        self.T = T3;
    }

    /// Specialized point subtraction routine when the other operand is in
    /// affine extended coordinates (used in the pregenerated tables for
    /// multiples of the base point).
    fn set_sub_affine_extended(&mut self, rhs: &PointAffineExtended) {
        let mrhs = PointAffineExtended {
            e: rhs.e,
            u: -rhs.u,
            t: rhs.t,
        };
        self.set_add_affine_extended(&mrhs);
    }

    /// Doubles this point (in place).
    pub fn set_double(&mut self) {
        let (E, Z, U, T) = (&self.E, &self.Z, &self.U, &self.T);

        // Doubling, output in XWJ coordinates (cost: 1M+3S)
        // C = U**2
        // X = 16*b*(C**2)
        // W = 4*gamma*C - (2*gamma*T + Z)**2
        // J = 2*E*U
        let C = U.square();
        let X = C.square() * Self::Bx16;
        let W = C.mul2() - (T + Z).square();
        let J = E * U.mul2();

        // Conversion to EZUT coordinates (cost: 3S)
        // Z = W**2
        // T = J**2
        // U = ((W + J)**2 - Z - T)/2  # or: U = W*J
        // E = 2*X - Z + a*T
        self.Z = W.square();
        self.T = J.square();
        self.U = W * J;
        self.E = X.mul2() - self.Z + self.T * Self::A;
    }

    /// Doubles this point.
    #[inline(always)]
    pub fn double(self) -> Self {
        let mut r = self;
        r.set_double();
        r
    }

    /// Doubles this point n times (in place).
    pub fn set_xdouble(&mut self, n: u32) {
        if n == 0 {
            return;
        }

        let (E, Z, U, T) = (&self.E, &self.Z, &self.U, &self.T);

        // First doubling, output in XWJ coordinates (cost: 1M+3S)
        // C = U**2
        // X = 16*b*(C**2)
        // W = 4*gamma*C - (2*gamma*T + Z)**2
        // J = 2*E*U
        let C = U.square();
        let mut X = C.square() * Self::Bx16;
        let mut W = C.mul2() - (T + Z).square();
        let mut J = E * U.mul2();

        for _ in 1..n {
            // (n-1) doublings in XWJ coordinates.
            // C = J**2
            // E = W**2
            // G = (W + J)**2 - C - E # G = 2*W*J
            // H = G**2
            // I = (E + 2*gamma*C)**2
            // X2 = b*(H**2)
            // W2 = gamma*H - I
            // J2 = G*(2*X + a*C - E)   # note: uses previous X, not new X2
            let C = J.square();
            let E = W.square();
            let G = (W + J).square() - C - E; // FIXME: or: W * J.mul2()
            let H = G.square();
            let I = (E + C).square();
            W = H.half() - I;
            J = G * (X.mul2() + C * Self::A - E);
            X = H.square() * Self::B;
        }

        // Final conversion to EZUT coordinates (cost: 3S)
        // Z = W**2
        // T = J**2
        // U = ((W + J)**2 - Z - T)/2  # or: U = W*J
        // E = 2*X - Z + a*T
        self.Z = W.square();
        self.T = J.square();
        self.U = W * J;
        self.E = X.mul2() - self.Z + self.T * Self::A;
    }

    /// Doubles this point n times.
    #[inline(always)]
    pub fn xdouble(self, n: u32) -> Self {
        let mut r = self;
        r.set_xdouble(n);
        r
    }

    /// Negates this point (in place).
    #[inline(always)]
    pub fn set_neg(&mut self) {
        self.U.set_neg();
    }

    /// Subtract another point (`rhs`) from this point.
    fn set_sub(&mut self, rhs: &Self) {
        self.set_add(&-rhs);
    }

    /// Multiplies this point by a small integer.
    ///
    /// This operation is constant-time with regard to the source point,
    /// but NOT with regard to the multiplier; the multiplier `n` MUST
    /// NOT be secret.
    pub fn set_mul_small(&mut self, n: u64) {
        if n == 0 {
            *self = Self::NEUTRAL;
            return;
        }
        if n == 1 {
            return;
        }

        let nlen = 64 - n.leading_zeros();
        let T = *self;
        let mut ndbl = 0u32;
        for i in (0..(nlen - 1)).rev() {
            ndbl += 1;
            if ((n >> i) & 1) == 0 {
                continue;
            }
            self.set_xdouble(ndbl);
            ndbl = 0;
            self.set_add(&T);
        }
        self.set_xdouble(ndbl);
    }

    /// Compares two points for equality.
    ///
    /// Returned value is 0xFFFFFFFF if the two points are equal,
    /// 0x00000000 otherwise.
    #[inline]
    pub fn equals(self, rhs: Self) -> u32 {
        // Points are equal if and only if they have the same image through
        // isogeny theta1:
        //    theta1(e, u) = (f, v)
        //    with f = (a^2 - 4*b)*u^2, and v = u/e
        // In the theta1 output, coordinate v of a point uniquely identifies
        // the point. Thus, we only need to compare u1/e1 and u2/e2, which
        // is equivalent to comparing u1*e2 and u2*e1 (since e1 and e2 are
        // never zero).
        (self.U * rhs.E).equals(rhs.U * self.E)
    }

    /// Tests whether this point is the neutral (identity point on the
    /// curve).
    ///
    /// Returned value is 0xFFFFFFFF for the neutral, 0x00000000
    /// otherwise.
    #[inline(always)]
    pub fn isneutral(self) -> u32 {
        self.U.iszero()
    }

    /// Conditionally copies the provided point (`P`) into `self`.
    ///
    ///  - If `ctl` = 0xFFFFFFFF, then the value of `P` is copied into `self`.
    ///
    ///  - If `ctl` = 0x00000000, then the value of `self` is unchanged.
    ///
    /// `ctl` MUST be equal to 0x00000000 or 0xFFFFFFFF.
    #[inline]
    pub fn set_cond(&mut self, P: &Self, ctl: u32) {
        self.E.set_cond(&P.E, ctl);
        self.Z.set_cond(&P.Z, ctl);
        self.U.set_cond(&P.U, ctl);
        self.T.set_cond(&P.T, ctl);
    }

    /// Returns a point equal to `P0` (if `ctl` = 0x00000000) or `P1` (if
    /// `ctl` = 0xFFFFFFFF).
    ///
    /// Value `ctl` MUST be either 0x00000000 or 0xFFFFFFFF.
    #[inline(always)]
    pub fn select(P0: &Self, P1: &Self, ctl: u32) -> Self {
        let mut P = *P0;
        P.set_cond(P1, ctl);
        P
    }

    /// Conditionally negates this point.
    ///
    /// This point is negated if `ctl` = 0xFFFFFFFF, but kept unchanged
    /// if `ctl` = 0x00000000. `ctl` MUST be equal to 0x00000000 or
    /// 0xFFFFFFFF.
    #[inline]
    pub fn set_condneg(&mut self, ctl: u32) {
        self.U.set_cond(&-self.U, ctl);
    }

    /// Maps a field element into a point.
    ///
    /// This map output is not uniformly distributed; in general, it should
    /// be used only through `hash_to_curve()`, which invokes this map
    /// twice.
    fn map_to_curve(f: &GFp) -> Self {
        // We use the Elligator2 map.
        // Let d = -1 (a non-square in GF(p)). We compute:
        //   c = 1 + d*f^2 = 1 - f^2
        // If c = 0, then the output is the neutral. Otherwise, we
        // compute:
        //   v = -a/c
        //   z = v*(v^2 + a*v + b)
        // If z is a square, then we set x = v; otherwise, x = -v - a.
        // At that point, x is correct, we can compute x*(x^2 + a*x + b)
        // and extract a square root to get y. From x and y, we can compute
        // e and u using:
        //   e = (x^2 - b)/(x^2 + a*x + b)
        //   u = x/y
        // We do not really care about getting an affine point (in general
        // we'll immediately add the resulting point with another map
        // output); we can thus avoid divisions here.

        // c = 1 - f^2
        let c = GFp::ONE - f.square();

        // We now assume that c != 0.
        // v = -a/c
        // z = v*(v^2 + a*v + b)
        // We really compute:
        //   z*c^4 = -a*c*(a^2 - c*a^2 + b*c^2)
        // which is as much a square as z is a square, and does not need
        // any division.
        let zc4 = -Self::A * c * ((Self::B * c - Self::AA) * c + Self::AA);

        // If z (zc4) is a square, then x = v; otherwise, x = -v - a.
        // We really compute x*c, which is then set to either -a or a*(1 - c).
        let ls = zc4.legendre();
        let z_is_qr = !((ls >> 1) as u32);
        let xc0 = Self::A * (GFp::ONE - c);
        let xc1 = -Self::A;
        let xc = GFp::select(&xc0, &xc1, z_is_qr);

        // If c != 0, then v != 0. If v = -a, then c = -1, which implies
        // that f^2 = 2, which is not possible since 2 is not a square in
        // GF(p). Thus, we can never get x = 0, regardless of whether
        // z was a square or not. Since the point N = (0,0) is the only
        // curve point such that y = 0, this implies that y != 0.
        //   y^2 = x*(x^2 + a*x + b)
        //   u = x/y
        //     = x*y/y^2
        //   e = (x^2 - b)/(x^2 + a*x + b)
        //     = x*(x^2 - b)/y^2
        //   t = u^2
        //     = x^2/y^2
        // To avoid divisions, we multiply all numerators and denominators
        // with c^4.

        // (y*c^2)^2 = c*(x*c)*((x*c)^2 + a*c*(x*c) + b*c^2)
        // We then extract yc2 = y*c^2 with a square root. Our sqrt()
        // function enforces the choice of a "non-negative" output (the
        // least significant bit of the integer output is 0), which is
        // the convention we use for this map.
        let c2 = c.square();         // c^2
        let xc2 = xc * c;            // x*c^2
        let x2c2 = xc.square();      // x^2*c^2
        let y2c4 = xc2 * (xc.square() + Self::A * xc2 + Self::B * c2);
        let (yc2, g) = y2c4.sqrt();  // y*c^2
        assert!(g == 0xFFFFFFFF);    // sqrt() should never fail here

        // E = c*(x*c)*((x*c)^2 - b*c^2)
        // Z = y^2*c^4
        // U = x*y*c^4 = x*c^2*(y*c^2)
        // T = (x*c^2)^2
        let mut E = c * xc * (x2c2 - Self::B * c2);
        let mut Z = y2c4;
        let U = xc2 * yc2;
        let T = xc2.square();

        // If c = 0 then everything is zero here, which is invalid;
        // in that case, we must replace E with -1 and Z with 1, to get
        // a valid representation of the neutral.
        let c_is_zero = c.iszero();
        E.set_cond(&GFp::MINUS_ONE, c_is_zero);
        Z.set_cond(&GFp::ONE, c_is_zero);

        Self { E, Z, U, T }
    }

    /// Maps a pseudorandom 64-byte input into a point.
    ///
    /// This function assumes that the provided 64-byte input was
    /// obtained from a cryptographically secure hash function (e.g.
    /// SHA-512), in which case the whole process represents a secure
    /// hash-to-curve mechanism. The output distribution is
    /// computationally indistinguishable from uniform over the whole
    /// group. Note that the output _may_ be the neutral (with very
    /// low probability).
    ///
    /// The input MUST have length exactly 64 bytes (otherwise, the
    /// function panics).
    pub fn hash_to_curve(data: &[u8]) -> Self {
        assert!(data.len() == 64);
        let f1 = GFp::decode_reduce(&data[0..32]);
        let f2 = GFp::decode_reduce(&data[32..64]);
        Self::map_to_curve(&f1) + Self::map_to_curve(&f2)
    }

    /// Recodes a scalar into 52 signed digits.
    ///
    /// Each digit is in -15..+16, top digit is 0 or 1.
    fn recode_scalar(n: &Scalar) -> [i8; 52] {
        let mut sd = [0i8; 52];
        let bb = n.encode();
        let mut cc: u32 = 0;       // carry from lower digits
        let mut i: usize = 0;      // index of next source byte
        let mut acc: u32 = 0;      // buffered bits
        let mut acc_len: i32 = 0;  // number of buffered bits
        for j in 0..52 {
            if acc_len < 5 && i < 32 {
                acc |= (bb[i] as u32) << acc_len;
                acc_len += 8;
                i += 1;
            }
            let d = (acc & 0x1F) + cc;
            acc >>= 5;
            acc_len -= 5;
            let m = 16u32.wrapping_sub(d) >> 8;
            sd[j] = (d.wrapping_sub(m & 32)) as i8;
            cc = m & 1;
        }
        sd
    }

    /// Lookups a point from a window, with sign handling (constant-time).
    fn lookup(win: &[Self; 16], k: i8) -> Self {
        // Split k into its sign s (0xFFFFFFFF for negative) and
        // absolute value (f).
        let s = ((k as i32) >> 8) as u32;
        let f = ((k as u32) ^ s).wrapping_sub(s);
        let mut P = Self::NEUTRAL;
        for i in 0..16 {
            // win[i] contains (i+1)*P; we want to keep it if (and only if)
            // i+1 == f.
            // Values a-b and b-a both have their high bit equal to 0 only
            // if a == b.
            let j = (i as u32) + 1;
            let w = !(f.wrapping_sub(j) | j.wrapping_sub(f));
            let w = ((w as i32) >> 31) as u32;

            P.E.set_cond(&win[i].E, w);
            P.Z.set_cond(&win[i].Z, w);
            P.U.set_cond(&win[i].U, w);
            P.T.set_cond(&win[i].T, w);
        }

        // Negate the returned value if needed.
        P.U.set_cond(&-P.U, s);

        P
    }

    /// Multiplies this point by a scalar (in place).
    ///
    /// This operation is constant-time with regard to both the points
    /// and the scalar value.
    pub fn set_mul(&mut self, n: &Scalar) {
        // Make a 5-bit window: win[i] contains (i+1)*P
        let mut win = [Self::NEUTRAL; 16];
        win[0] = *self;
        for i in 1..8 {
            let j = 2 * i;
            win[j - 1] = win[i - 1].double();
            win[j] = win[j - 1] + win[0];
        }
        win[15] = win[7].double();

        // Recode the scalar into 52 signed digits.
        let sd = Self::recode_scalar(n);

        // Process the digits in high-to-low order.
        *self = Self::lookup(&win, sd[51]);
        for i in (0..51).rev() {
            self.set_xdouble(5);
            self.set_add(&Self::lookup(&win, sd[i]));
        }
    }

    /// Lookups a point from a window of points in affine extended
    /// coordinates, with sign handling (constant-time).
    fn lookup_affine_extended(win: &[PointAffineExtended; 16], k: i8)
        -> PointAffineExtended
    {
        // Split k into its sign s (0xFFFFFFFF for negative) and
        // absolute value (f).
        let s = ((k as i32) >> 8) as u32;
        let f = ((k as u32) ^ s).wrapping_sub(s);
        let mut P = PointAffineExtended::NEUTRAL;
        for i in 0..16 {
            // win[i] contains (i+1)*P; we want to keep it if (and only if)
            // i+1 == f.
            // Values a-b and b-a both have their high bit equal to 0 only
            // if a == b.
            let j = (i as u32) + 1;
            let w = !(f.wrapping_sub(j) | j.wrapping_sub(f));
            let w = ((w as i32) >> 31) as u32;

            P.e.set_cond(&win[i].e, w);
            P.u.set_cond(&win[i].u, w);
            P.t.set_cond(&win[i].t, w);
        }

        // Negate the returned value if needed.
        P.u.set_cond(&-P.u, s);

        P
    }

    /// Sets this point by multiplying the conventional generator by the
    /// provided scalar.
    ///
    /// This operation is constant-time. It is faster than using the
    /// generic multiplication on `Self::BASE`.
    pub fn set_mulgen(&mut self, n: &Scalar) {
        // Recode the scalar into 52 signed digits.
        let sd = Self::recode_scalar(n);

        // We process four chunks in parallel. Each chunk is 13 digits.
        *self = Self::from_affine_extended(
            &Self::lookup_affine_extended(&PRECOMP_B, sd[12]));
        self.set_add_affine_extended(
            &Self::lookup_affine_extended(&PRECOMP_B65, sd[25]));
        self.set_add_affine_extended(
            &Self::lookup_affine_extended(&PRECOMP_B130, sd[38]));
        self.set_add_affine_extended(
            &Self::lookup_affine_extended(&PRECOMP_B195, sd[51]));

        // Process the digits in high-to-low order.
        for i in (0..12).rev() {
            self.set_xdouble(5);
            self.set_add_affine_extended(
                &Self::lookup_affine_extended(&PRECOMP_B, sd[i]));
            self.set_add_affine_extended(
                &Self::lookup_affine_extended(&PRECOMP_B65, sd[i + 13]));
            self.set_add_affine_extended(
                &Self::lookup_affine_extended(&PRECOMP_B130, sd[i + 26]));
            self.set_add_affine_extended(
                &Self::lookup_affine_extended(&PRECOMP_B195, sd[i + 39]));
        }
    }

    /// Creates a point by multiplying the conventional generator by the
    /// provided scalar.
    ///
    /// This operation is constant-time.
    #[inline]
    pub fn mulgen(n: &Scalar) -> Self {
        let mut P = Self::NEUTRAL;
        P.set_mulgen(n);
        P
    }

    /// 5-bit wNAF recoding of a scalar; output is a sequence of 256
    /// digits.
    ///
    /// Non-zero digits have an odd value, between -15 and +15
    /// (inclusive). (The recoding is constant-time, but use of wNAF is
    /// inherently non-constant-time.)
    fn recode_scalar_NAF(n: &Scalar) -> [i8; 256] {
        // We use a branchless algorithm to avoid misprediction
        // penalties.
        //
        // Let x be the current (complete) integer:
        //  - If x is even, then the next digit is 0.
        //  - Otherwise, we produce a digit from the low five bits of
        //    x. If these low bits have value v (odd, 1..31 range):
        //     - If v <= 15, then the next digit is v.
        //     - Otherwise, the next digit is v - 32, and we add 32 to x.
        //    When then subtract v from x (i.e. we clear the low five bits).
        // Once the digit has been produced, we divide x by 2 and loop.
        //
        // Since scalars are modulo q < 2^255, only 256 digits are necessary
        // at most.

        let mut sd = [0i8; 256];
        let bb = n.encode();
        let mut x = bb[0] as u32;
        for i in 0..256 {
            if (i & 7) == 4 && i < 252 {
                x += (bb[(i + 4) >> 3] as u32) << 4;
            }
            let m = (x & 1).wrapping_neg();  // -1 if x is odd, 0 otherwise
            let v = x & m & 31;              // low 5 bits if x odd, or 0
            let c = (v & 16) << 1;           // carry (0 or 32)
            let d = v.wrapping_sub(c);       // next digit
            sd[i] = d as i8;
            x = x.wrapping_sub(d) >> 1;
        }
        sd
    }

    /// 5-bit wNAF recoding of a nonnegative integer.
    ///
    /// 129 digits are produced (array has size 130, extra value is 0).
    /// Non-zero digits have an odd value, between -15 and +15
    /// (inclusive). (The recoding is constant-time, but use of wNAF is
    /// inherently non-constant-time.)
    fn recode_u128_NAF(n: u128) -> [i8; 130] {
        // See recode_scalar_NAF() for details.
        let mut sd = [0i8; 130];
        let mut y = n;
        for i in 0..129 {
            let x = y as u32;
            let m = (x & 1).wrapping_neg();  // -1 if x is odd, 0 otherwise
            let v = x & m & 31;              // low 5 bits if x odd, or 0
            let c = (v & 16) << 1;           // carry (0 or 32)
            sd[i] = v.wrapping_sub(c) as i8;
            y = y.wrapping_sub(v as u128).wrapping_add(c as u128) >> 1;
        }
        sd
    }

    /// Given scalars `u` and `v`, sets this point to `u*self + v*B`
    /// (with `B` being the conventional generator of the prime order
    /// subgroup).
    ///
    /// This can be used to support Schnorr signature verification.
    ///
    /// THIS FUNCTION IS NOT CONSTANT-TIME; it shall be used only with
    /// public data.
    pub fn set_mul_add_mulgen_vartime(&mut self, u: &Scalar, v: &Scalar) {
        // Recode the scalars in 5-bit wNAF.
        let sdu = Self::recode_scalar_NAF(&u);
        let sdv = Self::recode_scalar_NAF(&v);

        // Compute the window for the current point:
        //   win[i] = (2*i+1)*self    (i = 0 to 7)
        let mut win = [Self::NEUTRAL; 8];
        let Q = self.double();
        win[0] = *self;
        for i in 1..8 {
            win[i] = win[i - 1] + Q;
        }

        let mut zz = true;
        let mut ndbl = 0u32;
        for i in (0..256).rev() {
            // We have one more doubling to perform.
            ndbl += 1;

            // Get next digits. If they are all zeros, then we can loop
            // immediately.
            let e1 = sdu[i];
            let e2 = sdv[i];
            if ((e1 as u32) | (e2 as u32)) == 0 {
                continue;
            }

            // Apply accumulated doubles.
            if zz {
                *self = Self::NEUTRAL;
                zz = false;
            } else {
                self.set_xdouble(ndbl);
            }
            ndbl = 0u32;

            // Process digits.
            if e1 != 0 {
                if e1 > 0 {
                    self.set_add(&win[e1 as usize >> 1]);
                } else {
                    self.set_sub(&win[(-e1) as usize >> 1]);
                }
            }
            if e2 != 0 {
                if e2 > 0 {
                    self.set_add_affine_extended(&PRECOMP_B[e2 as usize - 1]);
                } else {
                    self.set_sub_affine_extended(&PRECOMP_B[(-e2) as usize - 1]);
                }
            }
        }

        if zz {
            *self = Self::NEUTRAL;
        } else {
            if ndbl > 0 {
                self.set_xdouble(ndbl);
            }
        }
    }

    /// Given scalars `u` and `v`, returns `u*self + v*B` (with `B` being
    /// the conventional generator of the prime order subgroup).
    ///
    /// This can be used to support Schnorr signature verification.
    ///
    /// THIS FUNCTION IS NOT CONSTANT-TIME; it shall be used only with
    /// public data.
    #[inline(always)]
    pub fn mul_add_mulgen_vartime(self, u: &Scalar, v: &Scalar) -> Self {
        let mut R = self;
        R.set_mul_add_mulgen_vartime(u, v);
        R
    }

    /// Given integer `u` and scalar `v`, sets this point to `u*self + v*B`
    /// (with `B` being the conventional generator of the prime order
    /// subgroup).
    ///
    /// This can be used to support Schnorr signature verification.
    ///
    /// THIS FUNCTION IS NOT CONSTANT-TIME; it shall be used only with
    /// public data.
    pub fn set_mul128_add_mulgen_vartime(&mut self, u: u128, v: &Scalar) {
        // Recode the integer and scalar in 5-bit wNAF.
        let sdu = Self::recode_u128_NAF(u);
        let sdv = Self::recode_scalar_NAF(&v);

        // Compute the window for the current point:
        //   win[i] = (2*i+1)*self    (i = 0 to 7)
        let mut win = [Self::NEUTRAL; 8];
        let Q = self.double();
        win[0] = *self;
        for i in 1..8 {
            win[i] = win[i - 1] + Q;
        }

        let mut zz = true;
        let mut ndbl = 0u32;
        for i in (0..130).rev() {
            // We have one more doubling to perform.
            ndbl += 1;

            // Get next digits. If they are all zeros, then we can loop
            // immediately.
            let e1 = sdu[i];
            let e2 = sdv[i];
            let e3 = if i < 126 { sdv[i + 130] } else { 0 };
            if ((e1 as u32) | (e2 as u32) | (e3 as u32)) == 0 {
                continue;
            }

            // Apply accumulated doubles.
            if zz {
                *self = Self::NEUTRAL;
                zz = false;
            } else {
                self.set_xdouble(ndbl);
            }
            ndbl = 0u32;

            // Process digits.
            if e1 != 0 {
                if e1 > 0 {
                    self.set_add(&win[e1 as usize >> 1]);
                } else {
                    self.set_sub(&win[(-e1) as usize >> 1]);
                }
            }
            if e2 != 0 {
                if e2 > 0 {
                    self.set_add_affine_extended(&PRECOMP_B[e2 as usize - 1]);
                } else {
                    self.set_sub_affine_extended(&PRECOMP_B[(-e2) as usize - 1]);
                }
            }
            if e3 != 0 {
                if e3 > 0 {
                    self.set_add_affine_extended(&PRECOMP_B130[e3 as usize - 1]);
                } else {
                    self.set_sub_affine_extended(&PRECOMP_B130[(-e3) as usize - 1]);
                }
            }
        }

        if zz {
            *self = Self::NEUTRAL;
        } else {
            if ndbl > 0 {
                self.set_xdouble(ndbl);
            }
        }
    }

    /// Given integer `u` and scalar `v`, returns `u*self + v*B` (with
    /// `B` being the conventional generator of the prime order subgroup).
    ///
    /// This can be used to support Schnorr signature verification.
    ///
    /// THIS FUNCTION IS NOT CONSTANT-TIME; it shall be used only with
    /// public data.
    #[inline(always)]
    pub fn mul128_add_mulgen_vartime(self, u: u128, v: &Scalar) -> Self {
        let mut R = self;
        R.set_mul128_add_mulgen_vartime(u, v);
        R
    }

    // Recodes a scalar into up to 52 signed digits.
    //
    // The width (w) must be in 5 to 8 range. Number of digits and
    // range of each digit depends on the width, and the top digit is
    // a special case:
    //
    //    w   num   min   max  top-max
    //    5    52   -16   +15     1
    //    6    43   -32   +31     8
    //    7    37   -64   +63     8
    //    8    32   -128  +127   128     (+128 is encoded as -128)
    //
    // Note: for 5 <= w <= 8, the number of digits is floor(260/w).
    fn recode_scalar_ext(n: &Scalar, w: i32) -> [i8; 52] {
        assert!(w >= 5 && w <= 8);
        let mut sd = [0i8; 52];
        let bb = n.encode();
        let mut cc: u32 = 0;             // carry from lower digits
        let mut i: usize = 0;            // index of next source byte
        let mut acc: u32 = 0;            // buffered bits
        let mut acc_len: i32 = 0;        // number of buffered bits
        let t = (1u32 << (w - 1)) - 1;   // threshold for sign/carry
        let vm = (1u32 << w) - 1;        // chunk mask
        let cm = 1u32 << w;              // window value
        for j in 0..Self::num_recoded_digits(w) {
            if acc_len < w && i < 32 {
                acc |= (bb[i] as u32) << acc_len;
                acc_len += 8;
                i += 1;
            }
            let d = (acc & vm) + cc;
            acc >>= w;
            acc_len -= w;
            let m = t.wrapping_sub(d) >> 8;
            sd[j] = (d.wrapping_sub(m & cm)) as i8;
            cc = m & 1;
        }
        sd
    }

    // Get the number of digits in a recoded scalar for a given window
    // width (5 to 8).
    fn num_recoded_digits(w: i32) -> usize {
        260 / (w as usize)
    }

    /// Given two lists of scalars `s_i` and points `P_i` (provided as two
    /// iterable objects, set this point to `\sum s_i*P_i`. The two lists
    /// MUST have the same length. This function applies Pippenger's algorithm.
    ///
    /// THIS FUNCTION IS NOT CONSTANT-TIME; it shall be used only with
    /// public data.
    pub fn set_xmuladd_vartime<I, J>(&mut self, scalars: I, points: J)
        where
            I: IntoIterator,
            I::Item: Borrow<Scalar>,
            J: IntoIterator,
            J::Item: Borrow<Self>,
    {
        // Collect all points, and convert them all to affine (extended).
        // We can use a batch inversion on the Z coordinates.
        // We first create the PointAffineExtended structures, with e, u and t
        // set to E, U and Z, respectively.
        let mut pp: Vec<_> = points.into_iter().map(|p| {
            let r = p.borrow();
            PointAffineExtended { e: r.E, u: r.U, t: r.Z }
        }).collect();
        let n = pp.len();
        // We now batch-invert all Z coordinates.
        let mut zz = Vec::<GFp>::with_capacity(n);
        for i in 0..n {
            zz.push(pp[i].t);
        }
        GFp::batch_invert(&mut zz[..]);
        // We propagate back the inverses to fix all affine representations.
        for i in 0..n {
            pp[i].e *= zz[i];
            pp[i].u *= zz[i];
            pp[i].t = pp[i].u.square();
        }

        // Adjust number of buckets depending on size of input.
        // Some rough benchmarking with various numbers of points (n)
        // and window size (w) yielded these values (in clock cycles,
        // on an Intel i5-8259U at 2.3 GHz, Rust compiler 1.77.2,
        // with flag '-C target-cpu=native'):
        //      n      w = 5     w = 6     w = 7     w = 8
        //     100    7027332   7348788   8442832  10325476
        //     200   12130020  11787996  12653408  14876330
        //     300   17295658  16148224  16550730  18735672
        //     400   22474350  20506440  20351398  22192916
        //     500   27588466  24670988  24124692  25596360
        //     600   32701872  29214516  27930690  28930000
        //     700   37887610  33500780  31653746  32276674
        //     800   43099892  37888676  35566980  35663102
        //     900   48257408  42327264  39274256  38969788
        //    1000   53379008  46652806  43145590  42298562
        //    1100   58474250  51066746  46917582  45603456
        //    1200   63713838  55407826  50741862  48967392
        //    1300   68690520  59623172  54393972  52119948
        //    1400   73844728  64030814  58189806  55444314
        // The choice of w below follows these measurements to try to
        // get the best performance (on any particular platform, optimal
        // thresholds may vary, but these ones should be reasonably good
        // everywhere).
        let w = if n < 200 {
            5
        } else if n < 400 {
            6
        } else if n < 800 {
            7
        } else {
            8
        };

        // Do Booth recoding for all provided scalars. We also check that
        // the number of scalars matches the number of points.
        let ss_booth: Vec<_> = scalars.into_iter()
            .map(|s| Self::recode_scalar_ext(s.borrow(), w)).collect();
        assert!(ss_booth.len() == n);
        let num_digits = Self::num_recoded_digits(w);

        // Digits are in the -2^(w-1)..+2^(w-1) range (inclusive). By
        // adding either P or -P to a bucket, we can work is 2^(w-1)
        // buckets (we do not need a bucket for digits of value zero).
        let num_buckets = 1usize << (w - 1);

        // Allocate buckets.
        let mut qq: Vec<_> = (0..num_buckets).map(|_| Self::NEUTRAL).collect();

        // Process top digit of all scalars. The top digits are always
        // non-negative, so we can convert them to `u8`, which handles the
        // special encoding of the top digit when w = 8.
        for i in 0..n {
            let d = (ss_booth[i][num_digits - 1] as u8) as usize;
            if d != 0 {
                qq[d - 1].set_add_affine_extended(&pp[i]);
            }
        }

        // The accumulator ultimately receives the result.
        *self = Self::NEUTRAL;

        // Each loop assumes that buckets for digit j have been filled,
        // and empties them into the accumulator. If j == 0, the computation
        // is finished; otherwise, it fills the buckets for digit j-1.
        for j in (0..num_digits).rev() {
            // Add buckets with multiplicity, into the accumulator.
            // We skip the top empty buckets.
            let mut S = Self::NEUTRAL;
            let mut sz = true;
            for k in (0..num_buckets).rev() {
                let bucket_full = qq[k].isneutral() == 0;
                if sz {
                    if !bucket_full {
                        continue;
                    }
                    sz = false;
                    S = qq[k];
                } else {
                    if bucket_full {
                        S += qq[k];
                    }
                }
                *self += S;
            }

            // If we have processed the buckets for digit 0 then we are done.
            if j == 0 {
                break;
            }

            // Reset buckets.
            for q in &mut qq {
                *q = Self::NEUTRAL;
            }

            // Fill buckets for digit j-1. This is for non-top digits, hence
            // they can be negative, but there is no special encoding
            // (maximal non-top digit with w = 8 is +127, not +128).
            for i in 0..n {
                let d = ss_booth[i][j - 1] as isize;
                if d < 0 {
                    qq[(-d - 1) as usize].set_sub_affine_extended(&pp[i]);
                } else if d > 0 {
                    qq[(d - 1) as usize].set_add_affine_extended(&pp[i]);
                }
            }

            // Apply the doublings on the accumulator.
            if self.isneutral() == 0 {
                self.set_xdouble(w as u32);
            }
        }
    }

    /// Given two lists of scalars `s_i` and points `P_i` (provided as two
    /// iterable objects, compute and return `\sum s_i*P_i`. The two lists
    /// MUST have the same length. This function applies Pippenger's algorithm.
    ///
    /// THIS FUNCTION IS NOT CONSTANT-TIME; it shall be used only with
    /// public data.
    #[inline]
    pub fn xmuladd_vartime<I, J>(scalars: I, points: J) -> Self
        where
            I: IntoIterator,
            I::Item: Borrow<Scalar>,
            J: IntoIterator,
            J::Item: Borrow<Self>,
    {
        let mut P = Self::NEUTRAL;
        P.set_xmuladd_vartime(scalars, points);
        P
    }
}

impl Add<Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: Point) -> Point {
        let mut r = self;
        r.set_add(&other);
        r
    }
}

impl Add<&Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &Point) -> Point {
        let mut r = self;
        r.set_add(other);
        r
    }
}

impl Add<Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: Point) -> Point {
        let mut r = *self;
        r.set_add(&other);
        r
    }
}

impl Add<&Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &Point) -> Point {
        let mut r = *self;
        r.set_add(other);
        r
    }
}

impl AddAssign<Point> for Point {
    #[inline(always)]
    fn add_assign(&mut self, other: Point) {
        self.set_add(&other);
    }
}

impl AddAssign<&Point> for Point {
    #[inline(always)]
    fn add_assign(&mut self, other: &Point) {
        self.set_add(other);
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Scalar) -> Point {
        let mut r = self;
        r.set_mul(&other);
        r
    }
}

impl Mul<&Scalar> for Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Scalar) -> Point {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

impl Mul<Scalar> for &Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Scalar) -> Point {
        let mut r = *self;
        r.set_mul(&other);
        r
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Scalar) -> Point {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}

impl MulAssign<Scalar> for Point {
    #[inline(always)]
    fn mul_assign(&mut self, other: Scalar) {
        self.set_mul(&other);
    }
}

impl MulAssign<&Scalar> for Point {
    #[inline(always)]
    fn mul_assign(&mut self, other: &Scalar) {
        self.set_mul(other);
    }
}

impl Mul<Point> for Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Point) -> Point {
        let mut r = other;
        r.set_mul(&self);
        r
    }
}

impl Mul<&Point> for Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_mul(&self);
        r
    }
}

impl Mul<Point> for &Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Point) -> Point {
        let mut r = other;
        r.set_mul(self);
        r
    }
}

impl Mul<&Point> for &Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_mul(self);
        r
    }
}

impl Mul<u64> for Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: u64) -> Point {
        let mut r = self;
        r.set_mul_small(other);
        r
    }
}

impl Mul<u64> for &Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: u64) -> Point {
        let mut r = *self;
        r.set_mul_small(other);
        r
    }
}

impl MulAssign<u64> for Point {
    #[inline(always)]
    fn mul_assign(&mut self, other: u64) {
        self.set_mul_small(other);
    }
}

impl Mul<Point> for u64 {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Point) -> Point {
        let mut r = other;
        r.set_mul_small(self);
        r
    }
}

impl Mul<&Point> for u64 {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_mul_small(self);
        r
    }
}

impl Neg for Point {
    type Output = Point;

    #[inline(always)]
    fn neg(self) -> Point {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Neg for &Point {
    type Output = Point;

    #[inline(always)]
    fn neg(self) -> Point {
        let mut r = *self;
        r.set_neg();
        r
    }
}

impl Sub<Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: Point) -> Point {
        let mut r = self;
        r.set_sub(&other);
        r
    }
}

impl Sub<&Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &Point) -> Point {
        let mut r = self;
        r.set_sub(other);
        r
    }
}

impl Sub<Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: Point) -> Point {
        let mut r = *self;
        r.set_sub(&other);
        r
    }
}

impl Sub<&Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &Point) -> Point {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}

impl SubAssign<Point> for Point {
    #[inline(always)]
    fn sub_assign(&mut self, other: Point) {
        self.set_sub(&other);
    }
}

impl SubAssign<&Point> for Point {
    #[inline(always)]
    fn sub_assign(&mut self, other: &Point) {
        self.set_sub(other);
    }
}

// ========================================================================

// We hardcode known multiples of the points B, (2^65)*B, (2^130)*B
// and (2^195)*B, with B being the conventional base point. These are
// used to speed mulgen() operations up. The points are moreover stored
// in a three-coordinate format (e, u, u^2).

/// A point in affine extended coordinates (e, u, u^2)
#[derive(Clone, Copy, Debug)]
struct PointAffineExtended {
    e: GFp,
    u: GFp,
    t: GFp,
}

impl PointAffineExtended {

    const NEUTRAL: Self = Self {
        e: GFp::MINUS_ONE,
        u: GFp::ZERO,
        t: GFp::ZERO,
    };
}

// Points i*B for i = 1 to 16, affine extended format
static PRECOMP_B: [PointAffineExtended; 16] = [
    // B * 1
    PointAffineExtended {
        e: GFp::w64be(0x80EECF52DB5F5A44, 0xF50CA81BDD9B2756,
                      0x1B9488E2D8D6D550, 0x8E570EABE5552C04),
        u: GFp::w64be(0x0000000000000000, 0x0000000000000000,
                      0x0000000000000000, 0x0000000000000002),
        t: GFp::w64be(0x0000000000000000, 0x0000000000000000,
                      0x0000000000000000, 0x0000000000000004),
    },
    // B * 2
    PointAffineExtended {
        e: GFp::w64be(0x754980D9046108EA, 0x15CDAFC33D5DB9B5,
                      0x775957C59254E127, 0x0AF8C3398540104F),
        u: GFp::w64be(0xF0B8C028BD52F9D1, 0xA83941DB536305CC,
                      0x37E26FECC4C732E7, 0x2E6AD3BA219E5406),
        t: GFp::w64be(0x1C6B77EB358915D2, 0x2DC3086820BA852D,
                      0xC23A5957CC3B5498, 0x67E0BB0225486336),
    },
    // B * 3
    PointAffineExtended {
        e: GFp::w64be(0x8A1463B25FA02609, 0x9C3CC67DA62B8C98,
                      0x1D78F1501B162479, 0x0FCEEE45497CF781),
        u: GFp::w64be(0x650D23BA765E9826, 0x126587674355C5CB,
                      0x8C39C717B9AC446D, 0x4AA95D297E2F3FA9),
        t: GFp::w64be(0xECE14A169327CEA9, 0xEA5C096A4A26D01F,
                      0xFF44027B42C999E0, 0xAB48CC1137E97C13),
    },
    // B * 4
    PointAffineExtended {
        e: GFp::w64be(0xB0CF31309427930D, 0xE891E8906D4EAE36,
                      0x40D41D37C790C213, 0x6CB6B7A0CD78955C),
        u: GFp::w64be(0x31DF1B12ADF47760, 0x729F72451066407B,
                      0x0AF08FAEDB327503, 0xC68C3025DEEEBE31),
        t: GFp::w64be(0x3C08AD70C911F6B5, 0xF74A0ABDA90F241A,
                      0x51A0DA8ADD1465BF, 0x504733A80DD559FB),
    },
    // B * 5
    PointAffineExtended {
        e: GFp::w64be(0x4EC17DC938A5FF12, 0xE362D9371FC6079C,
                      0x8BB601A5439E42FD, 0xEF69698E9EED3C4D),
        u: GFp::w64be(0x39971482BCBDC62C, 0xCD216971F266F713,
                      0x54A888606AA01EC7, 0xEDE8E349BE6E1079),
        t: GFp::w64be(0x1650FC12047F6D96, 0x03211E7C3464B9F7,
                      0xFDB3F9E8F6B02C5F, 0x486A3DE93907361F),
    },
    // B * 6
    PointAffineExtended {
        e: GFp::w64be(0xF3E86AC7C43ECC22, 0x9F1F931DC56C62F6,
                      0x700F2A9C4B70BAB9, 0xB7A4CE2FD8809972),
        u: GFp::w64be(0x91EA9DA4EB0480C2, 0x5B4EFE92E3C26D9B,
                      0xA7F6F98EEF530461, 0x01404AF8DE603845),
        t: GFp::w64be(0x4614EE32CA8259D3, 0x338151613D01CB7C,
                      0x158BE36B46A1E5D3, 0xA1ECDF10B9488760),
    },
    // B * 7
    PointAffineExtended {
        e: GFp::w64be(0x019AF0EB4AAD5B59, 0x0CDA218D32E3642A,
                      0x05E0AFC56D6D9A49, 0xD2FE5CBF578D49BD),
        u: GFp::w64be(0x2CFFC6F434246E0E, 0x57D8E95EAC87EE67,
                      0x45C2A4477F6CB9D3, 0x95770F14C1EC4A86),
        t: GFp::w64be(0xF4166F23C298A6AB, 0xBBA6ED893C827F6A,
                      0x7C851F9A8C600147, 0x72072C91617123DD),
    },
    // B * 8
    PointAffineExtended {
        e: GFp::w64be(0xED956BAEC757DBF4, 0x624B5F697053D95C,
                      0x2E97B4D1B7AF91B6, 0xCDEF1FB327CF40B9),
        u: GFp::w64be(0x437D9B4FA9F32A62, 0x9E8043F115C7EF68,
                      0xEF8F8810BF60EAA1, 0xE405275896AA3B09),
        t: GFp::w64be(0x11BF26E3144B292F, 0x2B918EDCDEFA61B9,
                      0x5FBE0F58C93E4B72, 0xE33BE33712C628C8),
    },
    // B * 9
    PointAffineExtended {
        e: GFp::w64be(0x2550E91DCA558435, 0xB276587D895D8C40,
                      0x77E0EF0842A529EB, 0xDFE9D5951BA804F8),
        u: GFp::w64be(0x34DD6C2A3DC223D6, 0xDA9DC9150F7356DF,
                      0x019172B736198DEA, 0x3C70C864AC19409E),
        t: GFp::w64be(0xA6E795C8365566A2, 0xA4231EB3F22D7326,
                      0x19BBB1EC29F07CC3, 0x79B401A45E077554),
    },
    // B * 10
    PointAffineExtended {
        e: GFp::w64be(0x183FC60288F6E2A9, 0xF94BF2956759385F,
                      0x24E0859D2FC86C90, 0xC576A9560508BEB3),
        u: GFp::w64be(0x36E6B1B822913968, 0x1504D6AAA5496B52,
                      0x9973094746C3A53D, 0xBFD92CDA390DD4FF),
        t: GFp::w64be(0x080D5F9EA93A99B2, 0x56EB4D3E3CAE126E,
                      0x1D766C8F9F77FFC0, 0xC7D70F2334D46781),
    },
    // B * 11
    PointAffineExtended {
        e: GFp::w64be(0x8DB40DBABE30C99B, 0xE5F8DE92DDF5BA30,
                      0x71EF9FFA04075A8B, 0x9853669086F3646A),
        u: GFp::w64be(0x3060DB4D15E08DD3, 0xBA02748BAFD454D1,
                      0x78D578839676BB1E, 0x447D5F45D12EE375),
        t: GFp::w64be(0xFF23A44988D59A7F, 0x33DA97B2C4AA5770,
                      0xFB3B00137F344D09, 0xA7372AE901E989DD),
    },
    // B * 12
    PointAffineExtended {
        e: GFp::w64be(0x6AAE40D1DC240E12, 0x1ACBA6533A29A563,
                      0x61CF181ECF1EFC7B, 0x66479C521A492E4B),
        u: GFp::w64be(0x628D161C563E2BC2, 0xDE9EE1949959B7EE,
                      0x671AB12B4ABF99CF, 0x0572E01B21B5822F),
        t: GFp::w64be(0xD9A339F31144E977, 0x92FFCE1EF4A9C0D4,
                      0x6636AC3D8004FCA6, 0xCE334CDFF620F40C),
    },
    // B * 13
    PointAffineExtended {
        e: GFp::w64be(0xC1A4BF9D0E791065, 0xD4D68D0036BEC901,
                      0xF87FDB15CD9854AC, 0x55569E55F6616C0E),
        u: GFp::w64be(0x77FDD57F73B1B6F0, 0x518CC5655F706CA7,
                      0x7AE6FCCB5ABF196A, 0x1B04566BA6E6ED76),
        t: GFp::w64be(0x6FD9A41081BBDBF1, 0x950C3B0DFE3AE1B0,
                      0xF43F0F977ED7EE4A, 0x82C448A4FB4DBB03),
    },
    // B * 14
    PointAffineExtended {
        e: GFp::w64be(0xCCEDC1214EA183D5, 0xC7A0945867D5B8F8,
                      0xBCC26CE6DEF37D50, 0xFC9B4AE7955B4CFB),
        u: GFp::w64be(0x05D7074D65AAD3E9, 0x7A8FFF9B66E2AFE2,
                      0x56C2D3CAA9A35734, 0x5E7E0D422F4549EF),
        t: GFp::w64be(0xE79742A1F7282845, 0xA1D308DA89880372,
                      0x8E3C22921D39E085, 0xA464B859B2256418),
    },
    // B * 15
    PointAffineExtended {
        e: GFp::w64be(0x7AB5A6CD6BC5662B, 0x81F0C9BD91CCB756,
                      0x560CF4BCEAB7EC7F, 0xCC1FEF43A995B681),
        u: GFp::w64be(0x099147802F8F5626, 0x03079F42B0F39AA5,
                      0x89BFFAA2D4329863, 0xA4E0AC70B7DAE979),
        t: GFp::w64be(0x66BA4857120473D8, 0x334C3B5D935D0588,
                      0xA65C9765974A4DDD, 0xC23B5C33FE29C40E),
    },
    // B * 16
    PointAffineExtended {
        e: GFp::w64be(0x259A9592E37D58B2, 0x1DA33E8AA1684A62,
                      0x96B8871D013D93E7, 0xB2FA92BA7C8F86CB),
        u: GFp::w64be(0xE5E71B2BD33C0EB4, 0x27CBE0177D5A8686,
                      0xFDFA4A37605C83BA, 0x2AB3FB8C446B39D3),
        t: GFp::w64be(0xD6766C7D0F495FA7, 0x296486F4A999F1C9,
                      0x82812CA0086FE921, 0x7BF0DA5E89725140),
    },
];

// Points i*(2^65)*B for i = 1 to 16, affine extended format
static PRECOMP_B65: [PointAffineExtended; 16] = [
    // (2^65)*B * 1
    PointAffineExtended {
        e: GFp::w64be(0x7EEBDC89D1CBFAA9, 0x2419E626E7B00902,
                      0xFB26824C2922A44C, 0xE270C6747BF3C5A2),
        u: GFp::w64be(0xC408FDB81A4F07CA, 0xECE24E81F47834E1,
                      0x32873D32D8A15A60, 0x54281FF53F9A7980),
        t: GFp::w64be(0x58EDF76F72454445, 0x27DE0A601C3D5C48,
                      0x72A2B27A29FF9548, 0x5A07C1CF5462C314),
    },
    // (2^65)*B * 2
    PointAffineExtended {
        e: GFp::w64be(0xEF3491E139FB7B4B, 0x90BF4E205E349549,
                      0x57D5D2DCAA865F4C, 0x61CC8B422A74B02D),
        u: GFp::w64be(0x3BDA8C2DE3AE48FB, 0x578D915AA024B96E,
                      0x9713C9C1C7843843, 0xC0509AA72B32EACB),
        t: GFp::w64be(0x5CD1DB045A2B93C4, 0x505994E2803E63ED,
                      0x4886091C1F1EF44E, 0x39A01368EBE670BB),
    },
    // (2^65)*B * 3
    PointAffineExtended {
        e: GFp::w64be(0x4D2DB1E5580CD1C3, 0x58CC706CD7500E81,
                      0xBB47E94EE715A8F3, 0xEC852585DA006E45),
        u: GFp::w64be(0x112F27873DD78E6C, 0xCBFEE6139D435B49,
                      0xE4C90DB183F0EAAA, 0x8DEC9C25F6924BC0),
        t: GFp::w64be(0x1C03DE2347C7CA11, 0xA059B4F6AD900072,
                      0x80F4258BD17C2A86, 0xA84186EC72E9B221),
    },
    // (2^65)*B * 4
    PointAffineExtended {
        e: GFp::w64be(0x516055FC2868663C, 0x8C1ABEFA28D12F9D,
                      0x9734BD8DFAE732B8, 0xACF0806A0871313C),
        u: GFp::w64be(0xF3C823B6D91C09E2, 0x41A2415CD3C1BC80,
                      0xADB1A71CF63077CC, 0x015108488556229A),
        t: GFp::w64be(0xC7325E92B836904B, 0xA172A8B29DC9F8D3,
                      0x4A492144C916FF5E, 0x17B608B15FE0776A),
    },
    // (2^65)*B * 5
    PointAffineExtended {
        e: GFp::w64be(0xFC53FE544FC97617, 0x7C6E45CB4F8BAF6E,
                      0x45F9DAE439A8714B, 0xC31D91C68F16778E),
        u: GFp::w64be(0x1EF7A8EC7BF85F92, 0xDAF1DD3F71255277,
                      0x9513DF1A0B12D0CD, 0xEAF27DBC1F1DB0A5),
        t: GFp::w64be(0x281B2C7C1D93FB30, 0x82EEB2840A6DF5D5,
                      0xA52A14600DA39F17, 0xDEFC0A3E8E1432C4),
    },
    // (2^65)*B * 6
    PointAffineExtended {
        e: GFp::w64be(0x0E62A2BB64878922, 0xA65ABB0CE1F01B00,
                      0x716DD76B3EDFF4C8, 0x33396BE7482C0C5A),
        u: GFp::w64be(0x5BC81E17258A41D8, 0xE5D58D07D692F0A9,
                      0x76C0D3118F6E2399, 0x2782AEE3F95691AA),
        t: GFp::w64be(0x58437CA9095317C0, 0xF8C5B1557FAD6FE1,
                      0x844E5961FFB83907, 0xC3DAE9566914D1F0),
    },
    // (2^65)*B * 7
    PointAffineExtended {
        e: GFp::w64be(0x12C110144498FC33, 0xFCC9E289547278CA,
                      0x1BE741A0ABF9032D, 0x7C4DDC9F43A4C4DB),
        u: GFp::w64be(0xF535ABDD686E49E2, 0x573A47E388781B68,
                      0x28FB0867FD72DE01, 0x4047BE745D6564B2),
        t: GFp::w64be(0x73326A00C74AC27A, 0xC347396D67A805E9,
                      0x37145C9E2A276BA9, 0x45F50EC92D1CD389),
    },
    // (2^65)*B * 8
    PointAffineExtended {
        e: GFp::w64be(0xE01E1A5273E1CE54, 0x9AE6B77BD00F64FA,
                      0x0959AF4A7CF51F22, 0x752A8A999FD09C5C),
        u: GFp::w64be(0x1F545DF41EDEADBF, 0x890CB0106EAC6AA7,
                      0xF1F8649758FDC39C, 0x1B42B4A56D3F3C23),
        t: GFp::w64be(0xA13204B9F3070657, 0xB0BECF5EE24618D9,
                      0x2AB188D1269970DE, 0xECAA4D2688AD2D7C),
    },
    // (2^65)*B * 9
    PointAffineExtended {
        e: GFp::w64be(0x268B4B3C8822F0DB, 0xC57ED7EDA80A7D1D,
                      0x3AC4AF7DE0594B90, 0xC7133350BD661C7C),
        u: GFp::w64be(0x7162DDA9D57EC5A6, 0x12F555216AC05812,
                      0x08ACEEBA66D162A8, 0xC2BB222D7813AA60),
        t: GFp::w64be(0x666CA696946037ED, 0xBFBDD07A05BD930B,
                      0x64EF435B0A3F9863, 0xCBF020442D500465),
    },
    // (2^65)*B * 10
    PointAffineExtended {
        e: GFp::w64be(0x221CBF34FB8DD9CD, 0x76D34C6B64D6E23D,
                      0xFBF4CDEC92BA2C54, 0x94634AAFACFF3270),
        u: GFp::w64be(0xC9255DE3E4400E13, 0x61011A2A33AAEBC3,
                      0x3A57D9F4B4C1C8E5, 0x96F63FEFD739E8E5),
        t: GFp::w64be(0x5F18BF1D4EADD054, 0x6ADB8FE4D6F68272,
                      0x6767096B62C4D2B6, 0xBD3F631857E3087C),
    },
    // (2^65)*B * 11
    PointAffineExtended {
        e: GFp::w64be(0x1A70CD5054F3F5AE, 0x2C48D260CFAF1DF1,
                      0xE6AB4EC3F5AEA380, 0x57737AF96AE62D2A),
        u: GFp::w64be(0xEE4AB762003D61F0, 0xD09763BF3DB9D6E5,
                      0xD4A624B5584ABAC1, 0xF6EDB0940F72037D),
        t: GFp::w64be(0x84781682D93F5398, 0x139F5F92FCBC72AE,
                      0xF7713B47F0FC1561, 0xBA0F42D58A82DE36),
    },
    // (2^65)*B * 12
    PointAffineExtended {
        e: GFp::w64be(0x5BD008669F54BDC9, 0x867835DBF6858321,
                      0xDF7A22F47DC8D05A, 0xFCF5CBED236C4B26),
        u: GFp::w64be(0x47BBD4FCBBB69BD0, 0x52E03ACF56DEE0FB,
                      0xD34361B07D9ADA04, 0x33BD2D271B14BC99),
        t: GFp::w64be(0x0E18C9FE204CB892, 0x539108625BE3C633,
                      0x3F9848454D249713, 0x7AC63BCBCD5C2FE8),
    },
    // (2^65)*B * 13
    PointAffineExtended {
        e: GFp::w64be(0x05B06EEF36F58443, 0xCA797231B630DC0D,
                      0xB21AFCE239B7D9E7, 0x3157469822032A95),
        u: GFp::w64be(0x55BB0E803788C9E6, 0x3254DF6FE4FC5108,
                      0xD208CAC0191A85A8, 0x638B82FAE9D24083),
        t: GFp::w64be(0x5552926512C8908B, 0xCD7BFD2C5DACA89F,
                      0x35D0E3CE5A2F8B88, 0xA501A30E6A223857),
    },
    // (2^65)*B * 14
    PointAffineExtended {
        e: GFp::w64be(0xEF85B3FC2E675AD2, 0x919F55C3F9CD9C9C,
                      0xBEE5520B2B952947, 0xA4825DD177C5CBD0),
        u: GFp::w64be(0x1BFCCFE6DEB3A97F, 0x6FB2718D7EF97B9E,
                      0x4239E7CEB1C7C81F, 0xF417AA29B2DE781C),
        t: GFp::w64be(0xF30C0882C4893D3F, 0x43A4ECA2175718EA,
                      0xAB2C434C361553B9, 0x35FDC838E8CC36BC),
    },
    // (2^65)*B * 15
    PointAffineExtended {
        e: GFp::w64be(0x1DE3F7AE3173F0D7, 0x4934A70A4BBE73F8,
                      0x487B05A92496F7E7, 0x82B70E822A17AE76),
        u: GFp::w64be(0x8392C57AA97E0EC2, 0xA281466C3C92101A,
                      0xB3702F0D63EFFF9C, 0x37DD333C15E66B69),
        t: GFp::w64be(0x020D69BD2B642826, 0x6EB4EC849EB44275,
                      0xA7A54B372EC3AC21, 0x8B7ABE779B43850B),
    },
    // (2^65)*B * 16
    PointAffineExtended {
        e: GFp::w64be(0x4D6DFD89EB9168EF, 0xFC5A080B0BB337A8,
                      0x712A710587AA5420, 0x53FDD0257A7B7A78),
        u: GFp::w64be(0x293663EA0B23A093, 0x8D2F9B2C13A87673,
                      0x1D2B5FF52AD3A776, 0xC26EDB8255D3A269),
        t: GFp::w64be(0x15CFBE1720B675B9, 0x604B42B307DF0AF0,
                      0x7643FD813204FEFA, 0x6F1A749791AEF12D),
    },
];

// Points i*(2^130)*B for i = 1 to 16, affine extended format
static PRECOMP_B130: [PointAffineExtended; 16] = [
    // (2^130)*B * 1
    PointAffineExtended {
        e: GFp::w64be(0x599C4377D2973838, 0xF3E54EE7A02CECC3,
                      0x321225E4D3C4456D, 0xF1942D6DCE7085DB),
        u: GFp::w64be(0x37066E03AD437E47, 0x4892FE5F44D39462,
                      0x286FB241A7AF021F, 0x7150D6CF2CE6355E),
        t: GFp::w64be(0x4612185911E38904, 0x17F41F57645633B4,
                      0xC38F94B06631402A, 0x918759F71568E2E7),
    },
    // (2^130)*B * 2
    PointAffineExtended {
        e: GFp::w64be(0x445408F2E99D15B5, 0x86A3AD9B5ACF58F7,
                      0x7567A424725542A4, 0x717B483B0F757F8F),
        u: GFp::w64be(0xBAF161489E698CE8, 0x18A143A6EA22BAB1,
                      0x1CAA7109B672B1A4, 0xC0621919145BDD1E),
        t: GFp::w64be(0xBCFF93FABC843A97, 0xB381CCC83AEB5310,
                      0x05E0C47429E73F07, 0x84E549B9CA57B9CA),
    },
    // (2^130)*B * 3
    PointAffineExtended {
        e: GFp::w64be(0xAF7C6EA0FC0D30A2, 0x5D9BCD4F320C4B87,
                      0x4C477E9ECC8F6447, 0x178BBB97F2F2BCC7),
        u: GFp::w64be(0xECC2A9207D5B8448, 0x7E4FAFB874FC7085,
                      0x8A7C4AD20B3CAA3E, 0x6CF12D9B9B72363F),
        t: GFp::w64be(0x435C6028ABF356FA, 0xAA6EB56A649B93F3,
                      0x8C4FE6AA93EDCB6E, 0xA716901AE4F580AE),
    },
    // (2^130)*B * 4
    PointAffineExtended {
        e: GFp::w64be(0x3E8E5D21B8539A19, 0x2550BE0E1ADE1DEC,
                      0x3E3CE3A3CCDF3D12, 0xA87BCBCD3817E1D1),
        u: GFp::w64be(0xD04B5F05C6FB1512, 0xD679BC7F64A6DFAB,
                      0x58EE4B900F24E654, 0x2B4B103608FEDA69),
        t: GFp::w64be(0x3941C0B876396D74, 0x174FC9FC62636662,
                      0xA72377E9901282AC, 0x9413BC10CAFDE6F9),
    },
    // (2^130)*B * 5
    PointAffineExtended {
        e: GFp::w64be(0x129D8493A46BF962, 0xC197D15E465EC6A5,
                      0xD2CAED56DA8008E8, 0xC1D9F92C1E831264),
        u: GFp::w64be(0x09EFA132BBAB6DCE, 0xD482283BCD4DA1AE,
                      0x24D49CB871B24534, 0x7BB50533145DB021),
        t: GFp::w64be(0xE646C9871B6E2B20, 0x334FBF780148A1D9,
                      0x214E0BF123CF4776, 0x20C1B63A76066F2F),
    },
    // (2^130)*B * 6
    PointAffineExtended {
        e: GFp::w64be(0x00975FA87FFA507C, 0x06FE045808A8ECCE,
                      0x103CCCB8C23D5F47, 0x03A169E8F1BFEB6C),
        u: GFp::w64be(0xCBDF2D4583E049D8, 0x129D1838ABE4BE9F,
                      0xF7A3EC0BF7EA367B, 0x21EA2AE371837CB7),
        t: GFp::w64be(0x17630878A37ED39D, 0x753B964379F0696C,
                      0x074EF904A130A120, 0xFDCEE6C7C512A495),
    },
    // (2^130)*B * 7
    PointAffineExtended {
        e: GFp::w64be(0xE49CA1DBE5285EDB, 0xA86360DF816CCF94,
                      0x82FE5EC77D7A78F2, 0x8F4CE0230491C607),
        u: GFp::w64be(0x05870E9772B6798E, 0xC3651674E664BC33,
                      0x48914008FBE7D16A, 0xFD1CC728BED4BEF2),
        t: GFp::w64be(0x1B064E7966C46F50, 0xE3107252BDC9A37F,
                      0x74B4293E9B116BE2, 0x22428B4E9C3582DA),
    },
    // (2^130)*B * 8
    PointAffineExtended {
        e: GFp::w64be(0x8D17CC99B691C798, 0xF138272E43AF51B3,
                      0x88BC068A2C7577B4, 0x9C0972293FA72FC6),
        u: GFp::w64be(0xC7584E6298F900AD, 0x862BD9E6BA32D533,
                      0xD826B29AAD0F0900, 0x19C5844E2885C378),
        t: GFp::w64be(0x4250016E4DD33706, 0xE4A9F4CC99985391,
                      0x441288A875A42E15, 0x3F09EEDCB3B53DEF),
    },
    // (2^130)*B * 9
    PointAffineExtended {
        e: GFp::w64be(0x640BF748916DDCE6, 0xB2F7BC0D75ABCF59,
                      0xAD3156C01169881B, 0x5AD5972B02D52E66),
        u: GFp::w64be(0x13DF69066BCC4C1B, 0xF7D30B6E1A392338,
                      0x3FD2D4476F607F07, 0x90DD6EC51A170783),
        t: GFp::w64be(0x20791F49E12CBB52, 0xFF9B67206781A6C5,
                      0x4EDF7AB48F01FE33, 0x29D25110324479E2),
    },
    // (2^130)*B * 10
    PointAffineExtended {
        e: GFp::w64be(0x0D13CB0B83A4E436, 0x215A090E23E009BA,
                      0xB1E7AD6E83BA630F, 0x1076716277FE965A),
        u: GFp::w64be(0x8B8F72DEA9CB6892, 0x51468E721EB2F0C7,
                      0xED7FCE377222D475, 0x98A114985034DB0F),
        t: GFp::w64be(0xCC7888B5D7F7EF38, 0xB1E8BC2FCFCBCCBD,
                      0x3B5CBE6565AFC603, 0x4E0AED79FE591565),
    },
    // (2^130)*B * 11
    PointAffineExtended {
        e: GFp::w64be(0x2C1EB2458B6E338B, 0xB9A07BA5C0E026D5,
                      0x8869FC1062CB6E15, 0x24B295671CEA742C),
        u: GFp::w64be(0x1A63AFF1EAEA17A2, 0x377A180210DE7B45,
                      0xFB5FF47A4311102D, 0x59F5C1F87FCE791C),
        t: GFp::w64be(0x9AFB1CAA349EB703, 0x0B44889E03D380C1,
                      0xB6684A67AC106FEE, 0x060C6F83F4055B5F),
    },
    // (2^130)*B * 12
    PointAffineExtended {
        e: GFp::w64be(0x7EA4E5F700925A9C, 0xDD939FD79D89B312,
                      0xB1F9181FAEF153B4, 0x9A1176B1DF2DE18B),
        u: GFp::w64be(0xCCF7B8C9F78AEF40, 0x5F3C905CEAF1DA81,
                      0x6332D28A1772F312, 0xAA27601DCD047263),
        t: GFp::w64be(0x0AC9F9EBDA208C1A, 0xED3130BDBC5E98C0,
                      0x761D3CE91C6614FA, 0xB27CA46016747DB7),
    },
    // (2^130)*B * 13
    PointAffineExtended {
        e: GFp::w64be(0x8606E25235257F89, 0xA74113BEFF43C49C,
                      0x3C197D7BEF53A193, 0xBB9E9D74F8C48374),
        u: GFp::w64be(0xFEBF6136BC0F2898, 0x5950CB04DF58C68C,
                      0x6A562AB45E4B0E95, 0xE051AF6018F320D1),
        t: GFp::w64be(0x0E2C80FB7A428078, 0x334120BC0DFC1AB8,
                      0xEA88C380F1EB599A, 0x24FC6308FEE4A0F8),
    },
    // (2^130)*B * 14
    PointAffineExtended {
        e: GFp::w64be(0x82EB6B222F622C21, 0xB518819B6F6D4CBE,
                      0xE28F8AF2712EE245, 0xA4B264991C0FE6D6),
        u: GFp::w64be(0x9CEC0B4941178C7A, 0x333309ADB8AEDB75,
                      0x61C189D7300547CF, 0xDAA937E63DB87B29),
        t: GFp::w64be(0x6D5F943ECE38CCAD, 0x7446D4E47D7F5FF0,
                      0xD05016EDC25F88EA, 0x9C12A02FD92E5065),
    },
    // (2^130)*B * 15
    PointAffineExtended {
        e: GFp::w64be(0x705C40FAF4E18D73, 0x10F2EC67589314EB,
                      0xDB806DDA9FB6B721, 0x86CBC4225CD1FD01),
        u: GFp::w64be(0x7A241CA54226F148, 0x97D945AB88735A1F,
                      0x1CB387861F1BDEF3, 0x35DAE05979E12A2F),
        t: GFp::w64be(0x0FC1714DE936EA68, 0x12C3787FD7DE6B8E,
                      0xCAA288E681ED4674, 0xA1CC22F3C9D8CB6D),
    },
    // (2^130)*B * 16
    PointAffineExtended {
        e: GFp::w64be(0xFFA87BFE9791DEAC, 0x61D4DD21759CD85B,
                      0x2FC5DDB17FFA38F1, 0xA423F1C1F35C1764),
        u: GFp::w64be(0x6C800341A6E661C9, 0xA0240AC06CE8FBC1,
                      0x2F19E1987996463C, 0x3B03D19EFAF0FEE6),
        t: GFp::w64be(0xC943E2CAD4B644DA, 0x967C6AE6BC2AF126,
                      0x7193EE118EEE4A18, 0x4D95F9D6D1F00E02),
    },
];

// Points i*(2^195)*B for i = 1 to 16, affine extended format
static PRECOMP_B195: [PointAffineExtended; 16] = [
    // (2^195)*B * 1
    PointAffineExtended {
        e: GFp::w64be(0x6984FA5FD8351EA0, 0x3C4398320B13EF49,
                      0xFC59A8F1266F50E9, 0xCF10980DF8CF9EDE),
        u: GFp::w64be(0x02CC8D1FDA2B07FB, 0xD20D750B3AE1C420,
                      0x923939431B7F9DB9, 0xC1A8F6E289019BA2),
        t: GFp::w64be(0x8361F125A136D250, 0x180402D298121834,
                      0xAC8E6CB697983873, 0xCD9FDADA4925AEC3),
    },
    // (2^195)*B * 2
    PointAffineExtended {
        e: GFp::w64be(0x38E076EBA74B437D, 0xC63F5962092C1E46,
                      0x1485DE2D7EEE4D3D, 0x4DFD533DC1FF57E0),
        u: GFp::w64be(0x32DA524D8BD52738, 0xDE320853BBF83BC9,
                      0x559486F8C4A88104, 0xF0FB693DC3574BF3),
        t: GFp::w64be(0x5289F57EB56E777C, 0x84DD59578BBF7C8F,
                      0x53C3A0CDB00FB77A, 0x7F9757CB8A8C1C17),
    },
    // (2^195)*B * 3
    PointAffineExtended {
        e: GFp::w64be(0xB98305439BE27E00, 0x04AB543C070A5966,
                      0x6EDE5FAE6D30A747, 0x7C295A0301B9DA75),
        u: GFp::w64be(0x7D7CFC1BDA86A30B, 0xB46B89EAFF81A28C,
                      0x1363263FCB83701C, 0xEFE042A19184F187),
        t: GFp::w64be(0xBA4362498B6E714A, 0x754A609AB4C28D21,
                      0x2DBF2B8F0E9516D2, 0x6BA8BB6C12337B5B),
    },
    // (2^195)*B * 4
    PointAffineExtended {
        e: GFp::w64be(0x889772BBC6C40AA7, 0xE381B59F5BF7148F,
                      0x04CA1E55CB2DE24A, 0xA91E1CC942CAD3F0),
        u: GFp::w64be(0x01716EA549482B46, 0x4C53695136CBAE9C,
                      0x690396AB4D863C92, 0xD31E11D887EB0CB5),
        t: GFp::w64be(0xDD0C2E561772646A, 0x8CEF18811B8625CB,
                      0x297789121EA0FF01, 0x551E1B20F06EDD74),
    },
    // (2^195)*B * 5
    PointAffineExtended {
        e: GFp::w64be(0x653B33AAFCA82464, 0x9755FD41B62F092E,
                      0xB2D670AE39B8E81E, 0x5CFB2084143F8B52),
        u: GFp::w64be(0x7BA5B547CC9C6A13, 0xA482B77085AFCAAC,
                      0xBB58520E3DF0E2FB, 0xE5D6F4173CD79837),
        t: GFp::w64be(0x4563268B3AD3E9BA, 0x23097775D4CACA0F,
                      0xC02D734442921CE2, 0xB71E96D50C6B536E),
    },
    // (2^195)*B * 6
    PointAffineExtended {
        e: GFp::w64be(0x8A79BBEC30894DAC, 0x4D01C101C6FA6AA3,
                      0xD174EEFC5FFA4460, 0xA0965CC26E9DDA57),
        u: GFp::w64be(0xA4B47D75B3DFC2A4, 0xB4A30A9FE39834F0,
                      0x67D9C1776C85A54C, 0x223FEE4A89CF4AAF),
        t: GFp::w64be(0x895682286425ADC2, 0x037CABED9C0A4ABF,
                      0x06A81F003EC1F2A5, 0x032853CA2951B4ED),
    },
    // (2^195)*B * 7
    PointAffineExtended {
        e: GFp::w64be(0x0014B50FAB28038B, 0x87FAD7F230F573A8,
                      0xEA250773B4DB6EC5, 0xCE4D3232A967558F),
        u: GFp::w64be(0xFB1CB99F0CAAB8AC, 0xBA5C81A062866457,
                      0x64934F9254624ACB, 0xFD12417A55BC99BC),
        t: GFp::w64be(0xE5B2C18A29CF8067, 0xF3DF6B4B3FC252C7,
                      0x3E9F6892577B7EDA, 0x51EE4620496AB523),
    },
    // (2^195)*B * 8
    PointAffineExtended {
        e: GFp::w64be(0x744D3431548799D2, 0xD71FAAD51F8F6083,
                      0x1B15F92A5507849F, 0x3A22C32BBCB51589),
        u: GFp::w64be(0x24D2F6FB70AE82A6, 0x62F7AA2B7321DEF7,
                      0x77DF9C6A5189B43D, 0x196C644C3A7C5AD7),
        t: GFp::w64be(0x898A06157FAB9CB6, 0xD0769AC548228A77,
                      0xDC2B915A54C01DDD, 0x87ADA3B969455F6E),
    },
    // (2^195)*B * 9
    PointAffineExtended {
        e: GFp::w64be(0x95C89D58CA789F41, 0x3D4D51FE24E6400C,
                      0xDBAB19F15A12049C, 0x4A8B9027455C0BE2),
        u: GFp::w64be(0xED7F0BC5959EB2F0, 0x285DEE80EB6DB207,
                      0x93D373617509D0BE, 0x693E3ABB506C1C98),
        t: GFp::w64be(0x0246C92D5B5C5F3D, 0xA832CE5EEFAF7348,
                      0xBB145B64501BE12C, 0x9660D84323548454),
    },
    // (2^195)*B * 10
    PointAffineExtended {
        e: GFp::w64be(0x2D586E0E6547EBE5, 0xB657DF427E9C997C,
                      0x5A38963A20CF007C, 0x73A9DE0FA1326A43),
        u: GFp::w64be(0x12F7B0975D2C3A1C, 0x35CE861F4E6BA5F9,
                      0x1465902198E5E3B2, 0x25C4F5FC601885B1),
        t: GFp::w64be(0x73A07E46C2432EF4, 0xB0693FF0C900FD8C,
                      0xFEF97E54B1F20E3E, 0x7D584BB099AC971C),
    },
    // (2^195)*B * 11
    PointAffineExtended {
        e: GFp::w64be(0xF79F1715358223A8, 0x649FB6D3708C796D,
                      0xBBBE86301ED8BB55, 0xB75B0675BC8FC788),
        u: GFp::w64be(0x5798ED78E0844447, 0x03E591E48B574455,
                      0xFEBA85E2BC751276, 0xC708E8F1FE871265),
        t: GFp::w64be(0xD2B33B8694701D00, 0x3AAE74E086F94633,
                      0x033DA2C81AC9BB4A, 0x97BE717DB1A31E22),
    },
    // (2^195)*B * 12
    PointAffineExtended {
        e: GFp::w64be(0x9F1F814B3FE1549F, 0x3C7798245BBD42A8,
                      0xA816B52283543620, 0xD8081CA0F0463D37),
        u: GFp::w64be(0x322DE3AA00D07711, 0x1E153428374F1AF6,
                      0x0D6CD8F01E40F52E, 0x0A415396E1CBEA98),
        t: GFp::w64be(0x4C81D23DB00B1815, 0x22D959966A0994F8,
                      0xE2967682C3174969, 0xED9E5F3990904AFE),
    },
    // (2^195)*B * 13
    PointAffineExtended {
        e: GFp::w64be(0x402CE80A875D3C38, 0x4445133534783D6B,
                      0xD2F8724DF6F2DB7D, 0xA9CA3F2B02162B06),
        u: GFp::w64be(0xAB72FBCC3E718D31, 0xD050203D0B58CF41,
                      0xA5F0B57CCBF63E85, 0x015C076F84296789),
        t: GFp::w64be(0x20F7153F9489C4C0, 0xA9ADF270E8139E3C,
                      0xCA05B0128461403A, 0x274E849036BF75A1),
    },
    // (2^195)*B * 14
    PointAffineExtended {
        e: GFp::w64be(0xAD97C35EAAECF043, 0xF4A0AD684580E0A7,
                      0xD26FAB309D2D467B, 0xD27B13A4271428BB),
        u: GFp::w64be(0x683B56B117B47018, 0xA7A03A86A3B17F1D,
                      0xBF00911330B3C911, 0x404FEB685E3FACB8),
        t: GFp::w64be(0xE301B17564CA9EBF, 0x0A2AFB98632179BB,
                      0xAED38A7E52C0393A, 0xB08422ED055CF6C3),
    },
    // (2^195)*B * 15
    PointAffineExtended {
        e: GFp::w64be(0xC35F4798670C2E9F, 0x959A6E5BBD688678,
                      0x8D4222C5BED76FE6, 0xFC3C1A1FA9B742B3),
        u: GFp::w64be(0x58C51D0A2D22312D, 0x33AA528283AD3C82,
                      0x4F27E67934B55D1C, 0x9F9F9B98D538E40D),
        t: GFp::w64be(0x5B5429BDF55E274E, 0x6AD507525585B0A4,
                      0x8ADE3EC013E0ED0F, 0xAEC066CA3945EA02),
    },
    // (2^195)*B * 16
    PointAffineExtended {
        e: GFp::w64be(0xA3AB8FB5AAD2C9CA, 0xD16BA675043D232C,
                      0x3C32565F120B2BC9, 0x789DE4775664C2DC),
        u: GFp::w64be(0x09608F66D036E2B3, 0xBB35549B10798986,
                      0x82D6DEE66D5CCEE5, 0x33A76457A70EB1B4),
        t: GFp::w64be(0xE78DE6DD7E96C507, 0x078DC64B62F7176B,
                      0x9846BB38449E6CF0, 0x2EEFBC620D80CD86),
    },
];

// ========================================================================

#[cfg(test)]
mod tests {

    use super::{Point, Scalar, GFp};

    use sha3::{Sha3_256, Sha3_512, Digest};

    /* unused

    fn print_gf(name: &str, x: GFp) {
        print!("{} = 0x", name);
        let bb = x.encode();
        for i in (0..32).rev() {
            print!("{:02X}", bb[i]);
        }
        println!();
    }

    fn print(name: &str, P: Point) {
        println!("{}:", name);
        print_gf("  E", P.E);
        print_gf("  Z", P.Z);
        print_gf("  U", P.U);
        print_gf("  T", P.T);
    }
    */

    static KAT_DECODE_OK: [&str; 21] = [
"0000000000000000000000000000000000000000000000000000000000000000",
"c6754db6934cc2d29b2e79fbaa307c28b203c09b4da579e7a859efd96f00b9f4",
"8201c50a097fae5f05409b39f3cca443cc61a64be370adf34e163b70dc27224c",
"fe13705fba513fddcbe17413c5a433d335d60f92bbea5dfdf8e22b5d121beb11",
"66063ca155b48d432788d85b6b6b4ba4d06ec5e9300b34d1eded82d8fb2b772a",
"1eb98b682d8032524565a03cbdfd06f1bc8f1fb134a22b909572a6ae4170388e",
"d934a16d351714d7e3473326f105ef8175b20c52558ba5f1f7b215ff34fd95ea",
"b69a35030f2bcca39ed6de56b7904f715df631c52b6104da149308eea0f49948",
"1ddf6cfd9bd0b3cc6de021c87a414c03cd10d035323bb3d937b05d86e7495e3d",
"f92d9f63ca31906e4ce659538a0165be2dbe63a75704c622e4fa6dd3d26a39f8",
"1413f10fdc7d19a68822bb08c0cb647c4a6c19ba2309d7d4e133bdd060fe316f",
"39d0a8abed2cd6f291b86f7c2842a2f4f59a92f8080eb7f7e14c74784718a36b",
"60f093f064a1fd252c0b9daae4c806dc38216bebf850a5643b906ea5880c752b",
"0e6db31ec74c8f31118930563a1d2b1557d9fef6a25cef6a8a721a6895f5f49b",
"d904ab90469e7f6befdb354b773cb2e442f801ae8381305a793cd0a9ad13ada9",
"36dab53b7a197f1a4ea68a09d6cc487a2bf3abb429b3dc6f1744c614aa1fe55c",
"e6ea9da7e62d6da3181ea8642748023ba81ba8e130a7f0e47a83b029466ec167",
"a454b7cbc0a06c4c98c531fe4bb421ac7dd8ff46ab43d504e63cc5118d043f7a",
"7d22bf28fc58e6ce0683d846fa25563a2c47b7c106dcde16a1a209170bc5c305",
"d2b83f15a10d977755b81362ec3f6f148a3b643f659d420fd2c7d99e6ccc67f4",
"bbfa488ec411f838ceebefb9ba9ae5a6b131d150520ce2204abe1901dff682ca",
    ];

    static KAT_DECODE_BAD: [&str; 40] = [
        // These values cannot be decoded (u is out of range).
"235961fd5592cd20258a96cd03c1afacfeffffffffffffffffffffffffffffff",
"a56d04c7aebc3127c5df6157b35329afffffffffffffffffffffffffffffffff",
"90533b37dd53d45ecf00627df5b7faa7ffffffffffffffffffffffffffffffff",
"3218d5b5473afc6984e4554729f22ff4ffffffffffffffffffffffffffffffff",
"dadf0df44a3be475d756794b454658d6feffffffffffffffffffffffffffffff",
"e151f28c8ed00d21d557b76b11daf499ffffffffffffffffffffffffffffffff",
"418385828f72962f6404b0a08029dc7dffffffffffffffffffffffffffffffff",
"47645fabe37b97962befb6d188b508bbffffffffffffffffffffffffffffffff",
"2e49e30b1b03a00105a62a5aa6a519befeffffffffffffffffffffffffffffff",
"65fe372dd725232fd6303e8933b03645ffffffffffffffffffffffffffffffff",
"665eedbf9989bcb4c695cfe8dd996ef9feffffffffffffffffffffffffffffff",
"ef14ec27af905f379b6ef3caa2d6f5e1feffffffffffffffffffffffffffffff",
"d8e89f216567a9743e1f7f68fc913edcffffffffffffffffffffffffffffffff",
"093130c0e322f7e7b7a5bd16719d4cf3ffffffffffffffffffffffffffffffff",
"b2c8f6f4ec0f6638520c772044a5a7d6ffffffffffffffffffffffffffffffff",
"fad808cccdc35eb9fa3b591bfcfa7b6effffffffffffffffffffffffffffffff",
"2259b4e2c61af9c1990359c02205228effffffffffffffffffffffffffffffff",
"20a3bd12a50b672459ffecc0ed2247eaffffffffffffffffffffffffffffffff",
"b03b2e17e596cba7671b3ce5ff4d21ecfeffffffffffffffffffffffffffffff",
"97dd9d4c71381cac42ec06bb034df367ffffffffffffffffffffffffffffffff",

        // These values cannot be decoded (u matches no point).
"3b27b892aea70a9d859859afce365227423d1c04d307c7aefb6dd9a92f7667c1",
"1f8b02d2e5bd3dae8b57948a43ffebdbf9b77818c20503c288e3635bd3140115",
"f638a23bf95e009abd86cbddbe2b481f056ae7fc81aa74956d6db831aa90a679",
"d71ab1700fbe4b800751a1d2c122aed56eb2442ba927859041bb90750c94c965",
"4dfee18430d7ec6933c3b06e9932ab989bb612d60a905df62814c4f4e053e32a",
"00676c87c413dff2bebf80f7a316b1551b60aadcde350efc6a086afc267ea1d5",
"e1b69d9e000ce5b3a3b570df5b977415487750d23a400fee1ba804f31d8a4112",
"fa7886e7de2ba4aa5b8633a5d08d1454eb2296d18ac487ed4cf64b0c3ee9a14e",
"0076832bc64ff67c5c725314d7e5d7dde8b314af54f04ca14f71ca1e4d8a608f",
"115bbce7aebb73d00cb4de7c551a69e393a6cb7afc80d99bc5bcb5cc730c7dfa",
"32d17cb1a307eed90fffb7fbb7c3a65a255105da3ecc153438220747128c7ee7",
"f0fecceb7fb9a43fb723d4bc3cdf7d6a40667b98ce27571ecaef9973abd772cc",
"76c61415e10f9706a192be0dc66a57723bc0d905912ffd00d213246432d5ac06",
"b6f17b5d034b6f58d8fa9d688d08106a31c184899693549cc20cbd471d0f0663",
"7c9f543fb2c6cef6b6df833904ac68f4448cf0eef058c8c6b90b876e34ae88b7",
"dd05138f6cabd98462e1c7f08dc64030d8bfec5ba66f685faf5c432254d73d92",
"e704bbbed5f47ed6395ad19d085a930e044df7d6a84bbc0d62749de14adcfaf0",
"fc5ed469902b7380a9526cb013500f6f3f9659166fabfae7c4edb98dc84b6f82",
"b26866c53049cc7ffdd3b1643c382874318182f7a11151943834883f18aaf5e5",
"ab44f95742cefd7c44a08bbc84483ec731880edfd7f79c2a92bd905da00bbc03",
    ];

    static KAT_ADD: [[&str; 6]; 20] = [
        // Each group of 6 values is encodings of points:
        // P1, P2, P1+P2, 2*P1, 2*P1+P2, 2*(P1+P2)
        [
"cbc7ed07ca508e0a3fddc7f13df77c7d6884f6fd927bcc2687aca8a8fefb2a1d",
"843952261fae4a4805e42d0f9552627950ce7aaa376fd4c469760473e95bf930",
"a7d2492c3866dbdb2d17b96aa92e7290b27c837b2541eeae8149f59042e46fb6",
"09d52c8b2bcdd539aa3e48a7313a2644791f67545124bb5b5606d6f1f19657cf",
"7b4aa4a5cfb8f182ef1a393eb84e37dd770d3c32f9bac9eedf157afb43ffcc37",
"9bb2666fe8b7ff6d170d303572dac48a00dbc50fac6d8799443f31d283a2a051",
        ], [
"d1bef9e773dc68484441909e5971a884686b8edee51b26c28111e57af9e5570b",
"b117087f3c772c5a190433ae5c0e0a9698d796fef6213415b743fb2644a98afb",
"7ebffcc3f2f3451b80f494f5200f45144b2e67b2b3e6ecad84e45aa7c05a8b74",
"02fad07bf13c94ed3339467002296fac454869691dadf97d7b394b02baec3a25",
"98ce1e834461222536f4c94b3c2392f9f385399fa3f39b1d41a9b3c834ece64f",
"d2defbda27a919574a971e4f7ec753b3251301dc32cd78fad21c77c7d20d4936",
        ], [
"e079c4fb6fd4374ee86faa5eb417587f769944786b6c8e36553c3d4b8b0ac768",
"6a9b495a5d84873c00ef653636aacda5cc6289af0ebe7c1233922661a6a144e8",
"7371a50013d72f3dc83c89ee85d0c217c03e1fe697dcf7e74cc32c301c526e10",
"dc03aeefef480151fd9caa88cd4920c9411e81f00d3a08594b51721547cdb088",
"97accbb5d7b919ac6ce9305f361bdd8988bec327cb85b96cafd66939a274f73a",
"ec51cf87aee58a5d08e6f338bb04041d1f39ca50b30d24c807ddf700fc52b126",
        ], [
"ea37c1a47e824ef49667fa52056c7156571751f1831b8bb6d9f4ac649e0c6deb",
"101788eb55d2ceb044f976f29f3c4e76c59782d26315babf11708ba51ee05f68",
"9efa6da7e6a0b79fd63b10662717b274a80f609a0630cf467bc9aa60dfed679c",
"8bf94069545a93e8be176288b80e87f557eaa7fe93ad0b18d3ed9348c52b4e3b",
"6a048026f6b645c13c4bfa5fad87950afd032f4cf957df40ffab89c2973996e3",
"46433a0a68095d4da95c368d05e6ede3f4ee405db90565ae09212e1c12cbb205",
        ], [
"3863af3eedd641e9de136269f4d27fcb0697bd2a3ffc07cfc1ce56a4f7b7b48c",
"90966396a34be1c135dd9a40f4ef79fd629dbcf3532b1989095a239f1575cdea",
"d4dbf804f163a7559e0fa32724049286f26cb87428c67f91e345f534254a6d11",
"4069b52edcbba08d2fdc73fa643ff8df07a3073a29d291a71d63185b0f0a5b68",
"f983accbdfb2ffadcba6391e812767f77a57ddcfe776c1daa8d9b6106a180953",
"f9043c2ff98df57b77409898a5c13e609fbcf1ccf6395682324e9c926af2850d",
        ], [
"e25fde1be148cede03e413389d9c3e272677c05c07d8232a721c36c7198e4677",
"a3b5544e8b1045d7e8a8894264b143c2bdba74722471b4aae1a0e84b8756f4c9",
"fa423f9fd12fdf2d2d46d3cadc67142934e5b17eca3394f37c5fc651e5eb70f7",
"698b86fa8570f4cb7f871c11dd51787245498f323f9ad4fff0e4d6f1c19f20f8",
"31411319922530d1f73ca20d2b641b0f08d8ee5cab6be576c0cfd9bc4a2e7596",
"aabcf7cac268d3651b59069cc69c8893089539dc41c899a262937dab5b0e00b5",
        ], [
"45427bea9bad14dee6c8aa2de29f7e11db2f0c2046a37cb60fc3437058eaf6f5",
"f037493aa712cbbc276e36e9500757bf8c01740ab866ea622204bdad37d64477",
"f023750cd0e793a0cee8b06b516a744dc9cce4198af20be7d0965adfe23e5a36",
"d54d8a741a10593098885747bc45920e7f6f6d3fc726b479a1ece7eaa40c0d29",
"c084c31bd90cf873ab98141c9cd1bd52822ff5ecb0ba3ba1cc2b1e9ca865b5f8",
"869b93bf94e4ce7db22a946f76b25c3e8d88c4cd9e72e91472eeec2c9ac1afd0",
        ], [
"3f04b543ecdd86b33ed4bc2d5a3512fad86a62c9eb71b7e2e8c394fd2c383bf8",
"88928f249697dbf12992f30be0f60e148ff206b2ce4ee0cfcb47237f03ce9e7d",
"b293b18365ec537e9b3671f64a91f0d81eae0f715f6f2db439a6544d1a025d15",
"1141d88e5ff114d9d7345d1922e877c211bae8c7e3ce7b5050b41ba26a0ea74f",
"2cc09cfeed5a7b986e01621780dab8a344108396f99bd28755873e6e67131759",
"2986c2c5d9eb473df1a66a17b462d1f0bc08511c658e14cfc915c4ade2a9bca3",
        ], [
"b199a5959c2859c12f9a4a8c3bab636533fe9c0ad4b1ce8256420c12d8f3c78f",
"310d5b48808dc94b09ccaef632228d7d1ada928ef228e393a8db1a1879d19989",
"6901c7e4b94a201dd0424f54c590745e895db35406c07d348d368c4d0c4b30cf",
"7430c11db3c60a7d553af1ceec5f494bc21f3c082b11347f2079559bad733bdc",
"4f51359cc701e97b65a1715c8c57cbaed68e430884fe9c7686e724beab81abbe",
"3dc6cbebe5837ab2bc3e9a73d1a27af98d232242dbeeb99de4fed9bf0b61114d",
        ], [
"728dc259fe491814ab224e98a5289e0438ded7cc4f6d782a4e001132b7d69997",
"4bfc61d53e69127d6b2c80fe5fbbd57f50d87ce3117c285d16fda49ea394bf05",
"2c3e1b0dafe2ef22cfa6afb64a26092c235f48820654ca447dc8796921752db7",
"2826af3e723d22ed66ed6b19f487155eac10345fef20a9c8a65849afe152af8f",
"a719805f30a4963340107606dec2b0ff850b54c75359574d7548c2282b69b5eb",
"b83f737e653ee38bbc3279ad06c83b7ec3821403db31a640d29f0aafb2c2e38c",
        ], [
"e434c88caa65f2e3bb65a2f2abd178ceb247f0036c765f27016a633fa2c91711",
"8b7808d2d4f9c5f1f7f28b6ceaa6468dd8c20dc13b1cc8509dc010a3f3bcfe70",
"6193eca5bc6f027f16069da86da0d365fdd68e00fb5f81fea0306128008aa33b",
"a7dc0b0b46fe17f1159f608aba6c9ded906dc3ca33ade56528f30e9920991b4a",
"754badf9c23b102f2644bc8ddd5d800b44777aa8db1cbd19d0512b7e7009eb8d",
"20e9829f92923b8fb2325b08d8ef0d8b59f0cd6e361eeeb9478e5b2b57a99dd7",
        ], [
"02b22b3151da8fc150e4f9d0b89c4829c54286c4b3a801ea8eebdd14ec41ecec",
"1981106b6318cf1593defe007bc47f46e86e732877c93efebb4438de801710f9",
"c84a17cc275875ff7802a4d15d0bf484bd079459e5c4598a5104cddbde6225f7",
"119f065957a07e12fb2685cef4b6959d92bf459dface90a226f8e799262466ac",
"6440c36958bcd9023087cdff7301524f521894f394f464f3a8192b13fdf74123",
"4c395c65b244ec29ced1e0e18b72be7ea175ff93a02065db1c9a52e04337c4d4",
        ], [
"e4c7cdaa6c7b7020c2254384e01ce2ab8b143d635b9b1ceec18936975f4e060e",
"33e4561730261caecaf5ac4e684e49e587074379b7e295e8806112fd411a106c",
"4065d0dd1ca36d9cc4f7fe393bde1894c2f3d06bef137ed256236718118ec171",
"6c1c3abdcf9eef052f1d3827ccca6bb62b17b4d7a0799e3ed7d45a0ddf462e3a",
"6e241b8d276835313424777b0b2b5b41cb7d13051e6edac701c3574c61a57abe",
"d8fa52c27e684a7d63087ee245f3da074613c2b32f6a1183b45163d38c437f6a",
        ], [
"882ff17bc22345ce60409d7389594b91d630f384a0d794761265239ce6ac803f",
"a968de5fd72e369d64944c35f0c9bdc030f004b2c8a0be8ebddfb792a1c48599",
"25c5d4dacad8e73ab54545907060ccdea9b3b62816cc823ec8c06bed26e8b388",
"b070c2c86a0bf0d8a742dab4c7d18febbf0e83d5eb8d658a58c43eca34479694",
"4ee3e91cc8dad3d081661cdd751d026b074342547aec2c7ef85b5cb5fccfcb88",
"fbadfc3786d272626465fe6aa0b4fdf0681329850cce41483933ef41052c4e0e",
        ], [
"dd9cb182445e867060bd44fa142040893e5b940135e5a4cc6728d2c61f9e9c87",
"af60d54f85064b7ff461dd3b6b608ab7f0906bc554789d20e7f689bf146f79ab",
"3d858f53f06af7e0858c532af6300400449fa71cf1a3ceff678b89c7dffe96dc",
"e5f4bcbcfecf2b7db8ac092bad648149c2aa0126eda77ecdcdc43ade22e21753",
"8df965fbb7cfc3c94df2b2a27e5adc5d3b5fb3e17a272052f5aa9ed99d4a5a82",
"eddf8fdac0a697ca51d1247f561c55e411e42cd4f56e8138186622fa8e62612c",
        ], [
"af5592995a5ae321186c546e6b8b4d894c0c1a4932ba3dbf6f50fe2f9b22043d",
"9dc89917d65547cd09d7ba87fe2c1fead6b7a6a31ab348251d54c229bf4e6349",
"506d313330d144fae7fe18775bedd897c16e15ecf98257695be279e0219366c2",
"04cfeab2f5aa91d6dd297573054fe1287991282928460768aa47678af1a8bf50",
"67156f70eadf9811cbe1d30c9db1e197a3456a2b632e7cc9401410dc666fd9e4",
"3a48ff67182347d60c1aabee2b41d87758e9dca449df62da35a72ed8eb397c61",
        ], [
"b490ea32b433babed7f933320ce490383b88152c455cf22099b5fefa35d0d556",
"fa4fbedcd7db944f34fbd1cf09a6ede9205c8b0ea884ae59c591b691e6ad3a2e",
"7df6cebfea01f1c5a6bf9d9e16c80692a9cf82c56f1b19d238af99483d7bb5b0",
"ef54c1ab699b0b4eb32735d18bd0d5c2e6dd0576ae4da08177847976ec4b2ea8",
"e6759784f7dcd1ff30dd0053c8c92cee98a80e5c1ae24ed875969b666765cafc",
"b9ff1488306a076cb6e8f494d337f5c107e2788eef29c9acc7005431de6adf74",
        ], [
"0031c95fee4ddca241a5c7e86fed719aa4b0101334cb1ada6ea1180d400729d0",
"bac3c18e0b2cc67bdb0a625a230254596c1b36d5571f360052f9af2e896f4e13",
"2e8db44896020250a1f1c5f13c5a28cfc6a847b1b7fc29284e77ba3fc024aac8",
"c3bc96acafc84d64cd59f6a410d13fba216fe64c268956ca604a39ef4080610e",
"3bb57d0760a48303b366b1c3eaa20601f949f0d72bebdf4fd2ebf8b282ffaa3a",
"1d436b1eef1af22b2b05daab1d5250b3ef9e0f770f89c7cd746a626f062bf4d5",
        ], [
"71f05218ed7d3653fb534e75b380ac6f37e1a7c8f7c4a71922590797d47888ce",
"37b5eee95937116dc3342fade6c6fc399a9c6e3e16db4d755757d9c189b6eb93",
"b8b27bff65fb60e4958592eda67c64018be5c8439bd47130b0dfbbd2d6842757",
"5fc7fd92dcfcc3f8c2e3204c04ae8a14259674f1d4defcb1cff7b34fc0e31473",
"e1f9f9629c96b7e43c4c3b81d76d9463c55e69aa043907963d1a3ede6276be43",
"ea5960e644f753cf0a219646361271cfba67075da98af62b6933f8e612cb57a4",
        ], [
"71e4f3589bae4c0130b1dc1d379018b4ec2bd07050be7e5700ba6a813b534f7d",
"9fb3a3849686fe19efef98e05ea9ae65444e7ebfacea188e2cd5668cfbc200b3",
"1c52a0b3f2c63f6311158aee8ca237b59ae3837934044812ed6263cc82485b72",
"362440ae86acfeb8c34eecb0e29d1bbcd6d8c98fd1012d6cefa86feba403b555",
"75bc067ed7beb7ad726b8fce054700226676c0b183ec00b9aae44a67b57b4259",
"097744283f77060e5a8f60d44f6d5921645e2084dbc2c374ae57c1fc9cd3b6e8",
        ]
    ];

    #[test]
    fn encode_decode() {
        for i in 0..KAT_DECODE_OK.len() {
            let buf = hex::decode(KAT_DECODE_OK[i]).unwrap();
            let Q = Point::decode(&buf).unwrap();
            assert!(Q.encode()[..] == buf);
        }
        for i in 0..KAT_DECODE_BAD.len() {
            let buf = hex::decode(KAT_DECODE_BAD[i]).unwrap();
            assert!(Point::decode(&buf).is_none());
        }
    }

    #[test]
    fn base_arith() {
        for i in 0..KAT_ADD.len() {
            let buf1 = hex::decode(KAT_ADD[i][0]).unwrap();
            let buf2 = hex::decode(KAT_ADD[i][1]).unwrap();
            let buf3 = hex::decode(KAT_ADD[i][2]).unwrap();
            let buf4 = hex::decode(KAT_ADD[i][3]).unwrap();
            let buf5 = hex::decode(KAT_ADD[i][4]).unwrap();
            let buf6 = hex::decode(KAT_ADD[i][5]).unwrap();
            let P1 = Point::decode(&buf1).unwrap();
            let P2 = Point::decode(&buf2).unwrap();
            let P3 = Point::decode(&buf3).unwrap();
            let P4 = Point::decode(&buf4).unwrap();
            let P5 = Point::decode(&buf5).unwrap();
            let P6 = Point::decode(&buf6).unwrap();
            assert!(P1.equals(P1) == 0xFFFFFFFF);
            assert!(P2.equals(P2) == 0xFFFFFFFF);
            assert!(P3.equals(P3) == 0xFFFFFFFF);
            assert!(P4.equals(P4) == 0xFFFFFFFF);
            assert!(P5.equals(P5) == 0xFFFFFFFF);
            assert!(P6.equals(P6) == 0xFFFFFFFF);
            assert!(P1.equals(P2) == 0x00000000);
            assert!(P1.equals(P3) == 0x00000000);
            assert!(P1.equals(P4) == 0x00000000);
            assert!(P1.equals(P5) == 0x00000000);
            assert!(P1.equals(P6) == 0x00000000);
            let Q3 = P1 + P2;
            assert!(Q3.equals(P3) != 0);
            assert!(Q3.encode()[..] == buf3);
            let Q4 = P1.double();
            assert!(Q4.equals(P4) != 0);
            assert!(Q4.encode()[..] == buf4);
            let R4 = P1 + P1;
            assert!(R4.equals(P4) != 0);
            assert!(R4.equals(Q4) != 0);
            assert!(R4.encode()[..] == buf4);
            let Q5 = P4 + P2;
            assert!(Q5.equals(P5) != 0);
            assert!(Q5.encode()[..] == buf5);
            let R5 = Q4 + P2;
            assert!(R5.equals(P5) != 0);
            assert!(R5.equals(Q5) != 0);
            assert!(R5.encode()[..] == buf5);
            let S5 = P1 + Q3;
            assert!(S5.equals(P5) != 0);
            assert!(S5.equals(Q5) != 0);
            assert!(S5.equals(R5) != 0);
            assert!(S5.encode()[..] == buf5);
            let Q6 = Q3.double();
            assert!(Q6.equals(P6) != 0);
            assert!(Q6.encode()[..] == buf6);
            let R6 = Q4 + P2.double();
            assert!(R6.equals(P6) != 0);
            assert!(R6.equals(Q6) != 0);
            assert!(R6.encode()[..] == buf6);
            let S6 = R5 + P2;
            assert!(S6.equals(P6) != 0);
            assert!(S6.equals(Q6) != 0);
            assert!(S6.equals(R6) != 0);
            assert!(S6.encode()[..] == buf6);

            let mut T = Q6;
            for j in 0..10 {
                let S = R6.xdouble(j as u32);
                assert!(T.equals(S) != 0);
                assert!(T.encode() == S.encode());
                T = T.double();
            }

            assert!((R6 + Point::NEUTRAL).encode()[..] == buf6);
        }
    }

    #[test]
    fn mulgen() {
        let sbuf = hex::decode("f17dbcbef04a157b7e470b6563940017e5de0bbf30042ef0a86e36f4b8600d14").unwrap();
        let (s, ok) = Scalar::decode32(&sbuf);
        assert!(ok == 0xFFFFFFFF);
        let rbuf = hex::decode("d79870ba92af7240e4e7a9ca4a96a6411822382b043006c9046fa8d011f79ace").unwrap();
        let R = Point::decode(&rbuf).unwrap();
        let P = Point::BASE * s;
        assert!(P.equals(R) == 0xFFFFFFFF);
        assert!(P.encode()[..] == rbuf);
        let Q = Point::mulgen(&s);
        assert!(Q.equals(R) == 0xFFFFFFFF);
        assert!(Q.encode()[..] == rbuf);
    }

    #[test]
    fn mul() {
        for i in 0..20 {
            // Build pseudorandom s1 and s2
            let v1 = Sha3_256::digest(&((2 * i + 0) as u64).to_le_bytes());
            let v2 = Sha3_256::digest(&((2 * i + 1) as u64).to_le_bytes());

            let s1 = Scalar::decode_reduce(&v1);
            let s2 = Scalar::decode_reduce(&v2);
            let s3 = s1 * s2;
            let P1 = Point::mulgen(&s1);
            let Q1 = s1 * Point::BASE;
            assert!(P1.equals(Q1) == 0xFFFFFFFF);
            let P2 = Point::mulgen(&s3);
            let Q2 = s2 * Q1;
            assert!(P2.equals(Q2) == 0xFFFFFFFF);
        }

        let mut T = Point::BASE.xdouble(120);
        assert!(T.encode()[..] == hex::decode("9811a66139b0779ecdd85726b290a67346aedda26bc1f6fded6da44631fb2149").unwrap());
        for _ in 0..1000 {
            let n = Scalar::decode_reduce(&T.encode());
            T *= n;
        }
        assert!(T.encode()[..] == hex::decode("7c9d21debf079763b76125728bbe6f8d22947ad296a86a92819654ac1b9bd135").unwrap());
    }

    #[test]
    fn mul_add_mulgen() {
        for i in 0..20 {
            // Build pseudorandom A, u and v
            let v1 = Sha3_256::digest(&((3 * i + 0) as u64).to_le_bytes());
            let v2 = Sha3_256::digest(&((3 * i + 1) as u64).to_le_bytes());
            let v3 = Sha3_256::digest(&((3 * i + 2) as u64).to_le_bytes());
            let A = Point::mulgen(&Scalar::decode_reduce(&v1));
            let u = Scalar::decode_reduce(&v2);
            let v = Scalar::decode_reduce(&v3);

            // Compute u*A + v*B in two different ways; check that they
            // match.
            let R1 = u * A + Point::mulgen(&v);
            let R2 = A.mul_add_mulgen_vartime(&u, &v);
            assert!(R1.equals(R2) == 0xFFFFFFFF);
        }
    }

    #[test]
    fn map() {
        for i in 0..50 {
            let v = Sha3_256::digest(&(i as u64).to_le_bytes());
            let f = GFp::decode_reduce(&v);
            let P = Point::map_to_curve(&f);
            assert!(P.Z.iszero() == 0);
            let iZ = GFp::ONE / P.Z;
            let e = P.E * iZ;
            let u = P.U * iZ;
            let t = P.T * iZ;
            assert!(u.square().equals(t) == 0xFFFFFFFF);
            assert!(e.square().equals(-u.xsquare(2) + Point::Ap * u.square() + GFp::ONE) == 0xFFFFFFFF);
        }
    }

    fn test_recode_scalar_ext(s: &Scalar, w: i32) {
        let sd = Point::recode_scalar_ext(s, w);
        let num = Point::num_recoded_digits(w);
        let mut r = Scalar::ZERO;
        let md = 1i32 << (w - 1);
        for i in (0..num).rev() {
            let mut d = sd[i] as i32;
            if i == (num - 1) {
                if w == 8 && d == -128 {
                    d = 128;
                }
                assert!(d >= 0);
                assert!(d <= md);
                r = Scalar::from_i32(d);
            } else {
                assert!(d >= -md);
                assert!(d < md);
                for _ in 0..w {
                    r = r.mul2();
                }
                r += Scalar::from_i32(d);
            }
        }
        assert!(s.equals(r) == 0xFFFFFFFF);
    }

    #[test]
    fn recode_scalar_ext() {
        for w in 5..9 {
            test_recode_scalar_ext(&Scalar::ZERO, w);
            test_recode_scalar_ext(&Scalar::ONE, w);
            test_recode_scalar_ext(&Scalar::MINUS_ONE, w);
            for i in 0..100 {
                let v = Sha3_256::digest(&(i as u64).to_le_bytes());
                test_recode_scalar_ext(&Scalar::decode_reduce(&v), w);
            }
        }
    }

    // This function tests xmuladd with n pseudorandom points and scalars.
    fn test_xmuladd(n: usize) {
        // Make n pseudorandom scalars and points.
        // We force one scalar to be zero, and one point to be the neutral,
        // to exercise these cases.
        let mut scalars = Vec::<Scalar>::with_capacity(n);
        let mut points = Vec::<Point>::with_capacity(n);
        let z = (n as u64) << 32;
        for i in 0..n {
            let y = z + ((i as u64) << 2);
            let vs = Sha3_256::digest(&(y + 0).to_le_bytes());
            let vp = Sha3_512::digest(&(y + 1).to_le_bytes());
            if i == 50 {
                scalars.push(Scalar::ZERO);
            } else {
                scalars.push(Scalar::decode_reduce(&vs));
            }
            if i == 40 {
                points.push(Point::NEUTRAL);
            } else {
                points.push(Point::hash_to_curve(&vp));
            }
        }

        let P = Point::xmuladd_vartime(&scalars, &points);

        let mut Q = Point::NEUTRAL;
        for i in 0..n {
            Q += scalars[i] * points[i];
        }
        assert!(P.equals(Q) == 0xFFFFFFFF);
    }

    #[test]
    fn xmuladd110() {
        test_xmuladd(110);
    }

    #[test]
    fn xmuladd400() {
        test_xmuladd(400);
    }

    #[test]
    fn xmuladd700() {
        test_xmuladd(700);
    }

    #[test]
    fn xmuladd1000() {
        test_xmuladd(1000);
    }
}
