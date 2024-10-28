// Code from https://github.com/SleepingShell/circom-pairing/ 
// that is requried for ECDSA

pragma circom 2.0.3;

include "../circomlib/circuits/bitify.circom";
include "./bigint.circom";

// save range check on Y compared to SignedFpCarryModP
template SignedCheckCarryModToZero(n, k, overflow, p){
    signal input in[k]; 
    var m = (overflow + n - 1) \ n; 
    signal output X[m];

    assert( overflow < 251 );

    var Xvar[2][50] = get_signed_Fp_carry_witness(n, k, m, in, p); 
    component X_range_checks[m];

    for(var i=0; i<m; i++){
        X[i] <-- Xvar[0][i];
        X_range_checks[i] = Num2Bits(n+1);
        X_range_checks[i].in <== X[i] + (1<<n); // X[i] should be between [-2^n, 2^n)
    }
    
    component mod_check = CheckCarryModP(n, k, m, overflow, p);
    for(var i=0; i<k; i++){
        mod_check.in[i] <== in[i];
        mod_check.Y[i] <== 0;
    }
    for(var i=0; i<m; i++){
        mod_check.X[i] <== X[i];
    }
}

// constrain in = p * X + Y 
// in[i] in (-2^overflow, 2^overflow) 
// assume registers of X have abs value < 2^{overflow - n - log(min(k,m)) - 1} 
// assume overflow - 1 >= n 
template CheckCarryModP(n, k, m, overflow, p){
    signal input in[k]; 
    signal input X[m];
    signal input Y[k];

    assert( overflow < 251 );
    assert( n <= overflow - 1);
    component pX;
    component carry_check;

    pX = BigMultShortLongUnequal(n, k, m, overflow); // p has k registers, X has m registers, so output really has k+m-1 registers 
    // overflow register in  (-2^{overflow-1} , 2^{overflow-1})
    for(var i=0; i<k; i++)
        pX.a[i] <== p[i];
    for(var i=0; i<m; i++)
        pX.b[i] <== X[i];

    // in - p*X - Y has registers in (-2^{overflow+1}, 2^{overflow+1})
    carry_check = CheckCarryToZero(n, overflow+1, k+m-1 ); 
    for(var i=0; i<k; i++){
        carry_check.in[i] <== in[i] - pX.out[i] - Y[i]; 
    }
    for(var i=k; i<k+m-1; i++)
        carry_check.in[i] <== -pX.out[i];
}

// a[k] registers can overflow
//  assume actual value of a < 2^{n*(k+m)} 
// p[k] registers in [0, 2^n)
// out[2][k] solving
//      a = p * out[0] + out[1] with out[1] in [0,p) 
// out[0] has m registers in range [-2^n, 2^n)
// out[1] has k registers in range [0, 2^n)
function get_signed_Fp_carry_witness(n, k, m, a, p){
    var out[2][50];
    var a_short[51] = signed_long_to_short(n, k, a); 

    /* // commenting out to improve speed
    // let me make sure everything is in <= k+m registers
    for(var j=k+m; j<50; j++)
        assert( a_short[j] == 0 );
    */

    if(a_short[50] == 0){
        out = long_div2(n, k, m, a_short, p);    
    }else{
        var a_pos[50];
        for(var i=0; i<k+m; i++) 
            a_pos[i] = -a_short[i];

        var X[2][50] = long_div2(n, k, m, a_pos, p);
        // what if X[1] is 0? 
        var Y_is_zero = 1;
        for(var i=0; i<k; i++){
            if(X[1][i] != 0)
                Y_is_zero = 0;
        }
        if( Y_is_zero == 1 ){
            out[1] = X[1];
        }else{
            out[1] = long_sub(n, k, p, X[1]); 
            
            X[0][0]++;
            if(X[0][0] >= (1<<n)){
                for(var i=0; i<m-1; i++){
                    var carry = X[0][i] \ (1<<n); 
                    X[0][i+1] += carry;
                    X[0][i] -= carry * (1<<n);
                }
                assert( X[0][m-1] < (1<<n) ); 
            }
        }
        for(var i=0; i<m; i++)
            out[0][i] = -X[0][i]; 
    }

    return out;
}

template FpIsEqual(n, k, p){
    signal input in[2][k];
    signal output out;

    // check in[i] < p
    component lt[2];
    for(var i = 0; i < 2; i++){
        lt[i] = BigLessThan(n, k);
        for(var idx=0; idx<k; idx++){
            lt[i].a[idx] <== in[i][idx];
            lt[i].b[idx] <== p[idx];
        }
        lt[i].out === 1;
    }

    component isEqual[k+1];
    var sum = 0;
    for(var i = 0; i < k; i++){
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== in[0][i];
        isEqual[i].in[1] <== in[1][i];
        sum = sum + isEqual[i].out;
    }

    isEqual[k] = IsEqual();
    isEqual[k].in[0] <== sum;
    isEqual[k].in[1] <== k;
    out <== isEqual[k].out;
}

// check if in[0], in[1] both have k registers in [0,2^n)
// to save constraints, DO NOT CONSTRAIN in[i] < p
template RangeCheck2D(n, k){
    signal input in[2][k];
    component range_checks[2][k];
    //component lt[2];
    
    for(var eps=0; eps<2; eps++){
        //lt[eps] = BigLessThan(n, k);
        for(var i=0; i<k; i++){
            range_checks[eps][i] = Num2Bits(n);
            range_checks[eps][i].in <== in[eps][i];
            //lt[eps].a[i] <== in[eps][i];
            //lt[eps].b[i] <== p[i];
        }
        //lt[eps].out === 1;
    }
}

// in[i] = (x_i, y_i) 
// Implements constraint: (y_1 + y_3) * (x_2 - x_1) - (y_2 - y_1)*(x_1 - x_3) = 0 mod p
// used to show (x1, y1), (x2, y2), (x3, -y3) are co-linear
template PointOnLine(n, k, p) {
    signal input in[3][2][k]; 

    var LOGK = log_ceil(k);
    var LOGK2 = log_ceil(3*k*k);
    assert(3*n + LOGK2 < 251);

    // AKA check point on line 
    component left = BigMultShortLong(n, k, 2*n + LOGK + 1); // 2k-1 registers abs val < 2k*2^{2n}
    for(var i = 0; i < k; i++){
        left.a[i] <== in[0][1][i] + in[2][1][i];
        left.b[i] <== in[1][0][i] - in[0][0][i]; 
    }

    component right = BigMultShortLong(n, k, 2*n + LOGK); // 2k-1 registers abs val < k*2^{2n}
    for(var i = 0; i < k; i++){
        right.a[i] <== in[1][1][i] - in[0][1][i];
        right.b[i] <== in[0][0][i] - in[2][0][i];
    }
    
    component diff_red; 
    diff_red = PrimeReduce(n, k, k-1, p, 3*n + LOGK2);
    for(var i=0; i<2*k-1; i++)
        diff_red.in[i] <== left.out[i] - right.out[i];  

    // diff_red has k registers abs val < 3*k^2*2^{3n}
    component diff_mod = SignedCheckCarryModToZero(n, k, 3*n + LOGK2, p);
    for(var i=0; i<k; i++)
        diff_mod.in[i] <== diff_red.out[i]; 
}

// in = (x, y)
// Implements:
// x^3 + ax + b - y^2 = 0 mod p
// Assume: a, b in [0, 2^n) 
template PointOnCurve(n, k, a, b, p){
    signal input in[2][k]; 

    var LOGK = log_ceil(k);
    var LOGK2 = log_ceil( (2*k-1)*(k*k+1) );
    assert(4*n + LOGK2 < 251);

    // compute x^3, y^2 
    component x_sq = BigMultShortLong(n, k, 2*n + LOGK); // 2k-1 registers in [0, k*2^{2n}) 
    component y_sq = BigMultShortLong(n, k, 2*n + LOGK); // 2k-1 registers in [0, k*2^{2n}) 
    for(var i=0; i<k; i++){
        x_sq.a[i] <== in[0][i];
        x_sq.b[i] <== in[0][i];

        y_sq.a[i] <== in[1][i];
        y_sq.b[i] <== in[1][i];
    }
    component x_cu = BigMultShortLongUnequal(n, 2*k-1, k, 3*n + 2*LOGK); // 3k-2 registers in [0, k^2 * 2^{3n}) 
    for(var i=0; i<2*k-1; i++)
        x_cu.a[i] <== x_sq.out[i];
    for(var i=0; i<k; i++)
        x_cu.b[i] <== in[0][i];

    component ax = BigMultShortLong(n, k, 2*n + LOGK); // 2k-1 registers in [0, k*2^{2n})
    for (var i=0; i<k; i++) {
        ax.a[i] <== a[i];
        ax.b[i] <== in[0][i];
    }

    // x_cu + a x + b has 3k-2 positive registers < k^2 * 2^{3n} + 2^{2n} + 2^n < (k^2 + 1) * 2^{3n} 
    component cu_red = PrimeReduce(n, k, 2*k-2, p, 4*n + 3*LOGK + 1);
    for(var i=0; i<3*k-2; i++){
        if (i < k) {
            cu_red.in[i] <== x_cu.out[i] + ax.out[i] + b[i];
        } else {
            if (i < 2*k-1) {
                cu_red.in[i] <== x_cu.out[i] + ax.out[i];
            } else {
                cu_red.in[i] <== x_cu.out[i];
            }
        }
    }
    // cu_red has k registers < (k^2 + 1)*(2k-1)*2^{4n}

    component y_sq_red = PrimeReduce(n, k, k-1, p, 3*n + 2*LOGK + 1);
    for(var i=0; i<2*k-1; i++)
        y_sq_red.in[i] <== y_sq.out[i]; 
    // y_sq_red has positive registers, so when we subtract from cu_red it doesn't increase absolute value

    component constraint = SignedCheckCarryModToZero(n, k, 4*n + LOGK2, p);
    for(var i=0; i<k; i++){
        constraint.in[i] <== cu_red.out[i] - y_sq_red.out[i]; 
    }
}

// in[0] = (x_1, y_1), in[1] = (x_3, y_3) 
// Checks that the line between (x_1, y_1) and (x_3, -y_3) is equal to the tangent line to the elliptic curve at the point (x_1, y_1)
// Implements: 
// (y_1 + y_3) = lambda * (x_1 - x_3)
// where lambda = (3 x_1^2 + a)/(2 y_1) 
// Actual constraint is 2y_1 (y_1 + y_3) = (3 x_1^2 + a ) ( x_1 - x_3 )
template PointOnTangent(n, k, a, p){
    signal input in[2][2][k];
    
    var LOGK = log_ceil(k);
    var LOGK3 = log_ceil((3*k)*(2*k-1) + 1);
    assert(4*n + LOGK3 < 251);
    component x_sq = BigMultShortLong(n, k, 2*n + LOGK); // 2k-1 registers < k*2^{2n}) 
    for(var i=0; i<k; i++){
        x_sq.a[i] <== in[0][0][i];
        x_sq.b[i] <== in[0][0][i];
    }
    component right = BigMultShortLongUnequal(n, 2*k-1, k, 3*n + 2*LOGK + 3); // 3k-2 registers < (3*k+1)*k*2^{3n} 
    for(var i=0; i<2*k-1; i++){
        if (i < k) {
            right.a[i] <== 3 * x_sq.out[i] + a[i]; // registers in [0, 3*k*2^{2n} + 2^n = (3k+2^{-n})*2^{2n})
        } else {
            right.a[i] <== 3 * x_sq.out[i];
        }
    }
    for(var i=0; i<k; i++){
        right.b[i] <== in[0][0][i] - in[1][0][i]; 
    }
    
    component left = BigMultShortLong(n, k, 2*n + 2 + LOGK); // 2k-1 registers in [0, 4k * 2^{2n})
    for(var i=0; i<k; i++){
        left.a[i] <== 2*in[0][1][i];
        left.b[i] <== in[0][1][i] + in[1][1][i];  
    }
    
    // prime reduce right - left 
    component diff_red = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3);
    for(var i=0; i<3*k-2; i++){
        if(i < 2*k-1) 
            diff_red.in[i] <== right.out[i] - left.out[i]; 
        else
            diff_red.in[i] <== right.out[i];
    }
    // inputs of diff_red has registers < (3k+2^{-n})k*2^{3n} + 4k*2^{2n} < (3k^2 + 1)*2^{3n} assuming 5k <= 2^n 
    // diff_red.out has registers < (3k+1)*(2k-1) * 2^{4n}
    component constraint = SignedCheckCarryModToZero(n, k, 4*n + LOGK3, p);
    for(var i=0; i<k; i++)
        constraint.in[i] <== diff_red.out[i];
}

// requires x_1 != x_2
// assume p is size k array, the prime that curve lives over 
//
// Implements:
//  Given a = (x_1, y_1) and b = (x_2, y_2), 
//      assume x_1 != x_2 and a != -b, 
//  Find a + b = (x_3, y_3)
// By solving:
//  x_1 + x_2 + x_3 - lambda^2 = 0 mod p
//  y_3 = lambda (x_1 - x_3) - y_1 mod p
//  where lambda = (y_2-y_1)/(x_2-x_1) is the slope of the line between (x_1, y_1) and (x_2, y_2)
// these equations are equivalent to:
//  (x_1 + x_2 + x_3)*(x_2 - x_1)^2 = (y_2 - y_1)^2 mod p
//  (y_1 + y_3)*(x_2 - x_1) = (y_2 - y_1)*(x_1 - x_3) mod p
template EllipticCurveAddUnequal(n, k, p) { 
    signal input a[2][k];
    signal input b[2][k];

    signal output out[2][k];

    var LOGK = log_ceil(k);
    var LOGK3 = log_ceil( (3*k*k)*(2*k-1) + 1 ); 
    assert(4*n + LOGK3 < 251);

    // precompute lambda and x_3 and then y_3
    var dy[50] = long_sub_mod(n, k, b[1], a[1], p);
    var dx[50] = long_sub_mod(n, k, b[0], a[0], p); 
    var dx_inv[50] = mod_inv(n, k, dx, p);
    var lambda[50] = prod_mod(n, k, dy, dx_inv, p);
    var lambda_sq[50] = prod_mod(n, k, lambda, lambda, p);
    // out[0] = x_3 = lamb^2 - a[0] - b[0] % p
    // out[1] = y_3 = lamb * (a[0] - x_3) - a[1] % p
    var x3[50] = long_sub_mod(n, k, long_sub_mod(n, k, lambda_sq, a[0], p), b[0], p);
    var y3[50] = long_sub_mod(n, k, prod_mod(n, k, lambda, long_sub_mod(n, k, a[0], x3, p), p), a[1], p);

    for(var i = 0; i < k; i++){
        out[0][i] <-- x3[i];
        out[1][i] <-- y3[i];
    }
    
    // constrain x_3 by CUBIC (x_1 + x_2 + x_3) * (x_2 - x_1)^2 - (y_2 - y_1)^2 = 0 mod p
    
    component dx_sq = BigMultShortLong(n, k, 2*n+LOGK+2); // 2k-1 registers abs val < k*2^{2n} 
    component dy_sq = BigMultShortLong(n, k, 2*n+LOGK+2); // 2k-1 registers < k*2^{2n}
    for(var i = 0; i < k; i++){
        dx_sq.a[i] <== b[0][i] - a[0][i];
        dx_sq.b[i] <== b[0][i] - a[0][i];

        dy_sq.a[i] <== b[1][i] - a[1][i];
        dy_sq.b[i] <== b[1][i] - a[1][i];
    } 

    // x_1 + x_2 + x_3 has registers in [0, 3*2^n) 
    component cubic = BigMultShortLongUnequal(n, k, 2*k-1, 3*n+4+2*LOGK); // 3k-2 registers < 3 * k^2 * 2^{3n} ) 
    for(var i=0; i<k; i++)
        cubic.a[i] <== a[0][i] + b[0][i] + out[0][i]; 
    for(var i=0; i<2*k-1; i++){
        cubic.b[i] <== dx_sq.out[i];
    }

    component cubic_red = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3);
    for(var i=0; i<2*k-1; i++)
        cubic_red.in[i] <== cubic.out[i] - dy_sq.out[i]; // registers abs val < 3k^2*2^{3n} + k*2^{2n} < (3k^2+1)2^{3n}
    for(var i=2*k-1; i<3*k-2; i++)
        cubic_red.in[i] <== cubic.out[i]; 
    // cubic_red has k registers < (3k^2+1)(2k-1) * 2^{4n}
    
    component cubic_mod = SignedCheckCarryModToZero(n, k, 4*n + LOGK3, p);
    for(var i=0; i<k; i++)
        cubic_mod.in[i] <== cubic_red.out[i]; 
    // END OF CONSTRAINING x3
    
    // constrain y_3 by (y_1 + y_3) * (x_2 - x_1) = (y_2 - y_1)*(x_1 - x_3) mod p
    component y_constraint = PointOnLine(n, k, p); // 2k-1 registers in [0, k*2^{2n+1})
    for(var i = 0; i < k; i++)for(var j=0; j<2; j++){
        y_constraint.in[0][j][i] <== a[j][i];
        y_constraint.in[1][j][i] <== b[j][i];
        y_constraint.in[2][j][i] <== out[j][i];
    }
    // END OF CONSTRAINING y3

    // check if out[][] has registers in [0, 2^n) 
    component range_check = RangeCheck2D(n, k);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++)
        range_check.in[j][i] <== out[j][i];
}


// Elliptic curve is E : y**2 = x**3 + ax + b
// assuming a < 2^n for now
// Note that for BLS12-381, a = 0, b = 4

// Implements:
// computing 2P on elliptic curve E for P = (x_1, y_1)
// formula from https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html
// x_1 = in[0], y_1 = in[1]
// assume y_1 != 0 (otherwise 2P = O)

// lamb =  (3x_1^2 + a) / (2 y_1) % p
// x_3 = out[0] = lambda^2 - 2 x_1 % p
// y_3 = out[1] = lambda (x_1 - x_3) - y_1 % p

// We precompute (x_3, y_3) and then constrain by showing that:
// * (x_3, y_3) is a valid point on the curve 
// * (x_3, y_3) is on the tangent line to E at (x_1, y_1) 
// * x_1 != x_3 
template EllipticCurveDouble(n, k, a, b, p) {
    signal input in[2][k];
    signal output out[2][k];

    var long_3[k];
    long_3[0] = 3;
    for (var i = 1; i < k; i++) {
        long_3[i] = 0;
    }

    // precompute lambda 
    var lamb_num[50] = long_add_mod(n, k, a, prod_mod(n, k, long_3, prod_mod(n, k, in[0], in[0], p), p), p);
    var lamb_denom[50] = long_add_mod(n, k, in[1], in[1], p);
    var lamb[50] = prod_mod(n, k, lamb_num, mod_inv(n, k, lamb_denom, p), p);

    // precompute x_3, y_3
    var x3[50] = long_sub_mod(n, k, prod_mod(n, k, lamb, lamb, p), long_add_mod(n, k, in[0], in[0], p), p);
    var y3[50] = long_sub_mod(n, k, prod_mod(n, k, lamb, long_sub_mod(n, k, in[0], x3, p), p), in[1], p);
    
    for(var i=0; i<k; i++){
        out[0][i] <-- x3[i];
        out[1][i] <-- y3[i];
    }
    // check if out[][] has registers in [0, 2^n)
    component range_check = RangeCheck2D(n, k);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++)
        range_check.in[j][i] <== out[j][i];

    component point_on_tangent = PointOnTangent(n, k, a, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++){
        point_on_tangent.in[0][j][i] <== in[j][i];
        point_on_tangent.in[1][j][i] <== out[j][i];
    }
    
    component point_on_curve = PointOnCurve(n, k, a, b, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++)
        point_on_curve.in[j][i] <== out[j][i];
    
    component x3_eq_x1 = FpIsEqual(n, k, p);
    for(var i = 0; i < k; i++){
        x3_eq_x1.in[0][i] <== out[0][i];
        x3_eq_x1.in[1][i] <== in[0][i];
    }
    x3_eq_x1.out === 0;
}


