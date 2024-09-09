pragma circom 2.0.3;

include "../circomlib/circuits/comparators.circom";

// http://0x80.pl/notesen/2016-01-17-sse-base64-decoding.html#vector-lookup-base
template Base64Lookup() {
    signal input in;
    signal output out;

    // ['A', 'Z']
    component le_Z = LessThan(8);
    le_Z.in[0] <== in;
    le_Z.in[1] <== 90+1;
    
    component ge_A = GreaterThan(8);
    ge_A.in[0] <== in;
    ge_A.in[1] <== 65-1;
    
    signal range_AZ <== ge_A.out * le_Z.out;
    signal sum_AZ <== range_AZ * (in - 65);

    // ['a', 'z']
    component le_z = LessThan(8);
    le_z.in[0] <== in;
    le_z.in[1] <== 122+1;
    
    component ge_a = GreaterThan(8);
    ge_a.in[0] <== in;
    ge_a.in[1] <== 97-1;
    
    signal range_az <== ge_a.out * le_z.out;
    signal sum_az <== sum_AZ + range_az * (in - 71);

    // ['0', '9']
    component le_9 = LessThan(8);
    le_9.in[0] <== in;
    le_9.in[1] <== 57+1;
    
    component ge_0 = GreaterThan(8);
    ge_0.in[0] <== in;
    ge_0.in[1] <== 48-1;
    
    signal range_09 <== ge_0.out * le_9.out;
    signal sum_09 <== sum_az + range_09 * (in + 4);

    // base64
    // // '+'
    // component equal_plus = IsZero();
    // equal_plus.in <== in - 43;
    // signal sum_plus <== sum_09 + equal_plus.out * (in + 19);

    // // // '.'
    // // component equal_period = IsZero();
    // // equal_period.in <== in - 46;
    // // signal sum_period <== sum_plus + equal_period.out * (in - 30);

    // // '/'
    // component equal_slash = IsZero();
    // equal_slash.in <== in - 47;
    // signal sum_slash <== sum_plus + equal_slash.out * (in + 16);

    // out <== sum_slash;

    // base64url
    // '-'
    component equal_minus = IsZero();
    equal_minus.in <== in - 45;
    signal sum_minus <== sum_09 + equal_minus.out * 62;

    // '_'
    component equal_underline = IsZero();
    equal_underline.in <== in - 95;
    signal sum_underline <== sum_minus + equal_underline.out * 63;

    out <== sum_underline;
}

template Base64Decode(N) {
    var M = 4*((N+2)\3);
    signal input in[M];
    signal output out[N];

    component bits_in[M\4][4];
    component bits_out[M\4][3];
    component translate[M\4][4];

    var idx = 0;
    for (var i = 0; i < M; i += 4) {
        for (var j = 0; j < 3; j++) {
            bits_out[i\4][j] = Bits2Num(8);
        }
        
        for (var j = 0; j < 4; j++) {
            bits_in[i\4][j] = Num2Bits(6);
            translate[i\4][j] = Base64Lookup();
            translate[i\4][j].in <== in[i+j];
            translate[i\4][j].out ==> bits_in[i\4][j].in;
        }

        // Do the re-packing from four 6-bit words to three 8-bit words.
        for (var j = 0; j < 6; j++) {
            bits_out[i\4][0].in[j+2] <== bits_in[i\4][0].out[j];
        }
        bits_out[i\4][0].in[0] <== bits_in[i\4][1].out[4];
        bits_out[i\4][0].in[1] <== bits_in[i\4][1].out[5];

        for (var j = 0; j < 4; j++) {
            bits_out[i\4][1].in[j+4] <== bits_in[i\4][1].out[j];
        }
        for (var j = 0; j < 4; j++) {
            bits_out[i\4][1].in[j] <== bits_in[i\4][2].out[j+2];
        }

        bits_out[i\4][2].in[6] <== bits_in[i\4][2].out[0];
        bits_out[i\4][2].in[7] <== bits_in[i\4][2].out[1];
        for (var j = 0; j < 6; j++) {
            bits_out[i\4][2].in[j] <== bits_in[i\4][3].out[j];
        }

        for (var j = 0; j < 3; j++) {
            if (idx+j < N) {
                out[idx+j] <== bits_out[i\4][j].out;
            }
        }
        idx += 3;
    }
}

// This function applies padding to the JWT token header before calling B64Decode
template JWTB64Decode(max_msg_bytes, max_json_bytes) {
    var EQUALS_CHARACTER = 61;           /* 61 is "=" */
    signal input period_idx;
    signal input message[max_msg_bytes];
    signal output out[max_json_bytes];

    // Apply padding to header before base64 decoding. See example here: 
    // https://github.com/latchset/jwcrypto/blob/41fb08a00ad2a36a1d85bf77ad973b31144ef9f2/jwcrypto/common.py#L20
    // The length of the header is period_idx
    component padding_bytes = NumPaddingBytes(15);
    padding_bytes.len <== period_idx;

    // First we remove the period between header and payload
    component no_period = RemoveValue(max_msg_bytes);
    no_period.p <== period_idx;
    no_period.in <== message;
    
    // Now insert 0, 1 or 2 equal signs as necessary:
    //      If padding_bytes > 0, append an "=";
    //      If padding_bytes > 1, append an "=";
    component cmp1 = IsZero();
    cmp1.in <== padding_bytes.out;
    component ci = ConditionalInsert(max_msg_bytes);
    ci.p <== period_idx;
    ci.cond <== 1 - cmp1.out;
    ci.c <== EQUALS_CHARACTER;
    ci.in <== no_period.out;

    component cmp2 = GreaterThan(15);
    cmp2.in[0] <== padding_bytes.out;
    cmp2.in[1] <== 1;
    component ci2 = ConditionalInsert(max_msg_bytes);
    ci2.p <== period_idx;
    ci2.cond <== cmp2.out;
    ci2.c <== EQUALS_CHARACTER;
    ci2.in <== ci.out;

    // Call the b64 decoder
    component message_b64 = Base64Decode(max_json_bytes);
    message_b64.in <== ci2.out;

    out <== message_b64.out;
}

template NumPaddingBytes(n) {
    signal input len;
    signal output out;

    // If the length is 0 or 2 mod 4 we append 0 or 2 bytes of padding ("" or ==, resp.)
    // If the length is 3 mod 4 we append 1 byte of padding (=)
    component n2b = Num2Bits(15);
    n2b.in <== len;

    // If len % mod 4 is 3 return 1, otherwise return len % 4    
    signal len_mod4 <== (n2b.out[0] * 1 + n2b.out[1] * 2);
    component eq = IsEqual();
    eq.in[0] <== len_mod4;
    eq.in[1] <== 3;
    
    out <== eq.out * 1 + (1 - eq.out) * len_mod4;
}

//  For a buffer of length n, remove the character at position p. 
//    The resulting buffer will have length n - 1, but padded with zeros to n.
//    E.g.:    input: [a, b, c, d, e, f], p = 2
//             output: [a, b, d, e, f, 0]
//    Assumes p < 2^15
template RemoveValue(n) {
    signal input in[n];
    signal output out[n];
    signal input p;

    assert(p < 32768);

    component cmp[n];
    signal normal_branch[n];

    for (var i = 0; i < n - 1; i++) {
        /* If i >= p then out[i] = in[i+1] else out[i] = in[i] */
        cmp[i] = GreaterEqThan(15);
        cmp[i].in[0] <== i;
        cmp[i].in[1] <== p; 

        var i_plus_one = cmp[i].out;
        var i_normal = 1 - cmp[i].out;

        normal_branch[i] <== (in[i] * i_normal);
        out[i] <== (in[i + 1] * (i_plus_one)) + normal_branch[i];
    }
    out[n - 1] <== 0;
}

//    For a buffer of length n, insert a character c at position p. 
//    If cond == false, no change is made to the buffer, otherwise:
//    The resulting buffer will be one larger, it's assumed that some of the buffer is padded with zeroes, 
//    otherwise values are lost off the end of the buffer. 
//    E.g.:    input: [a, b, c, d, 0, 0], p = 2, c = "."
//             output: [a, b, ".", c, d, 0]
//     Assumes p and n are strictly less than  2^15 - 1.
//     p must be > 1
template ConditionalInsert(n) {
    signal input in[n];
    signal output out[n];
    signal input p;
    signal input c;
    signal input cond;

    assert(p < 32767);

    component lt[n];
    component gt[n];
    signal eq[n];
    signal branch_lt[n];
    signal branch_gt[n];
    signal branch_eq[n];

    // If cond == false, set p = "MAX_p" so that i < p always true in
    // the loop below, so that we just copy in[n] to out[n]
    signal _p <== (1-cond)*32767 + cond * p;

    out[0] <== in[0];
    for (var i = 1; i < n; i++) {
        //  The circuit below implements
        //    if i < p then out[i] = in[i]
        //    else if i > p then out[i] = in[i+1]
        //    else if i == p then out[i] = c
        
        lt[i] = LessThan(15);
        lt[i].in[0] <== i;
        lt[i].in[1] <== _p;

        gt[i] = GreaterThan(15);
        gt[i].in[0] <== i;
        gt[i].in[1] <== _p;

        eq[i] <== (1 - lt[i].out) * (1 - gt[i].out);

        branch_lt[i] <== lt[i].out * in[i];
        branch_gt[i] <== gt[i].out * in[i-1];
        branch_eq[i] <== eq[i] * c;

        out[i] <== branch_lt[i] + branch_gt[i] + branch_eq[i];
    }
}