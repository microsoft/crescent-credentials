pragma circom 2.0.3;

include "./sha.circom";
include "./rsa.circom";
include "./base64.circom";
include "../circomlib/circuits/bitify.circom";


template JWTVerifyWithSuppliedDigest(max_msg_bytes, max_json_bytes, n, k) {
    signal input message[max_msg_bytes]; // header + . + payload
    signal input digest[256];
    signal input modulus[k];  // Modulus of RSA public key, exponent assumed to be 2^16 + 1
    signal input signature[k];

    signal input period_idx; // index of the period in the base64 encoded msg

    signal output jwt_bytes[max_json_bytes];

    // Convert the digest to an integer 
    // TODO: this conversion is undone in RSAVerify65537; more efficient (and simpler!) if that function accepted message digest as bits rather than integer
    var msg_len = (256+n)\n;
    component base_msg[msg_len];
    for (var i = 0; i < msg_len; i++) {
        base_msg[i] = Bits2Num(n);
    }
    for (var i = 0; i < 256; i++) {
        base_msg[i\n].in[i%n] <== digest[255 - i];
    }
    for (var i = 256; i < n*msg_len; i++) {
        base_msg[i\n].in[i%n] <== 0;
    }

    // *********** verify signature for the message *********** 
    component rsa = RSAVerifier65537(n, k);
    for (var i = 0; i < msg_len; i++) {
        rsa.message[i] <== base_msg[i].out;
    }
    for (var i = msg_len; i < k; i++) {
        rsa.message[i] <== 0;
    }
    
    for (var i = 0; i < k; i++) {
        rsa.modulus[i] <== modulus[i];
    }
    
    for (var i = 0; i < k; i++) {
        rsa.signature[i] <== signature[i];
    }

    // decode to JSON format
    component b64_decoder = JWTB64Decode(max_msg_bytes, max_json_bytes);
    b64_decoder.period_idx <== period_idx;
    b64_decoder.message <== message;

    jwt_bytes <== b64_decoder.out;
}

template JWTVerify(max_msg_bytes, max_json_bytes, n, k) {
    signal input message[max_msg_bytes]; // header + . + payload
    signal input modulus[k];  // Modulus of RSA public key, exponent assumed to be 2^16 + 1
    signal input signature[k];

    signal input message_padded_bytes; // length of the message including the padding
    signal input period_idx; // index of the period in the base64 encoded msg

    signal output jwt_bytes[max_json_bytes];

    // *********** hash the padded message ***********
    component sha = Sha256Bytes(max_msg_bytes);
    for (var i = 0; i < max_msg_bytes; i++) {
        sha.in_padded[i] <== message[i];
    }
    
    sha.in_len_padded_bytes <== message_padded_bytes;

    component jwt_verify = JWTVerifyWithSuppliedDigest(max_msg_bytes, max_json_bytes, n, k);

    for (var i = 0; i < max_msg_bytes; i++) {
        jwt_verify.message[i] <== message[i];
    }

    for (var i = 0; i < k; i++) {
        jwt_verify.modulus[i] <== modulus[i];
        jwt_verify.signature[i] <== signature[i];
    }

    jwt_verify.period_idx <== period_idx;
    
    for (var i = 0; i < 256; i++) {
        jwt_verify.digest[i] <== sha.out[i];
    }

    for (var i = 0; i < max_json_bytes; i++) {
        jwt_bytes[i] <== jwt_verify.jwt_bytes[i];
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
//    Assumes p < 2^15, which is checked in this template via Num2Bits.
template RemoveValue(n) {
    signal input in[n];
    signal output out[n];
    signal input p;

    // Range-checking `p` to ensure it is less than 2^15.
    // This is required by GreaterEqThan(15).
    component p_bits = Num2Bits(15);
    p_bits.in <== p;

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