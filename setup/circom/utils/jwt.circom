pragma circom 2.0.3;

include "./sha.circom";
include "./rsa.circom";
include "./base64.circom";


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
    component rsa = RSAVerify65537(n, k);
    for (var i = 0; i < msg_len; i++) {
        rsa.base_message[i] <== base_msg[i].out;
    }
    for (var i = msg_len; i < k; i++) {
        rsa.base_message[i] <== 0;
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