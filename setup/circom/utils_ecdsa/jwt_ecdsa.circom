pragma circom 2.0.3;

include "./sha.circom";
include "../utils/base64.circom";
include "../circom-ecdsa-circuits/ecdsa.circom";

template JWTVerifyES256K(max_msg_bytes, max_json_bytes, n, k) {
    signal input message[max_msg_bytes]; // header + . + payload
    signal input signature_r[k];
    signal input signature_s[k];
    signal input pubkey_x[k];
    signal input pubkey_y[k];

    signal input message_padded_bytes; // length of the message including the padding
    signal input period_idx; // index of the period in the base64 encoded msg

    signal output jwt_bytes[max_json_bytes];

    // *********** hash the padded message ***********
    component sha = Sha256Bytes(max_msg_bytes);
    sha.in_len_padded_bytes <== message_padded_bytes;
    for (var i = 0; i < max_msg_bytes; i++) {
        sha.in_padded[i] <== message[i];
    }
    
    // Call JWT verify with the digest and all inputs
    component jwt_verify = JWTVerifyES256KWithSuppliedDigest(max_msg_bytes, max_json_bytes, n, k);
    jwt_verify.message_padded_bytes <== message_padded_bytes;
    jwt_verify.period_idx <== period_idx;
    for (var i = 0; i < max_msg_bytes; i++) {
        jwt_verify.message[i] <== message[i];
    }
    for (var i = 0; i < k; i++) {
        jwt_verify.signature_r[i] <== signature_r[i];
        jwt_verify.signature_s[i] <== signature_s[i];
        jwt_verify.pubkey_x[i] <== pubkey_x[i];
        jwt_verify.pubkey_y[i] <== pubkey_y[i];
    }
    for (var i = 0; i < 256; i++) {
        jwt_verify.digest[i] <== sha.out[i];
    }

    // Assign output
    for (var i = 0; i < max_json_bytes; i++) {
        jwt_bytes[i] <== jwt_verify.jwt_bytes[i];
    }

}

template JWTVerifyES256KWithSuppliedDigest(max_msg_bytes, max_json_bytes, n, k) {
    signal input message[max_msg_bytes]; // header + . + payload
    signal input signature_r[k];
    signal input signature_s[k];
    signal input pubkey_x[k];
    signal input pubkey_y[k];
    signal input digest[256];
 
    signal input message_padded_bytes; // length of the message including the padding
    signal input period_idx; // index of the period in the base64 encoded msg
 
    signal output jwt_bytes[max_json_bytes];
 
    // Convert the digest to an integer     
    var msg_len = k;
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
    component ecdsa = ECDSAVerifyNoPubkeyCheck(n,k);
    for (var i = 0; i < msg_len; i++) {
        ecdsa.msghash[i] <== digest[i];
    }
    for (var i = msg_len; i < k; i++) {
        ecdsa.msghash[i] <== 0;
    }  
    for (var i = 0; i < k; i++) {
        ecdsa.pubkey[0][i] <== pubkey_x[i];
        ecdsa.pubkey[1][i] <== pubkey_y[i];
        ecdsa.r[i] <== signature_r[i];
        ecdsa.s[i] <== signature_s[i];
    }
    //log("Result from ecdsa verify component: ", ecdsa.result);
    ecdsa.result === 0;
     
    // decode to JSON format
    component b64_decoder = JWTB64Decode(max_msg_bytes, max_json_bytes);
    b64_decoder.period_idx <== period_idx;
    b64_decoder.message <== message;

    jwt_bytes <== b64_decoder.out;
}

template JWTHashOnlyES256K(max_msg_bytes, max_json_bytes, n, k) {
    signal input message[max_msg_bytes]; // header + . + payload
    signal input message_padded_bytes; // length of the message including the padding
    signal input period_idx; // index of the period in the base64 encoded msg

    signal output jwt_bytes[max_json_bytes];
    signal output digest[256];

    // Hash the padded message and output the digest
    component sha = Sha256Bytes(max_msg_bytes);
    sha.in_len_padded_bytes <== message_padded_bytes;
    sha.in_padded <== message;
    digest <== sha.out;

    // Decode to JSON format and output
    component b64_decoder = JWTB64Decode(max_msg_bytes, max_json_bytes);
    b64_decoder.period_idx <== period_idx;
    b64_decoder.message <== message;

    jwt_bytes <== b64_decoder.out;

}