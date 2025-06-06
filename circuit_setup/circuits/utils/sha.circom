pragma circom 2.0.3;

include "../circomlib/circuits/bitify.circom";
include "./sha256general.circom";
include "./sha256partial.circom";

// Assumption: The value `in_len_padded_bytes * 8` must fit within `ceil(log2(max_num_bytes * 8))` bits.
// This range constraint is assumed (but not enforced) by the underlying `Sha256General` template.
// It must be enforced externally, via a Num2Bits check, to prevent incorrect hash outputs.
template Sha256Bytes(max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal input in_len_padded_bytes;
    signal output out[256];

    var num_bits = max_num_bytes * 8;
    component sha = Sha256General(num_bits);

    component bytes[max_num_bytes];
    for (var i = 0; i < max_num_bytes; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== in_padded[i];
        for (var j = 0; j < 8; j++) {
            sha.paddedIn[i*8+j] <== bytes[i].out[7-j];
        }
    }
    sha.in_len_padded_bits <== in_len_padded_bytes * 8;

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}

// Assumption: The value `in_len_padded_bytes * 8` must fit within `ceil(log2(max_num_bytes * 8))` bits.
// This range constraint is assumed (but not enforced) by the underlying `Sha256Partial` template.
// It must be enforced externally, via a Num2Bits check, to prevent incorrect hash outputs.
template Sha256BytesPartial(max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal input in_len_padded_bytes;
    signal input pre_hash[32];
    signal output out[256];

    var num_bits = max_num_bytes * 8;
    component sha = Sha256Partial(num_bits);

    component bytes[max_num_bytes];
    for (var i = 0; i < max_num_bytes; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== in_padded[i];
        for (var j = 0; j < 8; j++) {
            sha.paddedIn[i*8+j] <== bytes[i].out[7-j];
        }
    }
    sha.in_len_padded_bits <== in_len_padded_bytes * 8;

    component states[32];
    for (var i = 0; i < 32; i++) {
        states[i] = Num2Bits(8);
        states[i].in <== pre_hash[i];
        for (var j = 0; j < 8; j++) {
            sha.pre_state[8*i+j] <== states[i].out[7-j];
        }
    }

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}