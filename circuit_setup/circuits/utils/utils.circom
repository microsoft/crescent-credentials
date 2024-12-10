pragma circom 2.0.3;

include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/comparators.circom";
include "./fp.circom";

// Takes `num_limbs` number of limbs of `limb_size` bits each, and breaks them
// up into bits, outputs an array of `num_limbs*limb_size` bits
template LimbsToBits(limb_size, num_limbs) {
    signal input limbs[num_limbs];
    signal output bits[limb_size*num_limbs];
    
    component num_to_bits[num_limbs];

    for (var i = 0; i < num_limbs; i++) {
        num_to_bits[i] = Num2Bits(limb_size);
        num_to_bits[i].in <== limbs[num_limbs - i - 1];
        for (var j = 0; j < 128; j++) {
            bits[j + i*limb_size] <== num_to_bits[i].out[limb_size - 1 - j];
        }
    }

}

// returns ceil(log2(a+1))
function log2_ceil(a) {
    var n = a+1;
    var r = 0;
    while (n>0) {
        r++;
        n \= 2;
    }
    return r;
}

// Lifted from MACI https://github.com/privacy-scaling-explorations/maci/blob/v1/circuits/circom/trees/incrementalQuinTree.circom#L29 (MIT Licensed)
// Bits is ceil(log2 choices)
template QuinSelector(choices, bits) {
    signal input in[choices];
    signal input index;
    signal output out;

    // Ensure that index < choices
    component lessThan = LessThan(bits);
    lessThan.in[0] <== index;
    lessThan.in[1] <== choices;
    lessThan.out === 1;

    component calcTotal = CalculateTotal(choices);
    component eqs[choices];

    // For each item, check whether its index equals the input index.
    for (var i = 0; i < choices; i ++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== index;

        // eqs[i].out is 1 if the index matches. As such, at most one input to
        // calcTotal is not 0.
        calcTotal.nums[i] <== eqs[i].out * in[i];
    }

    // Returns 0 + 0 + ... + item
    out <== calcTotal.sum;
}

template CalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for (var i=1; i < n; i++) {
        sums[i] <== sums[i - 1] + nums[i];
    }

    sum <== sums[n - 1];
}

// Written by us
// n bytes per signal, n = 31 usually
template Packed2Bytes(n){
    signal input in; // < 2 ^ (8 * 31)
    signal output out[n]; // each out is < 64
    // Rangecheck in and out?

    // Constrain bits
    component nbytes = Num2Bits(8 * n);
    nbytes.in <== in;
    component bytes[n];

    for (var k = 0; k < n; k++){
        // Witness gen out
        out[k] <-- (in >> (k * 8)) % 256;

        // Constrain bits to match
        bytes[k] = Num2Bits(8);
        bytes[k].in <== out[k];
        for (var j = 0; j < 8; j++) {
            nbytes.out[k * 8 + j] === bytes[k].out[j];
        }
    }
}

// n bytes per signal, n = 31 usually
template Bytes2Packed(n){
    signal input in[n]; // each in is < 64
    signal pow2[n+1]; // [k] is 2^k
    signal in_prefix_sum[n+1]; // each [k] is in[0] + 2^8 in[1]... 2^{8k-8} in[k-1]. cont.
    // [0] is 0. [1] is in[0]. [n+1] is out.
    signal output out; // < 2 ^ (8 * 31)
    // Rangecheck in and out?

    // Witness gen out
    in_prefix_sum[0] <-- 0;
    for (var k = 0; k < n; k++){
        in_prefix_sum[k+1] <-- in_prefix_sum[k] + in[k] * (2 ** (k * 8));
    }
    out <-- in_prefix_sum[n];

    // Constrain out bits
    component nbytes = Num2Bits(8 * n);
    nbytes.in <== out; // I think this auto-rangechecks out to be < 8*n bits.
    component bytes[n];

    for (var k = 0; k < n; k++){
        bytes[k] = Num2Bits(8);
        bytes[k].in <== in[k];
        for (var j = 0; j < 8; j++) {
            nbytes.out[k * 8 + j] === bytes[k].out[j];
        }
    }
}


