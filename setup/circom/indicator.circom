pragma circom 2.1.6;

include "./circomlib/circuits/mux1.circom";
include "./circomlib/circuits/comparators.circom";

// Generate a zero vector with 1 at the given position (a one-hot vector).
template PointIndicator(max_array_len) {
    signal input l;
    signal output indicator[max_array_len];

    assert(l < max_array_len);

    for (var j = 0; j < max_array_len; j++) {
        indicator[j] <-- (j == l);
    }

    var check_sum;
    check_sum = indicator[0];
    for (var j = 1; j < max_array_len; j++) {
        check_sum += indicator[j];
    }
    check_sum === 1;
    for (var j = 0; j < max_array_len; j++) {
        indicator[j] * (j - l) === 0;
    }
}

// The indicator is a binary array with 1's only at the [l, r) interval.
// Assume l < r and r <= max_array_len.
template IntervalIndicator(max_array_len) {
    signal input l;
    signal input r;

    assert(l < r);
    assert(r <= max_array_len);

    signal output indicator[max_array_len];
    signal output start_indicator[max_array_len];
    signal output last_indicator[max_array_len];

    component start = PointIndicator(max_array_len);
    start.l <== l;
    component last  = PointIndicator(max_array_len);
    last.l <== r - 1;
    
    for (var i = 0; i < max_array_len; i++) {
        if (i > 0) {
            indicator[i] <== indicator[i - 1] + start.indicator[i] - last.indicator[i - 1];
        } else {
            indicator[i] <== start.indicator[i];
        }
    }

    for (var i = 0; i < max_array_len; i++) {
        start_indicator[i] <== start.indicator[i];
        last_indicator[i] <== last.indicator[i];
    }
}