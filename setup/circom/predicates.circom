pragma circom 2.1.6;

include "./indicator.circom";
include "./circomlib/circuits/mux1.circom";
include "./circomlib/circuits/comparators.circom";

// Check the email has the substring of `@microsoft.com"`
// Assume l and r are valid.
template AssertMicrosoftDomain(msg_json_len) {
    signal input json_bytes[msg_json_len];
    signal input range_indicator[msg_json_len];

    // The one-hot vector with 1 at the position of '@'
    signal at_indicator[msg_json_len];
    signal at_indicator_in_interval[msg_json_len];

    var sum = 0;
    for (var j = 0; j < msg_json_len; j++) {
        at_indicator[j] <-- (range_indicator[j] == 1) && (json_bytes[j] == 64);    // 64 is the ASCII code of '@'
        at_indicator_in_interval[j] <== range_indicator[j] * at_indicator[j];
        at_indicator_in_interval[j] * (json_bytes[j] - 64) === 0;
        sum += at_indicator_in_interval[j];
    }
    sum === 1;

    var domain_len = 15;
    var domain[domain_len] = [64, 109, 105, 99, 114, 111, 115, 111, 102, 116, 46, 99, 111, 109, 34];  // `@microsoft.com"`

    for (var i = 0; i < domain_len; i++) {
        for (var j = i; j < msg_json_len; j++) {
            at_indicator[j - i] * (json_bytes[j] - domain[i]) === 0;
        }
    }
}

// Check the email has the substring of domain specified (as string beginning with '@')
// Assume l and r are valid.
template AssertDomainName(msg_json_len) {
    signal input json_bytes[msg_json_len];
    signal input range_indicator[msg_json_len];

    // The one-hot vector with 1 at the position of '@'
    signal at_indicator[msg_json_len];
    signal at_indicator_in_interval[msg_json_len];

    var sum = 0;
    for (var j = 0; j < msg_json_len; j++) {
        at_indicator[j] <-- (range_indicator[j] == 1) && (json_bytes[j] == 64);    // 64 is the ASCII code of '@'
        at_indicator_in_interval[j] <== range_indicator[j] * at_indicator[j];
        at_indicator_in_interval[j] * (json_bytes[j] - 64) === 0;
        sum += at_indicator_in_interval[j];
    }
    sum === 1;

    signal input domain[253];  // 253 is the maximum domain length

    // vector with ones where the domain of the email address is
    // (including the @ sign)
    // and domain range is a binary vector
    // with ones indicating characters of email address containing domain.
    signal domain_range[msg_json_len];
    var pre_sum = 0;

    // Because at_indicator has only one hot,
    // pre_sum is zero before, one after
    for (var i=0; i < msg_json_len; i++) {
        pre_sum += at_indicator[i];
        domain_range[i] <== range_indicator[i]*pre_sum;
    }

    // now mask out the domain
    signal placed_domain[msg_json_len];

    for (var i = 0; i < msg_json_len; i++) {
        placed_domain[i] <== domain_range[i]*json_bytes[i];
    }

    signal formatted_domain1[255]; // 253+2 for @ and "
    signal formatted_domain2[255];
    signal first_zero[255];

    formatted_domain1[0] <== 64;
    first_zero[0] <== 0;

    formatted_domain1[254] <== 0;

    var first_zero_sum = 0;

    for (var i = 1; i < 254; i++) {
        formatted_domain1[i] <== domain[i-1];
        first_zero[i] <-- (formatted_domain1[i-1] != 0)*(formatted_domain1[i] == 0);
        first_zero_sum += first_zero[i];
    }

    first_zero[254] <-- (formatted_domain1[253] != 0);

    first_zero_sum += first_zero[254];
    first_zero_sum === 1;

    for (var i = 0; i < 255; i++) {
        formatted_domain2[i] <== formatted_domain1[i] + 34*first_zero[i];
    }

    for (var i = 0; i < 255; i++) {
        for (var j = i; j < msg_json_len; j++) {
            at_indicator[j - i] * (placed_domain[j] - formatted_domain2[i]) === 0;
        }
    }
}

// Compare the exp claim with the current_ts.
// Assume range_indicator is valid
template AssertNotExpired(msg_json_len) {
    signal input json_bytes[msg_json_len];
    signal input range_indicator[msg_json_len];
    signal input current_ts;

    signal timestamp[msg_json_len + 1];
    component mux1[msg_json_len];

    timestamp[0] <== 0;
    for (var i = 0; i < msg_json_len; i++) {
        mux1[i] = Mux1();

        mux1[i].c[0] <== timestamp[i];
        mux1[i].c[1] <== (timestamp[i] * 10 + json_bytes[i] - 48);
        mux1[i].s <== range_indicator[i];
        
        timestamp[i + 1] <== mux1[i].out;
    }
    signal out <== LessThan(128)([current_ts, timestamp[msg_json_len]]);
    out === 1;
}

// A trivial predicate used 1) for testing and 2) as a starting point to create a new predicate
template AssertNothing(msg_json_len) {
    signal input json_bytes[msg_json_len];
    signal input range_indicator[msg_json_len];

    // Check that the first two bytes of the token are greater than 10
    // (trivially true for any token with a valid header)
    signal gt0 <== GreaterThan(8)([json_bytes[0], 10]);
    gt0 === 1;
    signal gt1 <== GreaterThan(8)([json_bytes[1], 10]);
    gt1 === 1;
}

// Compare a numeric claim value v to an integer x, assert that v > x.
// Assumes that v has numeric type and is non-negative
template AssertGreaterThan(msg_json_len) {
    signal input json_bytes[msg_json_len];
    signal input range_indicator[msg_json_len];
    signal input compare_to;

    signal value[msg_json_len + 1];
    component mux1[msg_json_len];

    value[0] <== 0;
    for (var i = 0; i < msg_json_len; i++) {
        mux1[i] = Mux1();

        mux1[i].c[0] <== value[i];
        mux1[i].c[1] <== (value[i] * 10 + json_bytes[i] - 48);
        mux1[i].s <== range_indicator[i];
        
        value[i + 1] <== mux1[i].out;
    }
    signal out <== GreaterThan(128)([value[msg_json_len], compare_to]);
    out === 1;
}