pragma circom 2.1.6;

include "./circomlib/circuits/comparators.circom";
include "indicator.circom";
include "./circomlib/circuits/mimc.circom";

// Converts an array of ascii digits (base-10) and converts them to a field element.
// The input is big endian and may contain trailing zeros. 
// E.g., field elt. 12340 would be the output from input as [49, 50, 51, 52, 48, 0, 0]
template AsciiDigitsToField(n) {
    // Handling zero-padded values makes this more complicated
    // Strategy:
    // 1. reverse the value. e.g, from 4321000 to 0001234 (1 is LS, 4 is MS)
    // 2. compute an indicator vector 0001111, masking out leading zeros
    // 3. Compute pow10 = (0,0,0,1, 10, 10^2, 10^3)
    // 4. compute inner product value * pow10
    signal input digits[n];
    signal output field_elt;
    signal reversed[n];
    for(var i = 0; i < n; i++) {
        reversed[i] <== digits[n-i-1];
    }

    signal lz_mask[n];
    component is_zero[n];
    
    //i = 0
    is_zero[0] = IsZero();
    is_zero[0].in <== reversed[0];
    lz_mask[0] <== 1 - is_zero[0].out;

    for(var i = 1; i < n; i++) {
        is_zero[i] = IsZero();
        is_zero[i].in <== reversed[i];
        lz_mask[i] <== lz_mask[i-1]*1 + (1-lz_mask[i-1]) * (1 - is_zero[i].out);
    }

    signal pow10[n];
    signal p[n+1];
    signal tmp[n];
    p[0] <== 1;

    for(var i = 0; i < n; i++){
        pow10[i] <== p[i] * lz_mask[i];
        tmp[i] <== (lz_mask[i]) * p[i] * 10;
        p[i+1] <== tmp[i] + (1-lz_mask[i]) * p[i] ;
    }

    signal intermediate_value[n];    
    intermediate_value[0] <== pow10[0] * reversed[0];
    for(var i = 1; i < n; i++) {
        intermediate_value[i] <== intermediate_value[i-1] + pow10[i] * (reversed[i] - 48);
    }

    field_elt <== intermediate_value[n-1];
}

// Match the claim name in json_bytes with slice.
// The input just assume the l is valid.
template MatchClaimName(json_byte_len, name_byte_len){
    var MAX_JSON_BITLEN = 16;
    signal input json_bytes[json_byte_len];
    signal input name[name_byte_len];
    signal input l;
    signal input r;
    signal input object_nested_level[json_byte_len + 1];

    signal output value_l;
    signal output value_r;

    component start = PointIndicator(json_byte_len);
    start.l <== l;
    
    // Match the claim name.
    for (var i = 0; i < name_byte_len; i++) {
        for (var j = i; j < json_byte_len; j++) {
            start.indicator[j - i] * (name[i] - json_bytes[j]) === 0;
        }
    }

    // Check the validity of l and r.
    signal interval_valid <== LessThan(MAX_JSON_BITLEN)([l, r]);
    interval_valid === 1;
    signal bound_valid <== LessThan(MAX_JSON_BITLEN)([r, json_byte_len + 1]);
    bound_valid === 1;

    // Check the claim name is located at the outermost object.
    for (var i = 0; i < json_byte_len; i++) {
        start.indicator[i] * (object_nested_level[i + 1] - 1) === 0;
    }

    value_l <== l + name_byte_len;
    value_r <== r;
}

// Validate the claim value without reveal.
// typ : 0 for string, 1 for number, 2 for bool, 3 for null, 4 for array, 5 for object.
template ValidateClaimValue(msg_json_len, typ) {
    signal input json_bytes[msg_json_len];
    signal input l;
    signal input r;

    signal output range_indicator[msg_json_len];
    signal output start_indicator[msg_json_len];
    signal output last_indicator[msg_json_len]; // correspond to r - 1.

    component value_range = IntervalIndicator(msg_json_len);
    value_range.l <== l;
    value_range.r <== r;

    for (var i = 0; i < msg_json_len; i++) {
        range_indicator[i] <== value_range.indicator[i];
        start_indicator[i] <== value_range.start_indicator[i];
        last_indicator[i] <== value_range.last_indicator[i];
    }

    if (typ == 1) {
        // Exclude `,`
        ExcludeSpecial(msg_json_len, 44)(range_indicator, json_bytes);
        // Exclude `]`
        ExcludeSpecial(msg_json_len, 93)(range_indicator, json_bytes);
        // Exclude `}`
        ExcludeSpecial(msg_json_len, 125)(range_indicator, json_bytes);
        AssertEndNumber(msg_json_len)(value_range.last_indicator, json_bytes);
    } else if (typ == 0) {
        signal inside_indicator[msg_json_len];
        for (var i = 0; i < msg_json_len; i++) {
            inside_indicator[i] <== range_indicator[i] - start_indicator[i] - last_indicator[i];
        }
        // Exclude `"`
        ExcludeSpecial(msg_json_len, 34)(inside_indicator, json_bytes);
        // The last character must be '"'
        for (var i = 0; i < msg_json_len; i++) {
            last_indicator[i] * (json_bytes[i] - 34) === 0;
        }
    } else if (typ == 2 || typ  == 3) {
        1 === 0; // assert(false, "Support for types bool and null is not implemented");
    } else {
        // We don't do any operations except revealing it directly for list or object.
        // TODO: we check whether the pairs of `[]` (num(`[`) - num(']') > 0 and = 0 at the right end))
        // or `{}` (num(`{`) - num('}') > 0 and = 0 at the right end)) are valid.
        1 === 0; // assert false
    }
}

// Reveal the claim value with claim_byte_len as the maximum length.
template RevealClaimValueBytes(msg_json_len, claim_byte_len, field_byte_len, is_number) {
    signal input json_bytes[msg_json_len];
    signal input l;
    signal input r;
    signal output value[claim_byte_len];
    signal output value_len;

    component value_range = IntervalIndicator(msg_json_len);
    value_range.l <== l;
    value_range.r <== r;

    value_len <== r - l;

    // Number is special because there's no symbol denoting the end of a number.
    if (is_number) {
        AssertEndNumber(msg_json_len)(value_range.last_indicator, json_bytes);
    }

    var tmp_prod1[claim_byte_len][msg_json_len];
    var tmp_prod2[claim_byte_len][msg_json_len];
    for (var i = 0; i < claim_byte_len; i++) {
        var c = 0;
        for (var j = i; j < msg_json_len; j++) {
            tmp_prod1[i][j] = value_range.start_indicator[j - i] * value_range.indicator[j];
            c +=  tmp_prod1[i][j] * json_bytes[j];
        }
        value[i] <-- c;
        log(c);
    }

    component match_substring = MatchSubstring(msg_json_len, claim_byte_len, field_byte_len);
    for (var i = 0; i < claim_byte_len; i++) {
        match_substring.substr[i] <== value[i];
    }
    for (var i = 0; i < msg_json_len; i++) {
        match_substring.msg[i] <== json_bytes[i];
        match_substring.range_indicator[i] <== value_range.indicator[i];
    }
    match_substring.l <== l;
    match_substring.r <== r;
}

// Reveal the claim value as a single field element. 
// The claim_byte_len must be less than 32 so that it fits in a 254-bit field element
template RevealClaimValue(msg_json_len, claim_byte_len, field_byte_len, is_number) {
    signal input json_bytes[msg_json_len];
    signal input l;
    signal input r;
    
    component reveal_claim = RevealClaimValueBytes(msg_json_len, claim_byte_len, field_byte_len, is_number);
    reveal_claim.json_bytes <== json_bytes;
    reveal_claim.l <== l;
    reveal_claim.r <== r;
    
    // Pack the bytes to a field element
    // For integers, each byte is a decimal digit, we convert to an integer
    signal output value;
    if(is_number) {
        component convert = AsciiDigitsToField(claim_byte_len);
        convert.digits <== reveal_claim.value;
        value <== convert.field_elt;
    }
    else {
        signal intermediate_value[claim_byte_len];
        
        intermediate_value[0] <== reveal_claim.value[0];
        log("reveal_claim.value[0] = ", reveal_claim.value[0]);
        log("intermediate_value[0] = ", intermediate_value[0]);
        var  pow256 = 256;
        for(var i = 1; i < claim_byte_len; i++) {
            log("reveal_claim.value[", i, "] = ", reveal_claim.value[i]);
            intermediate_value[i] <== intermediate_value[i-1] + reveal_claim.value[i] * pow256;
            log("intermediate_value[", i, "] = ", intermediate_value[i]);
            pow256 = pow256*256;
        }
        value <== intermediate_value[claim_byte_len-1];        
    }
}

// Replace double quote characters with zero
template StripQuotes(input_len) {
    signal input in[input_len];
    signal output value[input_len];
    component is_eq[input_len];
    for (var i = 0; i < input_len; i++) {
        is_eq[i] = IsEqual();
        is_eq[i].in[0] <== in[i];
        is_eq[i].in[1] <== 34; // 34 is the ASCII code of " (double quote)
        value[i] <== is_eq[i].out * 0 + (1 - is_eq[i].out) * in[i];
    }
}

// Reveal part of the claim value, following the @ symbol
// E.g., reveals 'example.com' on input 'alice@example.com'
// The claim_byte_len must be less than 32 so that it fits in a 254-bit field element
template RevealDomainOnly(msg_json_len, claim_byte_len, field_byte_len, is_number) {
    signal input json_bytes[msg_json_len];
    signal input l;
    signal input r;
    
    component reveal_claim_q = RevealClaimValueBytes(msg_json_len, claim_byte_len, field_byte_len, is_number);
    reveal_claim_q.json_bytes <== json_bytes;
    reveal_claim_q.l <== l;
    reveal_claim_q.r <== r;

    component reveal_claim = StripQuotes(claim_byte_len);
    reveal_claim.in <== reveal_claim_q.value;
    
    // Create an indicator vector for where the domain occurs
    // pow256 is a vector of powers of 256 we use to pack the string into a field elt.
    component is_eq[claim_byte_len];
    signal indicator[claim_byte_len];
    signal  pow256[claim_byte_len];    

    assert(reveal_claim.value[0] != 64);    
    indicator[0] <== 0; // Assumes the claim doesn't start with @
    pow256[0] <== 0;

    is_eq[0] = IsEqual();
    is_eq[0].in[0] <== 1;
    is_eq[0].in[1] <== 0;

    for(var i = 1; i < claim_byte_len; i++) {
        is_eq[i] = IsEqual();
        is_eq[i].in[0] <== reveal_claim.value[i];
        is_eq[i].in[1] <== 64; // 64 is the ASCII code of '@'
        indicator[i] <== is_eq[i].out + indicator[i-1];
        (1 - indicator[i])*indicator[i] === 0;      // make sure it's in {0,1}, ensures only one @ symbol
        
        pow256[i] <== is_eq[i-1].out * 1 + (1-is_eq[i-1].out)*(pow256[i-1] * 256) ;      
    }

    // Pack the indicated bytes to a field element
    signal output value;
    signal intermediate_value[claim_byte_len];
    
    intermediate_value[0] <== 0;    
    for(var i = 1; i < claim_byte_len; i++) {
        intermediate_value[i] <== intermediate_value[i-1] + reveal_claim.value[i] * pow256[i];
    }
    value <== intermediate_value[claim_byte_len-2];        
}

// Hash and Reveal the claim value with claim_byte_len as the maximum length.
template HashRevealClaimValue(msg_json_len, claim_byte_len, field_byte_len, is_number) {
    signal input json_bytes[msg_json_len];
    signal input l;
    signal input r;
    
    component reveal_claim = RevealClaimValueBytes(msg_json_len, claim_byte_len, field_byte_len, is_number);
    reveal_claim.json_bytes <== json_bytes;
    reveal_claim.l <== l;
    reveal_claim.r <== r;
    
    signal output digest;

    component mimc_hash = MultiMiMC7(claim_byte_len, 10);
    for(var i=0; i<claim_byte_len; i++) {
        mimc_hash.in[i] <== reveal_claim.value[i];
    }
    mimc_hash.k <== 0;

    digest <== mimc_hash.out;
}

// Generates constraints to enforce that `msg` has the substring `substr` starting at position `l` and ending at position `r`
// Assumes that
// r > l,
// r-l < substr_byte_len,
// substr_byte_len < msg_byte_len
// The approach is to
//  1. Create an indicator vector I for the substr
//  2. Compute a powers-of-two vector I' from I, where the run of 1s is replaced with 1, 2, 2^2, 2^3, ..., 2^substr_byte_len
//  3. Compute the field element v = I' * msg (where * is the dot-product). Note that v packs the bytes of substr into a field element, assuming (for now) there is no overflow
//  4. Compute the expected field element v' by packing the bytes of substr into a field element
//  5. Ensure that v == v'
//  When substr_byte_len is larger than field_byte_len, the process is repeated in blocks of size field_byte_len
template MatchSubstring(msg_byte_len, substr_byte_len, field_byte_len) {
    signal input msg[msg_byte_len];
    signal input substr[substr_byte_len];
    signal input range_indicator[msg_byte_len];
    signal input l;
    signal input r;

    var substr_field_len = (substr_byte_len + field_byte_len - 1) \ field_byte_len;

    // Generate the power of two vectors. 2^0 is located at the position of l.
    component field_window_range;
    field_window_range = IntervalIndicator(msg_byte_len);
    field_window_range.l <== l;
    field_window_range.r <== l + field_byte_len;

    signal pow256_window[msg_byte_len];
    pow256_window[0] <== Mux1()([0, 1], field_window_range.start_indicator[0]);
    component previous_mux[msg_byte_len - 1];
    for (var i = 1; i < msg_byte_len; i++) {
        previous_mux[i - 1] = Mux1();
        previous_mux[i - 1].c[0] <== pow256_window[i - 1] * 256;
        previous_mux[i - 1].c[1] <== 1;
        previous_mux[i - 1].s <== field_window_range.start_indicator[i];
        pow256_window[i] <== previous_mux[i - 1].out * field_window_range.indicator[i];
    }

    signal prod1[substr_field_len][msg_byte_len];
    signal prod2[substr_field_len][msg_byte_len];

    signal expected_fields[substr_field_len];

    var pow256[substr_byte_len];
    pow256[0] = 1;
    for (var i = 1; i < field_byte_len; i++) {
        pow256[i] = pow256[i - 1] * 256;
    }

    for (var i = 0; i < substr_field_len; i++) {
        var matched_field = 0;
        for (var j = i * field_byte_len; j < msg_byte_len; j++) {
            prod1[i][j] <== range_indicator[j] * msg[j];
            prod2[i][j] <== prod1[i][j] * pow256_window[j - i * field_byte_len];
            matched_field += prod2[i][j];
        }

        var expected_field = 0;
        for (var j = 0; j < field_byte_len; j++) {
            expected_field += substr[i * field_byte_len + j] * pow256[j];
        }
        expected_fields[i] <== expected_field;
        matched_field === expected_fields[i];
    }
}

template ExcludeSpecial(byte_len, special_char) {
    signal input interval[byte_len];
    signal input msg[byte_len];
    component is_zero[byte_len];

    for (var i = 0; i < byte_len; i++) {
        is_zero[i] = IsZero();
        is_zero[i].in <== msg[i] - special_char;
        interval[i] * is_zero[i].out === 0;
    }
}

template AssertEndNumber(msg_byte_len) {
    signal input last_indicator[msg_byte_len];
    signal input msg[msg_byte_len];

    // The last character must be a non-number, to ensure the entire number is being used,
    // the possibilities are ',' (44) or '}' (125)
    signal tmp[msg_byte_len];
    for (var j = 1; j < msg_byte_len; j++) {
        tmp[j] <== last_indicator[j - 1] * (msg[j] - 44); // 44 is the ASCII code of ','
        tmp[j] * (msg[j] - 125) === 0; // 125 is the ASCII code of '}'
    }
}