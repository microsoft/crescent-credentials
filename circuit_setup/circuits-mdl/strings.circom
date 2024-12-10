pragma circom 2.1.6;

include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/mux1.circom";
include "./indicator.circom";
include "./circomlib/circuits/bitify.circom";


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

    var pow256[field_byte_len];
    pow256[0] = 1;
    for (var i = 1; i < field_byte_len; i++) {
        pow256[i] = pow256[i - 1] * 256;
    }

    for (var i = 0; i < substr_field_len; i++) {
        var matched_field = 0;
        for (var j = i * field_byte_len; j < msg_byte_len; j++) {
        //log("range_indicator[",j,"] = ", range_indicator[j], ", msg = ", msg[j]);            
            prod1[i][j] <== range_indicator[j] * msg[j];
            prod2[i][j] <== prod1[i][j] * pow256_window[j - i * field_byte_len];
            matched_field += prod2[i][j];
        }

        var expected_field = 0;
        for (var j = 0; j < field_byte_len; j++) {
            if ((i * field_byte_len + j) < substr_byte_len) {
                expected_field += substr[i * field_byte_len + j] * pow256[j];
            }
        }
        expected_fields[i] <== expected_field;
        //log("matched_field = ", matched_field, ", expected_field = ", expected_field);
        matched_field === expected_fields[i];
    }
}

// Convert SHA-256 digest in bits, to bytes
template DigestToBytes() {
    signal input in[256];
    signal output out[32];
 
    component b2n[32];
    for( var i = 0; i < 32; i++) {

        b2n[i] = Bits2Num(8);
        for(var j = 0; j < 8; j++){ 
            b2n[i].in[7-j] <== in[i*8 + j];
        }
        out[i] <== b2n[i].out;        
    }

}

template DotProd(n) {
    signal input v1[n];
    signal input v2[n];
    signal output out;
    
    signal dp_int[n];
    dp_int[0] <== v1[0] * v2[0];
    for (var i = 1; i < n; i++){
        dp_int[i] <== dp_int[i-1] + v1[i] * v2[i];
    }

    out <== dp_int[n-1];    
}


template Lookup(n) {
    signal input table[n];
    signal input idx;

    component indicator = PointIndicator(n);
    indicator.l <== idx;

    component dp = DotProd(n);
    dp.v1 <== indicator.indicator;
    dp.v2 <== table;

    signal output out <== dp.out;
}

template DaysBeforeMonth() {
    signal input month;
    signal input year;

    signal days_before_month[13] <== [-1, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    component lookup_dbm = Lookup(13);
    lookup_dbm.table <== days_before_month;
    lookup_dbm.idx <== month;
    signal dbm <== lookup_dbm.out;

    // Add one to dbm if month > 2 and IsLeap(year)
    component is_leap = IsLeap();
    is_leap.year <== year;
    
    component gt = GreaterThan(16);
    gt.in[0] <== month;
    gt.in[1] <== 2;

    signal output out <== dbm + is_leap.out * gt.out;
}


// Convert a YY-MM-DD into a unix timestamp (seconds since Jan 1, 1970)
// Following the code here: https://github.com/python/cpython/blob/54b5e4da8a4c6ae527ab238fcd6b9ba0a3ed0fc7/Lib/datetime.py#L63
template UnixTimestamp() {
    signal input year;
    signal input month;
    signal input day;


    // For the range 2024-2040 we precompute the timestamps for Jan 1, then add seconds for the month and day
    // Use the bash command
    //      for Y in {2024..2040}; do date --date="${Y}-01-01" +%s; done
    // to generate the data
    assert(year >= 2024);
    assert(year <= 2040);
    var years_len = 17;    
    signal years[years_len] <== [1704096000, 1735718400, 1767254400, 1798790400, 1830326400, 1861948800, 1893484800, 1925020800,1956556800,1988179200,2019715200,2051251200,2082787200,2114409600,2145945600,2177481600,2209017600];

    component years_lookup = Lookup(years_len);
    years_lookup.table <== years;
    years_lookup.idx <== year - 2024;
    signal year_ts <== years_lookup.out;

    // To figure out how many days before the input month, we need to know if it's a leap year
    // This bash command outputs leap years in our range:
    //      seq -f "%g-02-29" 2024 2040 | date -f- +"%Y" 2>/dev/null
    signal leap_years[years_len] <== [1,0,0,0, 1,0,0,0, 1,0,0,0, 1,0,0,0, 1];

    component is_leap_lookup = Lookup(years_len);
    is_leap_lookup.table <== leap_years;
    is_leap_lookup.idx <== year - 2024;
    signal is_leap <== is_leap_lookup.out;

    component dbm = DaysBeforeMonth();
    dbm.month <== month;
    dbm.year <== year;

    signal SECONDS_PER_DAY <== 60*60*24;
    
    // In the final calculation we subtract one from the day, since we assume the time is zero,
    // there are no seconds that have occured in the day yet, i.e., it's `day` - 1 at midnight.
    signal output out <== year_ts + (dbm.out + day - 1)*SECONDS_PER_DAY;
}

template IsLeap() {
    signal input year;
    
    // For years between 1900 and 2030, is_leap[y] = 1 if y is a leap year
    signal is_leap[131] <== [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0];

    component lookup = Lookup(131);
    lookup.table <== is_leap;
    lookup.idx <== year - 1900;

    signal output out <== lookup.out;
}

template DaysBeforeYear() {
    signal input year;

    // Start with _days_before_year
    // For the years 1900 to 2030 we precompute the days that have happened before this year
    assert(year >= 1900);
    assert(year <= 2030);
    signal days_before_year[131] <== [693595, 693960, 694325, 694690, 695055, 695421, 695786, 696151, 696516, 696882, 697247, 697612, 697977, 698343, 698708, 699073, 699438, 699804, 700169, 700534, 700899, 701265, 701630, 701995, 702360, 702726, 703091, 703456, 703821, 704187, 704552, 704917, 705282, 705648, 706013, 706378, 706743, 707109, 707474, 707839, 708204, 708570, 708935, 709300, 709665, 710031, 710396, 710761, 711126, 711492, 711857, 712222, 712587, 712953, 713318, 713683, 714048, 714414, 714779, 715144, 715509, 715875, 716240, 716605, 716970, 717336, 717701, 718066, 718431, 718797, 719162, 719527, 719892, 720258, 720623, 720988, 721353, 721719, 722084, 722449, 722814, 723180, 723545, 723910, 724275, 724641, 725006, 725371, 725736, 726102, 726467, 726832, 727197, 727563, 727928, 728293, 728658, 729024, 729389, 729754, 730119, 730485, 730850, 731215, 731580, 731946, 732311, 732676, 733041, 733407, 733772, 734137, 734502, 734868, 735233, 735598, 735963, 736329, 736694, 737059, 737424, 737790, 738155, 738520, 738885, 739251, 739616, 739981, 740346, 740712, 741077];

    component lookup_dby = Lookup(131);
    lookup_dby.table <== days_before_year;
    lookup_dby.idx <== year - 1900;

    signal output out <== lookup_dby.out;
}


// Similar to a unix timestamp, but it counts the number of days since January 1, year 0000
template Daystamp() {
    signal input year;
    signal input month;
    signal input day;

    // See https://github.com/python/cpython/blob/54b5e4da8a4c6ae527ab238fcd6b9ba0a3ed0fc7/Lib/datetime.py#L63
    
    component dby = DaysBeforeYear();
    dby.year <== year;

    component dbm = DaysBeforeMonth();
    dbm.year <== year;
    dbm.month <== month;


    signal output out <== dby.out + dbm.out + day;


}
