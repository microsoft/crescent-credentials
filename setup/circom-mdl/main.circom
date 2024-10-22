pragma circom 2.1.6;

include "./ecdsa-p256/ecdsa.circom";
include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/gates.circom";
include "./ecdsa-p256/sha256.circom";
include "./strings.circom";
//include "./match_claim.circom";
//include "./predicates.circom";

template Main(max_msg_bytes, max_json_bytes, field_byte_len, n, k) {

    signal input message[max_msg_bytes]; 
    signal input signature_r[k]; 
    signal input signature_s[k];
    signal input pubkey_x[k];
    signal input pubkey_y[k];
    signal input message_padded_bytes; // length of the message including the padding
    
    // *********** hash the padded message ***********
    log("start hashing");
    component sha = Sha256Bytes(max_msg_bytes);
    sha.in_len_padded_bytes <== message_padded_bytes;
    for (var i = 0; i < max_msg_bytes; i++) {
        sha.in_padded[i] <== message[i];
    }   

    signal digest[256];
    digest <== sha.out;
    
    log("convert digest to int");
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

    signal msg_hash[msg_len];
    for(var i = 0; i < msg_len; i++) {
        msg_hash[i] <== base_msg[i].out;
    }

    // *********** verify signature for the message ***********
    log("Calling ecdsa sig ver");
    component ecdsa = ECDSAVerifyNoPubkeyCheck(n,k);
    for (var i = 0; i < msg_len; i++) {
        ecdsa.msghash[i] <== msg_hash[i];
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
    log("Result from ecdsa verify component: ", ecdsa.result);
    ecdsa.result === 1;

    // #################### Prove validUntil date ####################
    signal valid_until_prefix[13] <== [106, 118, 97, 108, 105, 100, 85, 110, 116, 105, 108, 192, 116];
    signal input valid_until_prefix_l;
    signal input valid_until_prefix_r;
    signal input valid_until_value;    // TODO: extract from message, using MatchClaim component?

    // First we make sure that valid_until_prefix appears in message[l:r]
    component prefix_indicator = IntervalIndicator(max_msg_bytes);
    prefix_indicator.l <== valid_until_prefix_l;
    prefix_indicator.r <== valid_until_prefix_r;

    component match_prefix = MatchSubstring(max_msg_bytes, 13, 13);
    match_prefix.msg <== message;
    match_prefix.substr <== valid_until_prefix;
    match_prefix.range_indicator <== prefix_indicator.indicator;
    match_prefix.l <== valid_until_prefix_l;
    match_prefix.r <== valid_until_prefix_r;

    // Next we get the timestamp from the following twenty bytes

    // Use a prover-only function to compute the bytes
    var timestamp_len = 20;
    signal valid_until_bytes[timestamp_len];
    component value_indicator = IntervalIndicator(max_msg_bytes);
    value_indicator.l <== valid_until_prefix_l + 13;
    value_indicator.r <== value_indicator.l + timestamp_len;

    var tmp;
    log("Bytes of timestamp:");
    for (var i = 0; i < timestamp_len; i++) {
        var c = 0;
        for (var j = i; j < max_msg_bytes; j++) {
            tmp = value_indicator.start_indicator[j - i] * value_indicator.indicator[j];
            c +=  tmp * message[j];
        }
        valid_until_bytes[i] <-- c;
        log(c);
    }
    // Use MatchSubstring to *prove* these valid_until_bytes are found following the prefix
    component match_value = MatchSubstring(max_msg_bytes, timestamp_len, timestamp_len);
    match_value.msg <== message;
    match_value.substr <== valid_until_bytes;
    match_value.range_indicator <== value_indicator.indicator;
    match_value.l <== value_indicator.l;
    match_value.r <== value_indicator.r;

    // Parse out the year, month and day from the timestamp (ISO 8061 format, e.g., 2027-01-02T00:00:00Z )
    signal d[timestamp_len] <== valid_until_bytes;
    signal year <== (d[0]-48)*1000 + (d[1]-48)*100 + (d[2]-48)*10 + (d[3]-48);
    signal month <== (d[5]-48)*10 + (d[6]-48); 
    signal day <== (d[8]-48)*10 + (d[9]-48);

    log("validUntil date: ", year,"-",month,"-",day);

    component ts = UnixTimestamp();
    ts.year <== year;
    ts.month <== month;
    ts.day <== day;
    log("ts.output = ", ts.out);
    
    ts.out === valid_until_value;    // Constrain the input to the value extracted from the cred
    
    // #################### Prove birth_date ####################
    var dob_preimage_len = 128;
    signal input dob_value;         // integer, days since year 0000
    signal input dob_id;            // the number of the birth_date claim 
    signal input dob_preimage[dob_preimage_len];    // Version of dob_value that is encoded with random salt. 
                                                    // It's OK to hardcode the length since birth_date is fixed-length
    signal input dob_encoded_l;     // Theposition in the cred where the hashed dob occurs
    signal input dob_encoded_r;

    
    component sha_bytes = Sha256Bytes(dob_preimage_len);
    sha_bytes.in_padded <== dob_preimage;
    sha_bytes.in_len_padded_bytes <== 128;

    // Convert digest to bytes, ensure it's present in the cred, encoded with dob_id as:
    //   "{:02x}{}{}".format(as_byte(dob_id), "5820", as_bytes(digest))

    component hash_bytes = DigestToBytes();
    hash_bytes.in <== sha_bytes.out;

    signal encoded_dob_digest[35];
    encoded_dob_digest[0] <== dob_id;
    encoded_dob_digest[1] <== 88;   // == 58h
    encoded_dob_digest[2] <== 32;   // == 20h
    for(var i = 0; i < 32; i++ ) {
        encoded_dob_digest[i + 3] <== hash_bytes.out[i];
    }

    component dob_indicator = IntervalIndicator(max_msg_bytes);
    dob_indicator.l <== dob_encoded_l;
    dob_indicator.r <== dob_encoded_r;

    component match_dob = MatchSubstring(max_msg_bytes, 35, 31);
    match_dob.msg <== message;
    match_dob.substr <== encoded_dob_digest;
    match_dob.range_indicator <== dob_indicator.indicator;
    match_dob.l <== dob_indicator.l;
    match_dob.r <== dob_indicator.r;

    // Now we've confirmed that dob_preimage is authenticated: parse out the YYYY-MM-DD 
    // and confirm it equals dob_value

    signal a[dob_preimage_len] <== dob_preimage;
    // last 10 characters are 'YYYY-MM-DD', 32 bytes of SHA padding, so year 
    // starts at position 85 = 127 - 32 - 10
    signal dob_year <== (a[85]-48)*1000 + (a[86]-48)*100 + (a[87]-48)*10 + (a[88]-48);
    signal dob_month <== (a[90]-48)*10 + (a[91]-48); 
    signal dob_day <== (a[93]-48)*10 + (a[94]-48);
    log("birth_date: ", dob_year,"-",dob_month,"-",dob_day);

    // Convert y-m-d to "daystamp" (number of days since year 0)
    component ds = Daystamp();
    ds.year <== dob_year;
    ds.month <== dob_month;
    ds.day <== dob_day;

    log("ds.out =", ds.out);
    ds.out === dob_value;

}

component main { public [pubkey_x, pubkey_y, valid_until_value, dob_value] } = Main(1152, 1152, 31, 43, 6);
