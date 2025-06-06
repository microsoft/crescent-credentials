/// @function log2Ceil
/// @notice Calculate log2 of a number and round it up
/// @param a The input value
/// @return The result of the log2Ceil
/// source: https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/utils/functions.circom
function log2Ceil(a) {
    var n = a - 1;
    var r = 0;

    while (n > 0) {
        r++;
        n \= 2;
    }

    return r;
}