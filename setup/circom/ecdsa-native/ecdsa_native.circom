pragma circom 2.0.3;

include "./circom-secp256k1/mul.circom";

template ECDSAVerify() {
  // private inputs: message hash and signature
  // message hash
  signal input h;
    
  // signature
  signal input r;     
  signal input sInv; // TODO: check that s is smaller than the order of secp256k1

  // public inputs: public key
  signal input Px;
  signal input Py;
    
  // generator for secp256k1
  signal Gx <== 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  signal Gy <== 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    
  // check if the public key is on the curve
  // y^2 = x^3 + 7
  signal y2 <== Py * Py;
  signal x2 <== Px * Px;
  signal x3plus7 <== x2 * Px + 7;
  y2 === x3plus7;

  // We need to compute R \gets s * (r*P + h*G) and check R.x =? r
  // We will do this in five steps

  // (1) compute r*P
  component sm1 =  Secp256k1Mul();
  sm1.scalar <== r;
    sm1.xP <== Px;
    sm1.yP <== Py; 
    
  // (2) compute h*G
  component sm2 =  Secp256k1Mul();
  sm2.scalar <== h;
  sm2.xP <== Gx;
  sm2.yP <== Gy; 
    
  // (3) compute h*P + r*G
  component ac = Secp256k1AddComplete();
  ac.xP <== sm1.outX;
  ac.yP <== sm1.outY;
  ac.xQ <== sm2.outX;
  ac.yQ <== sm2.outY;
    
  // (4) compute s * sum
  component sm3 =  Secp256k1Mul();
  sm3.scalar <== sInv;
  sm3.xP <== ac.outX;
  sm3.yP <== ac.outY; 

  // check that R lies on the curve
  signal Rx <== sm3.outX;
  signal Ry <== sm3.outY;
  signal Ry2 <== Ry * Ry;
  signal Rx2 <== Rx * Rx;
  signal Rx3plus7 <== Rx2 * Rx + 7;
  Ry2 === Rx3plus7;

  // (5) check R.x = r
  r === Rx;
}

template ECDSAVerifyTest() {
  // dummy input and constraint
  signal input x;
  x === 1;

  component ecdsaVerify = ECDSAVerify();
  // message hash
  ecdsaVerify.h <== 0x3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F;
  // signature = (r, s_inv)
  ecdsaVerify.r <== 0xA5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089;
  ecdsaVerify.sInv <== 0xd6e6d8e2b519d1955cf6452e05cb89143ea752a222d38f3492b7b51b83625700;
  // public key
  ecdsaVerify.Px <== 0x3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF;
  ecdsaVerify.Py <== 0xE4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A;
}