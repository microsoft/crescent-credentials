//! This module implements hash to curve for t256
use super::{Config, Projective};
use ark_ec::hashing::curve_maps::swu::{SWUMap, SWUConfig};
// use ark_ec::{
//     short_weierstrass::{self as sw, SWCurveConfig},
// };
use super::{fq::Fq};
// use ark_ec::hashing::curve_maps::swu::SWUConfig; 
use ark_ec::hashing::{map_to_curve_hasher::{MapToCurveBasedHasher}, 
                    HashToCurve};
use ark_ff::field_hashers::DefaultFieldHasher;
use sha2::Sha256;
use ark_ff::MontFp;
// use ark_ec::{
//     models::CurveConfig,
//     short_weierstrass::{self as sw, SWCurveConfig},
// };


impl SWUConfig for Config {
    /// Define parameters for hash to curve as needed in https://github.com/arkworks-rs/algebra/blob/fc3f6614b4b1aa4303a0204daece19679bea04c5/ec/src/hashing/curve_maps/swu.rs
    const ZETA: Fq = MontFp!("115792089210356248762697446949407573530594504085698471288169790229257723883798"); // -1
}

/// Create a hasher for hash to curve
pub fn create_curvebased_hasher(domain: &[u8]) -> MapToCurveBasedHasher::<
                                        Projective, 
                                        DefaultFieldHasher<Sha256, 128>, 
                                        SWUMap<Config>
                                    > 
{
    let hasher = MapToCurveBasedHasher::<
                    Projective, 
                    DefaultFieldHasher<Sha256, 128>, 
                    SWUMap<Config>
                >::new(domain).unwrap();
    hasher
}