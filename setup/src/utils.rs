use std::{path::Path, fs};
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use ark_std::{end_timer, start_timer};

// For compression speed benchmarks, see
// https://github.com/djkoloski/rust_serialization_benchmark
// https://github.com/PSeitz/lz4_flex
// https://github.com/facebook/zstd
// LZ4-flex gives us the best CPU speed, and good enough compression, and is pure Rust

const USE_COMPRESSION: bool = true;

pub(crate) fn serialize_into_file<T: serde::Serialize>(label: &str,path: &Path, obj: T) {
    
    let mut ser = bincode::serialize(&obj).unwrap();
    if USE_COMPRESSION {
        ser = compress_prepend_size(&ser);
    }
    println!("{} size: {} bytes", label, ser.len());
    fs::write(path, ser).expect("Failed to write file");   
}

pub(crate) fn deserialize_from_file<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    
    let timer = start_timer!(|| "Reading file ..."); 
    let mut de = fs::read(path).expect("Could not read file");
    end_timer!(timer);
    if USE_COMPRESSION {
        let timer = start_timer!(|| "Decompressing ..."); 
        de = decompress_size_prepended(&de).expect("Failed to decompress");
        end_timer!(timer);
    }
    let timer = start_timer!(|| "Bincode deserializing ..."); 
    let ret = bincode::deserialize(de.as_slice()).expect("Could not deserialize the object");
    end_timer!(timer);

    ret
}
