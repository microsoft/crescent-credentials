// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::Path;
use std::fs;
use std::io;

// TODO: Encode this information in a json config file containing, e.g,. 
//   schema_uid: jwt_corporate_1
//   cred_type : jwt
//   disclosure_ids : [email_domain]Put all the disclosure UIDs and Schema UIDs in a json config file


// define the supported cred schema UIDs. These are an opaque strings that identifies the setup parameters
pub const SCHEMA_UIDS: [&str; 2] = ["jwt_corporate_1", "mdl_1"];

// TODO: this is not quite right; we need to also use the Schema ID. It assumes that all JWTs support the email_domain predicate
// This is needed during show, in the client_helper, to check if we can actually create the proof with the cred we have.
pub fn is_disc_uid_supported(disc_uid : &String, cred_type: &String) -> bool {
    match cred_type.as_str() {
        "jwt" => {
            match disc_uid.as_str() {
                "crescent://email_domain" => true,
                _ => false,
            }
        }
        "mdl" => {
            match disc_uid.as_str() {
                "crescent://over_18" => true,
                "crescent://over_21" => true,
                "crescent://over_65" => true,
                _ => false,
            }
        }
        _ => false  // unknown cred type
    }
}

pub fn is_disc_supported_by_schema(disc : &String, schema : &String) -> bool {
    match (schema.as_str(), disc.as_str()) {
        ("jwt_corporate_1", "crescent://email_domain") => true,
        ("mdl_1", "crescent://over_18") => true,
        ("mdl_1", "crescent://over_21") => true,
        ("mdl_1", "crescent://over_65") => true,
        _ => false
    }
}

pub fn disc_uid_to_age(disc_uid : &String) -> Result<usize, &'static str> {

    match disc_uid.as_str() {
        "crescent://over_18" => Ok(18),
        "crescent://over_21" => Ok(21),
        "crescent://over_65" => Ok(65),
        _ => Err("disc_uid_to_age: invalid disclosure uid"),
    }
}


pub fn cred_type_from_schema(schema_uid : &String) -> Result<&'static str, &'static str> {
    match schema_uid.as_str() {
        "jwt_corporate_1" => Ok("jwt"), 
        "mdl_1" => Ok("mdl"),
        _ => Err("cred_type_from_schema: Unknown schema UID"),
    }
}

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_any;

#[cfg(windows)]
fn symlink_any(src: &Path, dst: &Path) -> io::Result<()> {
    if src.is_file() {
        std::os::windows::fs::symlink_file(src, dst)
    } else if src.is_dir() {
        std::os::windows::fs::symlink_dir(src, dst)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Source path is neither file nor directory"))
    }
}

// copies the contents of the shared folder to the target folder using symlinks
pub fn copy_with_symlinks(shared_folder: &Path, target_folder: &Path) -> io::Result<()> {
    // Ensure the target folder exists
    fs::create_dir_all(target_folder)?;

    for entry in fs::read_dir(shared_folder)? {
        let entry = entry?;
        let entry_path = entry.path();
        let abs_entry_path = entry_path.canonicalize()?;
        let target_path = target_folder.join(entry.file_name());

        // Create symlink from absolute source path to target path
        symlink_any(&abs_entry_path, &target_path)?;
    }

    Ok(())
}
