// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::Path;
use std::fs;
use std::io;

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_any;

#[cfg(windows)]
use junction;

// TODO: Encode this information in a json config file containing, e.g,. 
//   schema_uid: jwt_corporate_1
//   cred_type : jwt
//   disclosure_ids : [email_domain]Put all the disclosure UIDs and Schema UIDs in a json config file

// define the supported cred schema UIDs. These are an opaque strings that identifies the setup parameters
pub const SCHEMA_UIDS: [&str; 2] = ["jwt_corporate_1", "mdl_1"];

// TODO: this is not quite right; we need to also use the Schema ID. It assumes that all JWTs support the email_domain predicate
// This is needed during show, in the client_helper, to check if we can actually create the proof with the cred we have.
pub fn is_disc_uid_supported(disc_uid : &str, cred_type: &str) -> bool {
    match cred_type {
        "jwt" => {
            matches!(disc_uid, "crescent://email_domain")
        }
        "mdl" => {
            matches!(disc_uid, "crescent://over_18" | "crescent://over_21" | "crescent://over_65")
        }
        _ => false  // unknown cred type
    }
}

pub fn is_disc_supported_by_schema(disc : &str, schema : &str) -> bool {

    matches!( (schema, disc),
        ("jwt_corporate_1", "crescent://email_domain") | 
        ("mdl_1", "crescent://over_18") |
        ("mdl_1", "crescent://over_21") |
        ("mdl_1", "crescent://over_65")
    )
}

pub fn disc_uid_to_age(disc_uid : &str) -> Result<usize, &'static str> {
    match disc_uid {
        "crescent://over_18" => Ok(18),
        "crescent://over_21" => Ok(21),
        "crescent://over_65" => Ok(65),
        _ => Err("disc_uid_to_age: invalid disclosure uid"),
    }
}

pub fn cred_type_from_schema(schema_uid : &str) -> Result<&'static str, &'static str> {
    match schema_uid {
        "jwt_corporate_1" => Ok("jwt"), 
        "mdl_1" => Ok("mdl"),
        _ => Err("cred_type_from_schema: Unknown schema UID"),
    }
}


#[cfg(windows)]
fn symlink_any(src: &Path, dst: &Path) -> io::Result<()> {
    if src.is_file() {
        // Create a 'hard link' as Windows requires admin privileges to create symlinks
        std::fs::hard_link(src, dst)
    } else if src.is_dir() {
        // Trim \\?\ prefix from file paths or junction::create will mangle the prefix creating an invalid junction
        let trimmed_src = Path::new(src.to_str().expect("Invalid UTF-8 in path").trim_start_matches(r"\\?\"));
        let trimmed_dst = Path::new(dst.to_str().expect("Invalid UTF-8 in path").trim_start_matches(r"\\?\"));
        // Create a 'junction' as Windows requires admin privileges to create symlinks
        junction::create(trimmed_src, trimmed_dst)
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
