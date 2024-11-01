// TODO: Put all the disclosure UIDs and Schema UIDs in a json config file


// define the supported cred schema UIDs. These are an opaque strings that identifies the setup parameters
pub const SCHEMA_UIDS: [&str; 2] = ["jwt_corporate_1", "mdl_1"];

// TODO: this is not quite right; we need to also use the Schema ID. It assumes that all JWTs support the email_domain predicate
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

pub fn cred_type_from_disc_uid(disc_uid: &String) -> Result<&'static str, &'static str> {
    match disc_uid.as_str() {
        "crescent://over_18" => Ok("mdl"),
        "crescent://over_21" => Ok("mdl"),
        "crescent://over_65" => Ok("mdl"),
        "crescent://email_domain" => Ok("jwt"),
        _ => Err("cred_type_from_disc_uid: Unknown disclosure UID"),
    }
}