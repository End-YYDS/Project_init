use jsonwebtoken::{DecodingKey, EncodingKey};
use log::{error, info};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn create_rsa(name: &str) {
    let certificate_path = Path::new(name).join("keys");
    // let temp = name.to_owned();
    // let certificate_path = Path::new(temp.push_str(String::from("/keys").as_str()).as_str());
    if !certificate_path.exists() {
        fs::create_dir_all(&certificate_path).unwrap();

        let rsa = Rsa::generate(4096).unwrap();
        let private_key = PKey::from_rsa(rsa).unwrap();
        let private_key_pem = private_key.private_key_to_pem_pkcs8().unwrap();
        let public_key_pem = private_key.public_key_to_pem().unwrap();
        let mut private_key_file =
            fs::File::create(certificate_path.join(format!("{}_private_key.pem", name))).unwrap();
        private_key_file.write_all(&private_key_pem).unwrap();
        let mut public_key_file =
            fs::File::create(certificate_path.join(format!("{}_public_key.pem", name))).unwrap();
        public_key_file.write_all(&public_key_pem).unwrap();

        info!("Keys have been generated and saved in the 'keys' directory.");
    } else {
        info!("Keys already exist in the 'keys' directory.");
    }
}
pub fn create_encode_key(name: &str) -> Result<EncodingKey, Box<dyn std::error::Error>> {
    // let certificate_path = Path::new("keys");
    let certificate_path = Path::new(name).join("keys");
    let private_key =
        match fs::read_to_string(certificate_path.join(format!("{}_private_key.pem", name))) {
            Ok(key) => key,
            Err(e) => {
                error!("Cannot read private key: {:?}", e);
                return Err(Box::new(e));
            }
        };
    // print!("private_key: {:#?}", private_key);
    let encoding_key = match EncodingKey::from_rsa_pem(private_key.as_bytes()) {
        Ok(key) => key,
        Err(e) => {
            error!("Invalid private key: {:#?}", e);
            return Err(Box::new(e));
        }
    };
    Ok(encoding_key)
}
pub fn create_decode_key(name: &str) -> Result<DecodingKey, Box<dyn std::error::Error>> {
    // let certificate_path = Path::new("keys");
    let certificate_path = Path::new(name).join("keys");
    let public_key =
        match fs::read_to_string(certificate_path.join(format!("{}_public_key.pem", name))) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to read public key: {:?}", e);
                return Err(Box::new(e));
            }
        };

    let decoding_key = match DecodingKey::from_rsa_pem(public_key.as_bytes()) {
        Ok(key) => key,
        Err(e) => {
            error!("Invalid public key: {:?}", e);
            return Err(Box::new(e));
        }
    };
    Ok(decoding_key)
}
