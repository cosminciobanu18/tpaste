use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;
use tpaste_shared::Claims;
pub fn generate_random_url() -> String {
    let chars: &[u8] = b"0987654321mnbvcxzasdfghjklpoiuytrewqMNBVCXZASDFGHJKLPOIUYTREWQ";
    let mut rng = rand::rng();
    let mut url = String::new();
    for _ in 0..12 {
        let i = rng.random_range(0..62) as usize;
        url.push(chars[i] as char);
    }
    url
}

pub fn generate_jwt(username: String, client: String, secret: Vec<u8>) -> String {
    let expiration = match Utc::now().checked_add_signed(Duration::days(60)) {
        Some(time) => time.timestamp() as usize,
        None => 0_usize,
    };

    let claims = Claims {
        username,
        client,
        iat: Utc::now().timestamp() as usize,
        exp: expiration,
    };

    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    ) {
        Ok(jwt) => jwt,
        Err(e) => {
            println!("Eroare encode: {e:?}",);
            String::from("")
        }
    }
}

pub fn validate_jwt(jwt: String, secret: Vec<u8>) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::default();

    let token_data = decode::<Claims>(jwt, &DecodingKey::from_secret(&secret), &validation)?;
    Ok(token_data.claims)
}

pub fn hash_password(pass: String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    Ok(argon2.hash_password(pass.as_bytes(), &salt)?.to_string())
}

pub fn check_password(hashed_password: String, plain_password: String) -> bool {
    let parsed_hash = match PasswordHash::new(hashed_password.as_str()) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let argon2 = Argon2::default();
    argon2
        .verify_password(plain_password.as_bytes(), &parsed_hash)
        .is_ok()
}
