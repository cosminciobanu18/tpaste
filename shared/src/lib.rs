use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct Claims {
    pub username: String,
    pub iat: usize,
    pub exp: usize,
    pub client: String,
}

#[derive(Deserialize, Serialize)]
pub struct LoginRequestBody {
    pub username: String,
    pub password: String,
    pub client: String,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterRequestBody {
    pub username: String,
    pub email: String,
    pub password: String,
}
