use chrono::NaiveDateTime;
use serde::Deserialize;
#[derive(Deserialize, Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub hashed_password: String,
    pub created_at: NaiveDateTime,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Paste {
    pub id: i32,
    pub title: String,
    pub content: String,
    pub user_id: i32,
    pub url: String,
    pub created_at: NaiveDateTime,
}
