use crate::model::{Paste, User};
use sqlx::{PgPool, query, query_as};
pub async fn create_user(
    pool: &PgPool,
    username: String,
    email: String,
    password: String,
) -> Result<(), sqlx::Error> {
    let _new_user = query!(
        r#"
        INSERT INTO users (username, email, hashed_password) 
        values ($1, $2, $3) 
        RETURNING id, username, email, hashed_password, created_at
        "#,
        username,
        email,
        password
    )
    .fetch_optional(pool)
    .await?;
    Ok(())
}

pub async fn get_user_by_username(
    pool: &PgPool,
    username: String,
) -> Result<Option<User>, sqlx::Error> {
    query_as!(
        User,
        r#"
            SELECT * FROM users
            WHERE username=$1
        "#,
        username
    )
    .fetch_optional(pool)
    .await
}

pub async fn create_paste(
    pool: &PgPool,
    title: String,
    content: String,
    url: String,
    user_id: i32,
) -> Result<Paste, sqlx::Error> {
    query_as!(
        Paste,
        r#"
        INSERT INTO pastes (title,content,user_id, url)
        VALUES ($1,$2,$3,$4)
        RETURNING id, title, content, user_id, created_at, url
    "#,
        title,
        content,
        user_id,
        url
    )
    .fetch_one(pool)
    .await
}

pub async fn get_paste(pool: &PgPool, url: String) -> Result<Option<Paste>, sqlx::Error> {
    query_as!(
        Paste,
        r#"
    SELECT * FROM pastes
    WHERE url = $1
    "#,
        url
    )
    .fetch_optional(pool)
    .await
}
pub async fn get_user_pastes(pool: &PgPool, username: String) -> Result<Vec<Paste>, sqlx::Error> {
    query_as!(
        Paste,
        r#"
        SELECT * FROM pastes
        WHERE user_id = (
            SELECT id FROM users
            WHERE username = $1
        )
        "#,
        username
    )
    .fetch_all(pool)
    .await
}

pub async fn max_untitled_index(pool: &PgPool, username: String) -> Result<i32, sqlx::Error> {
    struct Temp {
        new_i: Option<i32>,
    }

    let idx = query_as!(
        Temp,
        r#"
        SELECT COALESCE (MAX(ltrim (title, 'New Paste ')::integer),0)+1 as new_i 
        FROM pastes 
        WHERE title like 'New Paste %' and user_id=(
            SELECT id 
            FROM users 
            WHERE username=$1
        )
    "#,
        username
    )
    .fetch_one(pool)
    .await?;
    match idx.new_i {
        Some(i) => Ok(i),
        None => Ok(1),
    }
}
