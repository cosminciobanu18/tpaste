use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::SET_COOKIE, request::Parts},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::{TypedHeader, headers::Cookie};
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use rustls::crypto::ring;
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, net::SocketAddr};
use tracing_subscriber::fmt;

mod db;
use crate::{
    db::{
        create_paste, create_user, get_paste, get_user_by_username, get_user_pastes,
        max_untitled_index,
    },
    helpers::{check_password, generate_jwt, hash_password, validate_jwt},
};
mod helpers;
use crate::helpers::generate_random_url;
use tpaste_shared::{LoginRequestBody, RegisterRequestBody};
mod model;
mod template;

pub struct AuthUser {
    username: Option<String>,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = StatusCode;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let guest = AuthUser { username: None };
        if let Ok(TypedHeader(cookies)) =
            TypedHeader::<Cookie>::from_request_parts(parts, state).await
        {
            if let Some(token) = cookies.get("jwt_token") {
                match validate_jwt(String::from(token), state.secret.clone()) {
                    Ok(claims) => Ok(AuthUser {
                        username: Some(claims.username),
                    }),
                    Err(_) => Ok(guest),
                }
            } else {
                Ok(guest)
            }
        } else {
            Ok(guest)
        }
    }
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    secret: Vec<u8>,
}

async fn index_page(AuthUser { username }: AuthUser) -> impl IntoResponse {
    template::HtmlTemplate(template::IndexTemplate { username })
}

async fn login_page(AuthUser { username }: AuthUser) -> impl IntoResponse {
    template::HtmlTemplate(template::LoginTemplate { username })
}

async fn register_page(AuthUser { username }: AuthUser) -> impl IntoResponse {
    template::HtmlTemplate(template::RegisterTemplate { username })
}

async fn paste_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AuthUser { username }: AuthUser,
) -> impl IntoResponse {
    match get_paste(&state.pool, id).await {
        Ok(optional_paste) => match optional_paste {
            Some(p) => template::HtmlTemplate(template::PasteTemplate {
                username,
                title: p.title,
                content: p.content,
                created_at: p.created_at.format("%d-%m-%Y %H:%M").to_string(),
                error: None,
            }),
            None => template::HtmlTemplate(template::PasteTemplate {
                username,
                title: String::new(),
                content: String::new(),
                created_at: String::new(),
                error: Some(String::from("The paste does not exist")),
            }),
        },
        Err(e) => {
            println!("Eroare la obtinerea unui paste: {e:?}");
            template::HtmlTemplate(template::PasteTemplate {
                username,
                title: String::new(),
                content: String::new(),
                created_at: String::new(),
                error: Some(String::from("Internal Server Error")),
            })
        }
    }
}

async fn profile_page(
    State(state): State<AppState>,
    Path(user): Path<String>,
    AuthUser { username }: AuthUser,
) -> impl IntoResponse {
    if username != Some(user.clone()) {
        template::HtmlTemplate(template::ProfileTemplate {
            username,
            pastes: Vec::new(),
            error: Some(String::from("You are not allowed to see this page!")),
        })
    } else {
        match get_user_pastes(&state.pool, user.clone()).await {
            Ok(pastes) => template::HtmlTemplate(template::ProfileTemplate {
                username,
                pastes,
                error: None,
            }),
            Err(e) => {
                println!("Eroare la obtinerea paste-urilor unui user: {e:?}");
                template::HtmlTemplate(template::ProfileTemplate {
                    username,
                    pastes: Vec::new(),
                    error: Some(String::from("Internal server error")),
                })
            }
        }
    }
}

async fn handle_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequestBody>,
) -> impl IntoResponse {
    if let Ok(res) = db::get_user_by_username(&state.pool, payload.username.clone()).await {
        if let Some(user) = res {
            if check_password(user.hashed_password, payload.password) {
                println!("User autentificat cu success");

                let jwt = generate_jwt(
                    payload.username.clone(),
                    payload.client.clone(),
                    state.secret,
                );

                if payload.client == "browser" {
                    let mut headers = HeaderMap::new();

                    let cookie = format!("jwt_token={}; Path=/; HttpOnly; Max-Age=5184000", jwt);
                    if let Ok(value) = HeaderValue::from_str(&cookie) {
                        headers.insert(SET_COOKIE, value);
                    }
                    return (headers, StatusCode::OK).into_response();
                } else {
                    return (StatusCode::OK, jwt).into_response();
                }
            } else {
                println!("Parola gresita!");
                return (StatusCode::UNAUTHORIZED).into_response();
            }
        } else {
            return (StatusCode::NOT_FOUND).into_response();
        }
    }
    (StatusCode::INTERNAL_SERVER_ERROR).into_response()
}

async fn handle_register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequestBody>,
) -> impl IntoResponse {
    if body.username.is_empty() || body.password.is_empty() || body.email.is_empty() {
        return (StatusCode::BAD_REQUEST).into_response();
    }
    match create_user(
        &state.pool,
        body.username,
        body.email,
        match hash_password(body.password) {
            Ok(pass) => pass,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
        },
    )
    .await
    {
        Ok(()) => {
            println!("S-a creat un user nou");
            (StatusCode::CREATED).into_response()
        }
        Err(e) => {
            println!("Eroare interna la creare user: {e:?}");
            (StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreatePasteBody {
    content: String,
    jwt: String,
}
async fn handle_create_paste(
    State(state): State<AppState>,
    Json(body): Json<CreatePasteBody>,
) -> impl IntoResponse {
    match validate_jwt(body.jwt, state.secret) {
        Err(_) => (StatusCode::UNAUTHORIZED).into_response(),
        Ok(claims) => {
            if let Ok(optional_user) =
                get_user_by_username(&state.pool, claims.username.clone()).await
            {
                if let Some(user) = optional_user {
                    let url = generate_random_url();
                    let mut title = String::from("New Paste ");
                    match max_untitled_index(&state.pool, claims.username).await {
                        Ok(number) => {
                            title.push_str(number.to_string().as_str());
                        }
                        Err(e) => {
                            println!("Eroare cautare index minim: {e:?}");
                            return (StatusCode::INTERNAL_SERVER_ERROR).into_response();
                        }
                    }
                    match create_paste(&state.pool, title, body.content, url, user.id).await {
                        Ok(new_paste) => {
                            return (StatusCode::CREATED, new_paste.url).into_response();
                        }
                        Err(e) => {
                            println!("Eroare creare paste: {e:?}");
                            return (StatusCode::INTERNAL_SERVER_ERROR).into_response();
                        }
                    }
                } else {
                    return (StatusCode::UNAUTHORIZED).into_response();
                }
            }
            (StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

async fn handler_logout() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_static("jwt_token=; Path=/; HttpOnly; Max-Age=0"),
    );
    (headers, Redirect::to("/"))
}
#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let jwt_secret = env::var("JWT_SECRET")
        .context("JWT_SECRET is not set")?
        .into_bytes();

    let database_url = env::var("DATABASE_URL").context("DATABASE_URI is not set")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to create the pool")?;

    println!("Connected to the database!");

    fmt::init();

    let state = AppState {
        pool,
        secret: jwt_secret,
    };

    let app = Router::new()
        .route("/", get(index_page))
        .route("/login", get(login_page))
        .route("/register", get(register_page))
        .route("/paste/{id}", get(paste_page))
        .route("/profile/{username}", get(profile_page))
        .route("/api/login", post(handle_login))
        .route("/api/register", post(handle_register))
        .route("/logout", post(handler_logout))
        .route("/api/paste", post(handle_create_paste))
        .with_state(state);

    let config = RustlsConfig::from_pem_file("cert.pem", "pv_key.pem")
        .await
        .context("Failed to load TLS certificate!")?;

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("HTTPS Server is listening on port 3000!");

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .context("Axum server down")?;

    Ok(())
}
