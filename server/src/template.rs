use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub username: Option<String>,
}

#[derive(Template)]
#[template(path = "paste.html")]
pub struct PasteTemplate {
    pub username: Option<String>,
    pub title: String,
    pub content: String,
    pub created_at: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub username: Option<String>,
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub username: Option<String>,
}

use crate::model::Paste;
#[derive(Template)]
#[template(path = "profile.html")]
pub struct ProfileTemplate {
    pub username: Option<String>,
    pub pastes: Vec<Paste>,
    pub error: Option<String>,
}

pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template...{}", e),
            )
                .into_response(),
        }
    }
}
