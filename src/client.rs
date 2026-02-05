use anyhow::{Context, Result};
use dotenv::dotenv;
use reqwest::Certificate;
use serde::Serialize;
use std::{
    env, fs,
    io::{self, Read},
};
mod common;
use crate::common::{LoginRequestBody, RegisterRequestBody};

fn parse_pair(args: &[String]) -> Option<(String, String)> {
    if args.len() <= 1 {
        return None;
    }
    Some((args[0].clone(), args[1].clone()))
}

fn parse_credentials(mut args: &[String]) -> Option<(String, String)> {
    let mut name: String = String::default();
    let mut pass: String = String::default();

    while args.len() >= 2 {
        if let Some((key, value)) = parse_pair(args) {
            match key.as_str() {
                "--name" => {
                    name = value;
                }
                "--password" => {
                    pass = value;
                }
                &_ => {
                    return None;
                }
            }
        } else {
            return None;
        }
        args = &args[2..];
    }
    if !args.is_empty() {
        return None;
    }
    if name == String::default() || pass == String::default() {
        return None;
    }
    Some((name, pass))
}

fn parse_register_fields(mut args: &[String]) -> Option<(String, String, String)> {
    let mut email = String::from("");
    let mut name: String = String::from("");
    let mut pass: String = String::from("");

    while args.len() >= 2 {
        if let Some((key, value)) = parse_pair(args) {
            match key.as_str() {
                "--name" => {
                    name = value;
                }
                "--email" => {
                    email = value;
                }
                "--password" => {
                    pass = value;
                }
                &_ => {
                    return None;
                }
            }
        } else {
            return None;
        }
        args = &args[2..];
    }
    if !args.is_empty() {
        return None;
    }
    if name == String::default() || pass == String::default() || email == String::default() {
        return None;
    }
    Some((name, email, pass))
}

#[derive(Serialize)]
struct PasteRequest {
    jwt: String,
    content: String,
}

fn main() -> Result<()> {
    dotenv().ok();
    let server_url = format!(
        "https://{}:3000",
        env::var("SERVER_IP").context("SERVER_IP env variable is not set")?
    );
    let args: Vec<String> = env::args().collect();

    let raw_cert = fs::read("cert.pem").context("Failed to load the certificate")?;
    let certificate =
        Certificate::from_pem(&raw_cert).context("Failed to parse the certificate")?;

    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(certificate)
        .use_rustls_tls()
        .build()
        .context("Failed to build the client")?;

    if args.len() == 1 {
        if let Ok(jwt) = fs::read_to_string(".token.b64") {
            let mut content = String::new();
            io::stdin()
                .read_to_string(&mut content)
                .context("Error reading command output")?;
            let req = PasteRequest { jwt, content };

            let res = client
                .post(format!("{}/api/paste", server_url))
                .json(&req)
                .send()?;

            if res.status().is_success() {
                println!("{}/paste/{}", server_url, res.text()?);
            } else {
                let st = res.status();
                let err = res.text()?;
                println!("Eroare: {} {}", st, err);
            }
        } else {
            println!("Trebuie sa fiti autentificat pentru a crea un paste");
        }
    } else {
        match args[1].as_str() {
            "login" => {
                // println!("Ne LOGAM...");
                if let Some((name, password)) = parse_credentials(&args[2..]) {
                    let credentials = LoginRequestBody {
                        username: name,
                        password,
                        client: String::from("cli"),
                    };

                    let res = client
                        .post(format!("{}/api/login", server_url))
                        .json(&credentials)
                        .send()?;

                    if res.status().is_success() {
                        let jwt = res.text()?;
                        fs::write(".token.b64", jwt)?;
                        println!("You are now logged in successfully!");
                    } else {
                        let st = res.status();
                        let err = res.text()?;
                        println!("Eroare: {} {}", st, err);
                    }
                } else {
                    println!("Usage: tpaste login --name <name> --password <password>");
                }
            }
            "register" => {
                if let Some((name, email, password)) = parse_register_fields(&args[2..]) {
                    let credentials = RegisterRequestBody {
                        username: name,
                        email,
                        password,
                    };

                    let res = client
                        .post(format!("{}/api/register", server_url))
                        .json(&credentials)
                        .send()?;

                    if res.status().is_success() {
                        println!("Account created successfully!");
                    } else {
                        let st = res.status();
                        let err = res.text()?;
                        println!("Eroare: {} {}", st, err);
                    }
                } else {
                    println!(
                        "Usage: tpaste register --name <name> --email <email> --password <password>"
                    );
                }
            }
            "logout" => {
                match fs::remove_file(".token.b64") {
                    Ok(()) => println!("Logout successful!"),
                    Err(_) => println!("Eroare la stergerea fisierului .token.b64"),
                }
                //sterg fisierul
            }
            "help" => {
                println!("----Welcome to tpaste----");
                println!("The available commands are:");
                println!("tpaste login --name <name> --password <password>");
                println!("tpaste register --name <name> --email <email> --password <password>");
                println!("To create a paste you just have to pipe a command's output into tpaste");
                println!("-------------------------");
            }
            &_ => {
                println!("Comanda necunoscuta");
            }
        }
    }
    Ok(())
}
