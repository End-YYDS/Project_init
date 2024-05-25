use actix_web::error::ResponseError;
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::{web, App, Error, HttpResponse, HttpServer};
use certificate::{create_decode_key, create_rsa};
use env_logger::{self, Env};
use healty_checker::server::health_check_handler;
use jsonwebtoken::{decode, Algorithm, Validation};
use log::{error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env::var;
use std::path::Path;
use std::{fmt, fs};

#[derive(Serialize, Deserialize, Debug)]
struct ExecuteCommand {
    action: String,
    target: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Claims {
    command: ExecuteCommand,
    exp: usize,
}

#[derive(Deserialize, Debug)]
struct CommandWithToken {
    token: String,
}
#[derive(Debug)]
struct JwtValidationError;

impl fmt::Display for JwtValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JWT validation error")
    }
}

impl ResponseError for JwtValidationError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Unauthorized().json("Invalid token")
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }
}

async fn execute_command(cmd: web::Json<CommandWithToken>) -> Result<HttpResponse, Error> {
    info!("Received command with token: {:?}", cmd);
    let decoding_key = create_decode_key("controller").unwrap();

    let token_data = match decode::<Claims>(
        &cmd.token,
        &decoding_key,
        &Validation::new(Algorithm::RS256),
    ) {
        Ok(data) => data,
        Err(e) => {
            error!("JWT validation error: {:?}", e);
            return Err(JwtValidationError.into());
        }
    };

    info!("Decoded token data: {:?}", token_data.claims);
    Ok(HttpResponse::Ok().body("Command Execute success!!"))
}
#[derive(Serialize)]
struct InitialConnection {
    username: String,
    password: String,
}

#[derive(Serialize, Debug)]
struct PublicKey {
    name: String,
    key: String,
}

#[derive(Deserialize)]
struct JwtResponse {
    token: String,
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    key: String,
}
#[derive(Debug)]
struct InitialConnectError {
    message: String,
}

impl InitialConnectError {
    fn new(msg: &str) -> InitialConnectError {
        InitialConnectError {
            message: msg.to_string(),
        }
    }
}

impl fmt::Display for InitialConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<reqwest::Error> for InitialConnectError {
    fn from(error: reqwest::Error) -> Self {
        InitialConnectError::new(&format!("Initial connection error: {}", error))
    }
}

async fn initial_connect() -> Result<String, InitialConnectError> {
    let client = Client::new();
    let initial_info = InitialConnection {
        username: "admin".to_string(),
        password: "password".to_string(),
    };

    let res = client
        .post("http://localhost:8080/initial_connect")
        .json(&initial_info)
        .send()
        .await?;

    if res.status().is_success() {
        let jwt_response: JwtResponse = res.json().await?;
        info!("Initial connection to controller successful");
        Ok(jwt_response.token)
    } else {
        error!("Initial connection to controller failed");
        Err(InitialConnectError::new("Initial connection failed"))
    }
}

async fn exchange_keys(token: &str) -> Result<(), InitialConnectError> {
    let client = Client::new();
    let key_path = Path::new(var("CARGO_PKG_NAME").unwrap().as_str()).join("keys");
    let public_key = fs::read_to_string(key_path.join(format!(
        "{}_public_key.pem",
        var("CARGO_PKG_NAME").unwrap().as_str()
    )))
    .unwrap();
    let key_info = PublicKey {
        name: var("CARGO_PKG_NAME").unwrap(),
        key: public_key,
    };
    let res = client
        .post("http://localhost:8080/receive_public_key")
        .bearer_auth(token)
        .json(&key_info)
        .send()
        .await?;
    if res.status().is_success() {
        let public_key_response: PublicKeyResponse = res.json().await?;
        info!("Public key sent to controller successfully");
        if !key_path.exists() {
            fs::create_dir_all(&key_path).unwrap();
        }

        let controller_public_key_path = key_path.join("controller_public_key.pem");
        fs::write(controller_public_key_path, public_key_response.key).unwrap();
        info!("Controller public key saved successfully");
    } else {
        error!("Failed to send public key to controller");
        return Err(InitialConnectError::new("Initial exchange failed"));
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "agent=info,actix_web=info");
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    info!("Starting agent...");
    create_rsa(var("CARGO_PKG_NAME").unwrap().as_str());
    if !Path::new(var("CARGO_PKG_NAME").unwrap().as_str())
        .join("keys")
        .join(format!("{}_public_key.pem", "controller"))
        .exists()
    {
        let token = match initial_connect().await {
            Ok(token) => token,
            Err(e) => {
                error!("Failed to connect to controller: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to connect to controller",
                ));
            }
        };
        match exchange_keys(&token).await {
            Ok(_) => info!("Key exchange successful"),
            Err(e) => {
                error!("Key exchange failed: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Key exchange failed: {}", e),
                ));
            }
        }
    }
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/execute", web::post().to(execute_command))
            .route("/health_check", web::post().to(health_check_handler))
    })
    .bind("0.0.0.0:8000")?
    .run()
    .await
}
