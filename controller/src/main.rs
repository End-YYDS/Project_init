use actix::clock::sleep;
use actix_rt::spawn as task;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use certificate::{create_decode_key, create_encode_key, create_rsa};
use chrono::{Duration, Utc};
use env_logger::Env;
use healty_checker::client::client;
use jsonwebtoken::{encode, Algorithm, Header};
use log::{error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use signal_checker::{handle_signals, signal_received};
use std::env::var;
use std::fs;
use std::path::Path;
use std::time::Duration as StdDuration;
#[derive(Serialize, Deserialize, Debug)]
struct Command {
    action: String,
    target: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    command: Command,
    exp: usize,
}

#[derive(Serialize, Debug)]
struct SendToken {
    token: String,
}
#[derive(Serialize, Deserialize)]
struct InitialConnection {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct PublicKey {
    name: String,
    key: String,
}

#[derive(Serialize)]
struct JwtResponse {
    token: String,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    key: String,
}

async fn initial_connect(info: web::Json<InitialConnection>) -> impl Responder {
    if info.username == "admin" && info.password == "password" {
        info!("Initial connection successful");

        let expiration = Utc::now() + Duration::hours(1);
        let claims = Claims {
            command: Command {
                action: "initial".to_string(),
                target: "connection".to_string(),
            },
            exp: expiration.timestamp() as usize,
        };
        let header = Header {
            alg: Algorithm::RS256,
            ..Default::default()
        };
        let encoding_key = create_encode_key(var("CARGO_PKG_NAME").unwrap().as_str()).unwrap();
        let token = match encode(&header, &claims, &encoding_key) {
            Ok(t) => t,
            Err(_) => return HttpResponse::InternalServerError().body("Token generation failed"),
        };

        let response = JwtResponse { token };
        HttpResponse::Ok().json(response)
    } else {
        error!("Invalid credentials");
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}

async fn receive_public_key(req: HttpRequest, key_info: web::Json<PublicKey>) -> impl Responder {
    if req.headers().get("Authorization").is_none() {
        return HttpResponse::Unauthorized().body("Missing Authorization header");
    }
    let auth_header = req
        .headers()
        .get("Authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let token = auth_header.trim_start_matches("Bearer ");
    let decoding_key = create_decode_key(var("CARGO_PKG_NAME").unwrap().as_str()).unwrap();
    // let decoding_key = jsonwebtoken::DecodingKey::from_secret("secret".as_ref());
    let validation = jsonwebtoken::Validation::new(Algorithm::RS256);

    match jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation) {
        Ok(_) => {
            // let keys_path = Path::new("keys");
            let keys_path = Path::new(var("CARGO_PKG_NAME").unwrap().as_str()).join("keys");
            if !keys_path.exists() {
                fs::create_dir_all(&keys_path).unwrap();
            }

            let public_key_path = keys_path.join(format!("{}_public_key.pem", key_info.name));
            match fs::write(public_key_path, &key_info.key) {
                Ok(_) => {
                    info!("Public key saved successfully");

                    // 讀取 controller 的 public key
                    let controller_public_key = fs::read_to_string(
                        keys_path
                            .join(format!("{}_public_key.pem", var("CARGO_PKG_NAME").unwrap())),
                    )
                    .unwrap();

                    let response = PublicKeyResponse {
                        key: controller_public_key,
                    };
                    HttpResponse::Ok().json(response)
                }
                Err(e) => {
                    error!("Failed to save public key: {:?}", e);
                    HttpResponse::InternalServerError().body("Failed to save public key")
                }
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid token"),
    }
}

async fn send_command(command: web::Json<Command>) -> impl Responder {
    info!("Received command: {:?}", command);
    let encoding_key = create_encode_key(var("CARGO_PKG_NAME").unwrap().as_str()).unwrap();
    let expiration = Utc::now() + Duration::minutes(10);
    let claims = Claims {
        command: command.into_inner(),
        exp: expiration.timestamp() as usize,
    };

    let header = Header {
        alg: Algorithm::RS256,
        ..Default::default()
    };

    let token = match encode(&header, &claims, &encoding_key) {
        Ok(token) => token,
        Err(e) => {
            error!("Token generation failed: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let sending = SendToken { token };
    let client = Client::new();
    let res = client
        .post("http://localhost:8000/execute")
        .header("Content-Type", "application/json")
        .json(&sending)
        .send()
        .await;

    match res {
        Ok(response) => {
            info!("Command sent successfully");
            HttpResponse::Ok().json(response.text().await.unwrap())
        }
        Err(e) => {
            error!("Failed to send command: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "controller=info,actix_web=info,certificate=info,healty_checker=info,error",
    );
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    info!("Starting controller...");
    create_rsa(var("CARGO_PKG_NAME").unwrap().as_str());
    // info!("{}", var("CARGO_MANIFEST_DIR").unwrap());
    task(async move {
        handle_signals();
    });
    let server = HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/command", web::post().to(send_command))
            .route("/get_health/{ip}", web::get().to(client))
            .route("/initial_connect", web::post().to(initial_connect))
            .route("/receive_public_key", web::post().to(receive_public_key))
    })
    .bind("0.0.0.0:8080")?
    .run();
    let server_handle = server.handle();
    task(async move {
        loop {
            if signal_received() {
                info!("Signal received, shutting down server...");
                server_handle.stop(true).await;
                break;
            }
            sleep(StdDuration::from_secs(1)).await;
        }
    });
    server.await
}
// http://localhost:8080/get_health/127.0.0.1:8000
