use actix_web::{web, HttpResponse, Responder};
use log::{error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthCheckRequest {
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthCheckResponse {
    status: String,
}

#[allow(dead_code)]
pub async fn client(
    ip: web::Path<(String,)>,
) -> Result<impl Responder, Box<dyn std::error::Error>> {
    let client = Client::new();
    info!("Client: {:?}", &ip);
    let server_addr = format!("http://{}/health_check", ip.0);

    let request = HealthCheckRequest {
        message: "health_check".to_string(),
    };

    let response = client
        .post(server_addr)
        .json(&request)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    if response.status().is_success() {
        let response_json: HealthCheckResponse = response.json().await?;
        info!("Received: {:?}", &response_json);
        Ok(HttpResponse::Ok().json(response_json.status))
    } else {
        error!("Health check failed with status: {}", response.status());
        Ok(HttpResponse::InternalServerError().finish())
    }
}
