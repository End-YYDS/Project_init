use actix_web::{web, HttpResponse, Responder};
// use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthCheckRequest {
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthCheckResponse {
    status: String,
}
#[allow(dead_code)]
pub async fn health_check_handler(info: web::Json<HealthCheckRequest>) -> impl Responder {
    if info.message == "health_check" {
        let response = HealthCheckResponse {
            status: "alive".to_string(),
        };
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::BadRequest().body("Invalid request")
    }
}
