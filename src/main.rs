use actix_web::http::header::{HeaderMap, CONTENT_TYPE};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use std::process::Command;

type HmacSha256 = Hmac<Sha256>;

// Function to verify HMAC signature (Gitea Webhook)
fn verify_hmac_signature(body: &[u8], headers: &HeaderMap) -> bool {
    let secret_key =
        env::var("GITEA_SECRET").expect("GITEA_SECRET environment variable is missing");

    // Check if the X-Hub-Signature-256 header is present
    if let Some(signature) = headers.get("X-Hub-Signature-256") {
        let signature = match signature.to_str() {
            Ok(sig) => sig,
            Err(_) => return false, // Handle invalid UTF-8 signature
        };

        // Verify the HMAC signature
        let mut mac =
            HmacSha256::new_from_slice(secret_key.as_bytes()).expect("Invalid key length");
        mac.update(body);
        let expected_signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        // Compare the signatures
        signature == expected_signature
    } else {
        false
    }
}

// Webhook handler with both HMAC and token authentication
async fn webhook(req_body: web::Bytes, req: HttpRequest) -> impl Responder {
    // Load the authorization token from environment variables
    let auth_token = env::var("AUTH_TOKEN").unwrap_or_else(|_| "default_token123".to_string());

    // Step 1: Token Authentication (Authorization header)
    let mut is_authorized = false;
    if let Some(auth_header) = req.headers().get("Authorization") {
        if *auth_header == format!("Bearer {}", auth_token) {
            is_authorized = true;
        }
    }

    // Handle invalid or missing Authorization header requests
    if !is_authorized {
        return HttpResponse::Unauthorized().body("Authorization header is missing or invalid");
    }

    // Step 2: HMAC Authentication (Gitea Webhook signature)
    if !verify_hmac_signature(&req_body, &req.headers()) {
        return HttpResponse::Unauthorized().body("HMAC signature verification failed");
    }

    // Step 3: Run the target binary/script if authenticated
    let bin_path = env::var("BIN_PATH").unwrap_or_else(|_| "./target/webhook.sh".to_string());
    match Command::new(bin_path).output() {
        Ok(output) if output.status.success() => HttpResponse::Ok()
            .insert_header((CONTENT_TYPE, "text/plain"))
            .body("Webhook successfully authenticated and executed"),
        Ok(_) => HttpResponse::InternalServerError()
            .body("Warning: Webhook payload exited with non-zero exit code"),
        Err(_) => {
            HttpResponse::InternalServerError().body("Error: Unable to execute webhook payload")
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load environment variables from .env file

    // Load address and route from environment or use defaults
    let addr = env::var("ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let route = env::var("ROUTE").unwrap_or_else(|_| "/webhook".to_string());

    println!("rusty-hook listening on: {}", addr);

    // Start the HTTP server and handle the webhook
    HttpServer::new(move || {
        App::new().route(&route, web::post().to(webhook)) // Handle POST requests to /webhook
    })
    .bind(&addr)?
    .run()
    .await
}
