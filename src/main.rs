use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::prelude::*;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use jwt_simple::prelude::*;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Jwk {
    kid: String,
    alg: String,
    kty: String,
    r#use: String,
    e: String,
    n: String,
}

struct Key {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    kid: String,
    expiry: i64,
}

trait KeyTrait {
    fn new() -> Self;
    fn new_expired() -> Self;
}

impl KeyTrait for Key {
    fn new() -> Self {
        let bits = 2048; // Adjust the key size as needed

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let kid = format!("rsa-key-{}", bits);
        let expiry = Utc::now().timestamp() + chrono::Duration::hours(1).num_seconds();
        Key {
            private_key,
            public_key,
            kid,
            expiry,
        }
    }
    fn new_expired() -> Self {
        let bits = 2048; // Adjust the key size as needed

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let kid = format!("rsa-key-{}", bits);
        let expiry = Utc::now().timestamp() - chrono::Duration::hours(1).num_seconds();
        Key {
            private_key,
            public_key,
            kid,
            expiry,
        }
    }
}
#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

async fn jwks_endpoint() -> HttpResponse {
    // Create a JSON Web Key (JWK)
    let (kid, private_key, public_key) = generate_rsa_key1();
    let jwk = Jwk {
        kid: kid.clone(),
        kty: "RSA".to_string(),
        r#use: "sig".to_string(),
        alg: "RS256".to_string(),
        e: BASE64.encode(&public_key.e().to_bytes_be()),
        n: BASE64.encode(&public_key.n().to_bytes_be()),
    };

    // Create a JWKS containing the JWK
    let jwks = Jwks { keys: vec![jwk] };

    // Serialize the JWKS as JSON and return it
    HttpResponse::Ok()
        .content_type("application/json")
        .body(serde_json::to_string(&jwks).unwrap())
}

fn generate_rsa_key1() -> (String, RsaPrivateKey, RsaPublicKey) {
    let bits = 2048; // Adjust the key size as needed

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let kid = format!("rsa-key-{}", bits);
    (kid, private_key, public_key)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let unexpired_key: Key = Key::new();
    let expired_key: Key = Key::new_expired();
    HttpServer::new(|| App::new().route("/.well-known/jwks.json", web::get().to(jwks_endpoint)))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
