use std::env;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

const DEFAULT_VSOCK_PORT: u32 = 5005;
const DEFAULT_HTTP_PORT: u16 = 9999;
const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
const DEFAULT_COCO_CONFIG_PATH: &str = "/app/coco-runtime-config.json";
const DEFAULT_WORKLOAD_ID: &str = "ztbrowser-aws-nitro";
const ATTESTED_RESPONSE_VERSION: &str = "zt-attested-response/v1";
const NITRO_PLATFORM: &str = "aws_nitro_eif";
const COCO_PLATFORM: &str = "aws_coco_snp";

static RESPONSE_SIGNING_KEY: OnceLock<SigningKey> = OnceLock::new();

#[derive(Deserialize)]
struct EnclaveRequest {
    action: String,
    #[serde(default)]
    nonce_hex: Option<String>,
    #[serde(default)]
    response_challenge: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    release_id: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    facts_url: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    body_b64: Option<String>,
    #[serde(default)]
    host_origin: Option<String>,
}

#[derive(Serialize)]
struct EnclaveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_doc_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_signing_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_signing_key_binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_response: Option<SignedResponseHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedResponseHeaders {
    version: String,
    key_id: String,
    content_digest: String,
    signature: String,
    signed_at: u128,
    challenge: String,
}

#[derive(Clone)]
struct ResponseSigningContext<'a> {
    method: &'a str,
    path: &'a str,
    status: u16,
    content_type: &'a str,
    challenge: &'a str,
    service: &'a str,
    release_id: &'a str,
    platform: &'a str,
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUNTIME_MODE").as_deref() == Ok("coco_http")
        || env::var("COCO_HTTP_MODE").as_deref() == Ok("1")
    {
        return run_coco_http_server();
    }

    let port = env::var("VSOCK_PORT")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_VSOCK_PORT);

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .with_context(|| format!("Could not bind enclave vsock listener on port {port}"))?;

    println!("Enclave attestation server listening on vsock port {port}");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("Could not accept vsock connection")?;
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream).await {
                eprintln!("vsock request from {peer_addr:?} failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(stream: tokio_vsock::VsockStream) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let read = reader
        .read_line(&mut request_line)
        .await
        .context("Could not read request line")?;

    if read == 0 {
        bail!("Parent closed connection before sending a request");
    }

    let request: EnclaveRequest =
        serde_json::from_str(request_line.trim()).context("Request is not valid JSON")?;
    let response = match request.action.as_str() {
        "index" => {
            let (status, content_type, body_bytes) = proxy_local_app(
                "GET",
                request.path.as_deref().unwrap_or("/"),
                request.host_origin.as_deref(),
                None,
                &[],
            )
            .await?;
            if status != 200 {
                bail!("Landing page returned unexpected status: {status}");
            }
            let html = String::from_utf8(body_bytes).context("Landing page HTML was not UTF-8")?;
            let service = request.service.as_deref().unwrap_or(DEFAULT_WORKLOAD_ID);
            let release_id = request.release_id.as_deref().unwrap_or(DEFAULT_WORKLOAD_ID);
            let platform = request.platform.as_deref().unwrap_or(NITRO_PLATFORM);
            let signed_response = request
                .response_challenge
                .as_deref()
                .map(|challenge| {
                    sign_response_headers(
                        html.as_bytes(),
                        ResponseSigningContext {
                            method: request.method.as_deref().unwrap_or("GET"),
                            path: request.path.as_deref().unwrap_or("/"),
                            status: 200,
                            content_type: &content_type,
                            challenge,
                            service,
                            release_id,
                            platform,
                        },
                    )
                })
                .transpose()?;
            EnclaveResponse {
                content_type: Some(content_type.to_string()),
                html: Some(html),
                attestation_doc_b64: None,
                attestation_json: None,
                response_signing_key: None,
                response_signing_key_id: None,
                response_signing_key_binding: None,
                signed_response,
                status: None,
                body_b64: None,
            }
        }
        "attestation" => {
            let nonce_hex = request
                .nonce_hex
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("nonce_hex is required for attestation requests"))?;
            let nonce = parse_nonce_hex(nonce_hex)?;
            let service = request.service.as_deref().unwrap_or(DEFAULT_WORKLOAD_ID);
            let release_id = request.release_id.as_deref().unwrap_or(DEFAULT_WORKLOAD_ID);
            let platform = request.platform.as_deref().unwrap_or(NITRO_PLATFORM);
            let public_jwk = response_signing_public_jwk();
            let key_id = response_signing_key_id()?;
            let binding = response_signing_binding_hash(
                nonce_hex,
                &key_id,
                &public_jwk,
                service,
                release_id,
                platform,
                BindingHash::Sha256,
            )?;
            let public_key = canonical_json(&public_jwk)?;
            let binding_bytes = hex_to_bytes(&binding)?;
            let attestation_doc_b64 = request_attestation_doc(
                nonce,
                Some(public_key.as_bytes().to_vec()),
                Some(binding_bytes),
            )?;
            
            let (workload_pubkey, trusted_input_service) = fetch_local_manifest(request.host_origin.as_deref())
                .await
                .unwrap_or((Value::Null, Value::Null));
            let mut claims_obj = serde_json::Map::new();
            claims_obj.insert("workload_pubkey".to_string(), workload_pubkey);
            claims_obj.insert("identity_hint".to_string(), Value::Null);
            claims_obj.insert("response_signing_key".to_string(), public_jwk.clone());
            claims_obj.insert("response_signing_key_id".to_string(), Value::String(key_id.clone()));
            claims_obj.insert("response_signing_key_binding".to_string(), Value::String(binding.clone()));
            if !trusted_input_service.is_null() {
                claims_obj.insert("trusted_input_service".to_string(), trusted_input_service);
            }

            let envelope = json!({
                "version": "ztinfra-attestation/v1",
                "service": service,
                "release_id": release_id,
                "platform": platform,
                "nonce": nonce_hex,
                "claims": Value::Object(claims_obj),
                "evidence": {
                    "type": "aws_nitro_attestation_doc",
                    "payload": {
                        "nitro_attestation_doc_b64": attestation_doc_b64,
                    },
                },
                "facts_url": request.facts_url.clone().map(Value::String).unwrap_or(Value::Null),
            });
            let payload = serde_json::to_vec(&envelope)?;
            let signed_response = request
                .response_challenge
                .as_deref()
                .map(|challenge| {
                    sign_response_headers(
                        &payload,
                        ResponseSigningContext {
                            method: request.method.as_deref().unwrap_or("POST"),
                            path: request
                                .path
                                .as_deref()
                                .unwrap_or("/.well-known/attestation"),
                            status: 200,
                            content_type: "application/json",
                            challenge,
                            service,
                            release_id,
                            platform,
                        },
                    )
                })
                .transpose()?;
            EnclaveResponse {
                content_type: None,
                html: None,
                attestation_doc_b64: None,
                attestation_json: Some(
                    String::from_utf8(payload)
                        .context("Attestation envelope JSON was not UTF-8")?,
                ),
                response_signing_key: Some(public_jwk),
                response_signing_key_id: Some(key_id),
                response_signing_key_binding: Some(binding),
                signed_response,
                status: None,
                body_b64: None,
            }
        }
        "http" => {
            let method = request.method.as_deref().unwrap_or("GET");
            let path = request.path.as_deref().unwrap_or("/");
            let body = if let Some(b64) = request.body_b64.as_deref() {
                BASE64_STANDARD.decode(b64).unwrap_or_default()
            } else {
                Vec::new()
            };
            let (status, content_type, body_bytes) = proxy_local_app(
                method,
                path,
                request.host_origin.as_deref(),
                request.content_type.as_deref(),
                &body,
            )
            .await?;
            
            let service = request.service.as_deref().unwrap_or(DEFAULT_WORKLOAD_ID);
            let release_id = request.release_id.as_deref().unwrap_or(DEFAULT_WORKLOAD_ID);
            let platform = request.platform.as_deref().unwrap_or(NITRO_PLATFORM);
            let signed_response = request.response_challenge.as_deref().map(|challenge| {
                sign_response_headers(&body_bytes, ResponseSigningContext {
                    method, path, status, content_type: &content_type, challenge, service, release_id, platform
                })
            }).transpose()?;
            
            EnclaveResponse {
                content_type: Some(content_type),
                html: None,
                attestation_doc_b64: None,
                attestation_json: None,
                response_signing_key: None,
                response_signing_key_id: None,
                response_signing_key_binding: None,
                signed_response,
                status: Some(status),
                body_b64: Some(BASE64_STANDARD.encode(body_bytes)),
            }
        }
        other => bail!("Unsupported action: {other}"),
    };
    let response = serde_json::to_vec(&response)?;

    let stream = reader.get_mut();
    AsyncWriteExt::write_all(stream, &response)
        .await
        .context("Could not write response JSON")?;
    AsyncWriteExt::write_all(stream, b"\n")
        .await
        .context("Could not write response terminator")?;

    Ok(())
}

fn origin_authority(origin: Option<&str>) -> &str {
    origin
        .and_then(|value| value.split("://").nth(1))
        .unwrap_or("localhost")
}

fn origin_scheme(origin: Option<&str>) -> &str {
    origin
        .and_then(|value| value.split("://").next())
        .filter(|value| !value.is_empty())
        .unwrap_or("http")
}

async fn proxy_local_app(
    method: &str,
    path: &str,
    host_origin: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(u16, String, Vec<u8>)> {
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
    let mut request = format!(
        "{method} {path} HTTP/1.0\r\nHost: {}\r\nX-Forwarded-Proto: {}\r\n",
        origin_authority(host_origin),
        origin_scheme(host_origin),
    );
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, body).await?;
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;
    let response_text = String::from_utf8_lossy(&response);
    let (headers, _) = response_text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP"))?;
    let mut status = 502;
    let mut response_content_type = "application/octet-stream".to_string();
    if let Some(line) = headers.lines().next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 1 {
            status = parts[1].parse().unwrap_or(502);
        }
    }
    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with("content-type:") {
            response_content_type = line.split(':').nth(1).unwrap_or("").trim().to_string();
        }
    }
    let body_offset = headers.len() + 4;
    let response_body = if body_offset <= response.len() {
        response[body_offset..].to_vec()
    } else {
        Vec::new()
    };
    Ok((status, response_content_type, response_body))
}

async fn fetch_local_manifest(host_origin: Option<&str>) -> Result<(Value, Value)> {
    let (status, _content_type, body) =
        proxy_local_app("GET", "/zt-manifest", host_origin, None, &[]).await?;
    if status != 200 {
        bail!("Manifest endpoint returned unexpected status: {status}");
    }
    let manifest: Value = serde_json::from_slice(&body)?;
    Ok((
        manifest.get("workload_pubkey").cloned().unwrap_or(Value::Null),
        manifest.get("trusted_input_service").cloned().unwrap_or(Value::Null),
    ))
}

fn run_coco_http_server() -> Result<()> {
    let host = env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_HTTP_PORT);
    let listener = TcpListener::bind((host.as_str(), port))
        .with_context(|| format!("Could not bind CoCo HTTP listener on {host}:{port}"))?;

    println!("CoCo attestation server listening on http://{host}:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| {
                    if let Err(error) = handle_http_connection(stream) {
                        eprintln!("CoCo HTTP request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("Could not accept CoCo HTTP connection: {error:#}"),
        }
    }
    Ok(())
}

fn handle_http_connection(mut stream: TcpStream) -> Result<()> {
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_http_response(
            &mut stream,
            400,
            "text/plain; charset=utf-8",
            b"bad_request",
            None,
        )?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];
    let mut content_length = 0usize;
    let mut content_type: Option<String> = None;
    let mut host_origin: Option<String> = None;
    let mut response_challenge: Option<String> = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("host") {
                host_origin = Some(format!("http://{}", value.trim()));
            } else if name.eq_ignore_ascii_case("x-zt-challenge") {
                response_challenge = Some(value.trim().to_string());
            }
        }
    }

    match (method, path) {
        ("GET", "/") => {
            let (status, page_content_type, html) = tokio::runtime::Handle::current()
                .block_on(proxy_local_app("GET", "/", host_origin.as_deref(), None, &[]))?;
            if status != 200 {
                bail!("Landing page returned unexpected status: {status}");
            }
            let signed = if let Some(challenge) = response_challenge.as_deref() {
                let config = load_coco_config()?;
                let service = config["service"]
                    .as_str()
                    .unwrap_or("ztinfra-enclaveproducedhtml");
                let release_id = config["release_id"].as_str().unwrap_or("unknown-release");
                let platform = config
                    .get("platform")
                    .and_then(Value::as_str)
                    .unwrap_or(COCO_PLATFORM);
                Some(sign_response_headers(
                    &html,
                    ResponseSigningContext {
                        method,
                        path,
                        status: 200,
                        content_type: &page_content_type,
                        challenge,
                        service,
                        release_id,
                        platform,
                    },
                )?)
            } else {
                None
            };
            write_http_response(
                &mut stream,
                200,
                &page_content_type,
                &html,
                signed.as_ref(),
            )?;
        }
        ("POST", "/.well-known/attestation") => {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            let request: Value =
                serde_json::from_slice(if body.is_empty() { b"{}" } else { &body })
                    .context("HTTP request body is not valid JSON")?;
            let nonce = request
                .get("NONCE")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("NONCE is required"))?
                .to_lowercase();
            parse_nonce_hex(&nonce)?;

            let config = load_coco_config()?;
            let service = config["service"]
                .as_str()
                .unwrap_or("ztinfra-enclaveproducedhtml");
            let release_id = config["release_id"].as_str().unwrap_or("unknown-release");
            let platform = config
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or(COCO_PLATFORM);
            let public_jwk = response_signing_public_jwk();
            let key_id = response_signing_key_id()?;
            let binding = response_signing_binding_hash(
                &nonce,
                &key_id,
                &public_jwk,
                service,
                release_id,
                platform,
                BindingHash::Sha512,
            )?;
            let evidence = fetch_coco_aa_evidence(
                config
                    .get("aa_evidence_url")
                    .and_then(Value::as_str)
                    .unwrap_or("http://127.0.0.1:8006/aa/evidence"),
                &binding,
            )?;
            let identity_hint = config
                .get("identity_hint")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "coco_image_initdata:{}:{}",
                        config["image_digest"].as_str().unwrap_or_default(),
                        config["initdata_hash"].as_str().unwrap_or_default()
                    )
                });
            let (workload_pubkey, trusted_input_service) = tokio::runtime::Handle::current()
                .block_on(fetch_local_manifest(host_origin.as_deref()))
                .unwrap_or((Value::Null, Value::Null));
            let envelope = json!({
                "version": "ztinfra-attestation/v1",
                "service": config["service"],
                "release_id": config["release_id"],
                "platform": platform,
                "nonce": nonce,
                "claims": {
                    "workload_pubkey": workload_pubkey,
                    "identity_hint": identity_hint,
                    "response_signing_key": public_jwk,
                    "response_signing_key_id": key_id,
                    "response_signing_key_binding": binding,
                    "trusted_input_service": trusted_input_service,
                },
                "evidence": {
                    "type": "coco_trustee_evidence",
                    "payload": evidence,
                },
                "facts_url": config.get("facts_url").cloned().unwrap_or(Value::Null),
            });
            let payload = serde_json::to_vec(&envelope)?;
            let signed = sign_response_if_challenged(
                response_challenge.as_deref(),
                &payload,
                ResponseSigningContext {
                    method,
                    path,
                    status: 200,
                    content_type: "application/json",
                    challenge: "",
                    service,
                    release_id,
                    platform,
                },
            )?;
            write_http_response(
                &mut stream,
                200,
                "application/json",
                &payload,
                signed.as_ref(),
            )?;
        }
        _ => {
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body)?;
            }
            let (status, response_content_type, response_body) = tokio::runtime::Handle::current()
                .block_on(proxy_local_app(
                    method,
                    path,
                    host_origin.as_deref(),
                    content_type.as_deref(),
                    &body,
                ))?;
            let signed = sign_coco_response_if_challenged(
                response_challenge.as_deref(),
                &response_body,
                method,
                path,
                status,
                &response_content_type,
            )?;
            write_http_response(
                &mut stream,
                status,
                &response_content_type,
                &response_body,
                signed.as_ref(),
            )?;
        }
    }

    Ok(())
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    signed_response: Option<&SignedResponseHeaders>,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    write!(stream, "HTTP/1.1 {status} {reason}\r\n")?;
    write!(stream, "Content-Type: {content_type}\r\n")?;
    write!(stream, "Content-Length: {}\r\n", body.len())?;
    if let Some(headers) = signed_response {
        write!(stream, "X-ZT-Signature-Version: {}\r\n", headers.version)?;
        write!(stream, "X-ZT-Key-Id: {}\r\n", headers.key_id)?;
        write!(
            stream,
            "X-ZT-Content-Digest: {}\r\n",
            headers.content_digest
        )?;
        write!(stream, "X-ZT-Signature: {}\r\n", headers.signature)?;
        write!(stream, "X-ZT-Signed-At: {}\r\n", headers.signed_at)?;
        write!(stream, "X-ZT-Challenge: {}\r\n", headers.challenge)?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.write_all(body)?;
    Ok(())
}

fn sign_coco_response_if_challenged(
    challenge: Option<&str>,
    body: &[u8],
    method: &str,
    path: &str,
    status: u16,
    content_type: &str,
) -> Result<Option<SignedResponseHeaders>> {
    let Some(challenge) = challenge else {
        return Ok(None);
    };
    let config = load_coco_config().unwrap_or(Value::Null);
    let service = config
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or("ztinfra-enclaveproducedhtml");
    let release_id = config
        .get("release_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| env::var("RELEASE_ID").unwrap_or_else(|_| "unknown-release".to_string()));
    let platform = config
        .get("platform")
        .and_then(Value::as_str)
        .unwrap_or(COCO_PLATFORM);
    Ok(Some(sign_response_headers(
        body,
        ResponseSigningContext {
            method,
            path,
            status,
            content_type,
            challenge,
            service,
            release_id: &release_id,
            platform,
        },
    )?))
}

fn sign_response_if_challenged(
    challenge: Option<&str>,
    body: &[u8],
    context: ResponseSigningContext<'_>,
) -> Result<Option<SignedResponseHeaders>> {
    let Some(challenge) = challenge else {
        return Ok(None);
    };
    sign_response_headers(
        body,
        ResponseSigningContext {
            challenge,
            ..context
        },
    )
    .map(Some)
}

#[derive(Clone, Copy)]
enum BindingHash {
    Sha256,
    Sha512,
}

fn response_signing_key() -> &'static SigningKey {
    RESPONSE_SIGNING_KEY.get_or_init(|| SigningKey::random(&mut OsRng))
}

fn response_signing_public_jwk() -> Value {
    let verifying_key = response_signing_key().verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded
        .x()
        .expect("P-256 public key must include x coordinate");
    let y = encoded
        .y()
        .expect("P-256 public key must include y coordinate");
    json!({
        "crv": "P-256",
        "ext": true,
        "key_ops": ["verify"],
        "kty": "EC",
        "x": BASE64_URL_SAFE_NO_PAD.encode(x),
        "y": BASE64_URL_SAFE_NO_PAD.encode(y),
    })
}

fn response_signing_key_id() -> Result<String> {
    let canonical = canonical_json(&response_signing_public_jwk())?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", BASE64_URL_SAFE_NO_PAD.encode(digest)))
}

fn response_signing_binding_hash(
    nonce: &str,
    key_id: &str,
    public_jwk: &Value,
    service: &str,
    release_id: &str,
    platform: &str,
    hash: BindingHash,
) -> Result<String> {
    let context = json!({
        "key_id": key_id,
        "platform": platform,
        "public_jwk": canonical_value(public_jwk),
        "release_id": release_id,
        "service": service,
        "nonce": nonce,
        "version": ATTESTED_RESPONSE_VERSION,
    });
    let canonical = canonical_json(&context)?;
    let bytes = canonical.as_bytes();
    Ok(match hash {
        BindingHash::Sha256 => hex_encode(&Sha256::digest(bytes)),
        BindingHash::Sha512 => hex_encode(&Sha512::digest(bytes)),
    })
}

fn sign_response_headers(
    body: &[u8],
    context: ResponseSigningContext<'_>,
) -> Result<SignedResponseHeaders> {
    let key_id = response_signing_key_id()?;
    let content_digest = format!("sha-256=:{}:", BASE64_STANDARD.encode(Sha256::digest(body)));
    let signed_at = now_millis()?;
    let payload = json!({
        "challenge": context.challenge,
        "content_digest": content_digest,
        "content_type": normalize_content_type(context.content_type),
        "key_id": key_id,
        "method": context.method.to_ascii_uppercase(),
        "path": context.path,
        "platform": context.platform,
        "release_id": context.release_id,
        "service": context.service,
        "signed_at": signed_at,
        "status": context.status,
        "version": ATTESTED_RESPONSE_VERSION,
    });
    let canonical = canonical_json(&payload)?;
    let signature: Signature = response_signing_key().sign(canonical.as_bytes());
    Ok(SignedResponseHeaders {
        version: ATTESTED_RESPONSE_VERSION.to_string(),
        key_id,
        content_digest,
        signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        signed_at,
        challenge: context.challenge.to_string(),
    })
}

fn normalize_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn now_millis() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before UNIX_EPOCH")?
        .as_millis())
}

fn canonical_json(value: &Value) -> Result<String> {
    serde_json::to_string(&canonical_value(value)).context("Could not serialize canonical JSON")
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), canonical_value(&object[key]));
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    parse_nonce_hex(value)
}

fn load_coco_config() -> Result<Value> {
    let path = env::var("COCO_RUNTIME_CONFIG_PATH")
        .unwrap_or_else(|_| DEFAULT_COCO_CONFIG_PATH.to_string());
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Could not read CoCo runtime config: {path}"))?;
    serde_json::from_str(&contents).context("CoCo runtime config is not valid JSON")
}

fn fetch_coco_aa_evidence(aa_evidence_url: &str, nonce_hex: &str) -> Result<Value> {
    let parsed = aa_evidence_url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// AA evidence URLs are supported"))?;
    let (authority, path) = parsed.split_once('/').unwrap_or((parsed, ""));
    let (host, port) = if let Some((host, port)) = authority.split_once(':') {
        (host, port.parse::<u16>()?)
    } else {
        (authority, 80)
    };
    let base_path = format!("/{path}");
    let separator = if base_path.contains('?') { '&' } else { '?' };
    let request_path = format!("{base_path}{separator}runtime_data={nonce_hex}");

    let mut stream = TcpStream::connect((host, port))
        .with_context(|| format!("Could not connect to CoCo AA endpoint {host}:{port}"))?;
    write!(
        stream,
        "GET {request_path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response_text = String::from_utf8(response).context("AA response is not UTF-8")?;
    let (headers, body) = response_text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("AA response is not valid HTTP"))?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        bail!(
            "AA endpoint returned non-200 response: {}",
            headers.lines().next().unwrap_or(headers)
        );
    }
    serde_json::from_str(body).context("AA evidence response is not valid JSON")
}

fn request_attestation_doc(
    nonce: Vec<u8>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
) -> Result<String> {
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        bail!("Could not open /dev/nsm");
    }

    let response = nsm_process_request(
        nsm_fd,
        Request::Attestation {
            user_data: user_data.map(ByteBuf::from),
            nonce: Some(ByteBuf::from(nonce)),
            public_key: public_key.map(ByteBuf::from),
        },
    );
    nsm_exit(nsm_fd);

    match response {
        Response::Attestation { document } => Ok(BASE64_STANDARD.encode(document)),
        Response::Error(code) => bail!("NSM returned error: {code:?}"),
        other => bail!("Unexpected NSM response: {other:?}"),
    }
}

fn parse_nonce_hex(value: &str) -> Result<Vec<u8>> {
    let clean = value.trim().to_lowercase();
    if clean.is_empty() {
        bail!("nonce_hex must be a non-empty hex string");
    }
    if clean.len() % 2 != 0 || !clean.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("nonce_hex must be an even-length hex string");
    }

    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for index in (0..clean.len()).step_by(2) {
        let pair = &clean[index..index + 2];
        let value =
            u8::from_str_radix(pair, 16).with_context(|| format!("Invalid nonce byte: {pair}"))?;
        bytes.push(value);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::EncodedPoint;

    fn public_key_from_jwk(jwk: &Value) -> VerifyingKey {
        let x = BASE64_URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().expect("jwk x"))
            .expect("x base64url");
        let y = BASE64_URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().expect("jwk y"))
            .expect("y base64url");
        let point = EncodedPoint::from_affine_coordinates((&x[..]).into(), (&y[..]).into(), false);
        VerifyingKey::from_encoded_point(&point).expect("valid P-256 public key")
    }

    #[test]
    fn response_key_id_and_bindings_are_well_formed() {
        let jwk = response_signing_public_jwk();
        let key_id = response_signing_key_id().expect("key id");
        assert!(key_id.starts_with("sha256:"));

        let nitro = response_signing_binding_hash(
            &"ab".repeat(32),
            &key_id,
            &jwk,
            "ztinfra-enclaveproducedhtml",
            "v0.2.2",
            NITRO_PLATFORM,
            BindingHash::Sha256,
        )
        .expect("nitro binding");
        assert_eq!(nitro.len(), 64);

        let coco = response_signing_binding_hash(
            &"ab".repeat(32),
            &key_id,
            &jwk,
            "ztinfra-enclaveproducedhtml",
            "v0.2.2",
            COCO_PLATFORM,
            BindingHash::Sha512,
        )
        .expect("coco binding");
        assert_eq!(coco.len(), 128);
        assert_ne!(nitro, coco[..64]);
    }

    #[test]
    fn signed_response_headers_verify_against_public_jwk() {
        let body = b"<html>signed</html>";
        let headers = sign_response_headers(
            body,
            ResponseSigningContext {
                method: "GET",
                path: "/?x=1",
                status: 200,
                content_type: "text/html; charset=utf-8",
                challenge: &"cd".repeat(32),
                service: "ztinfra-enclaveproducedhtml",
                release_id: "v0.2.2",
                platform: COCO_PLATFORM,
            },
        )
        .expect("signed headers");
        let payload = json!({
            "challenge": headers.challenge,
            "content_digest": headers.content_digest,
            "content_type": "text/html",
            "key_id": headers.key_id,
            "method": "GET",
            "path": "/?x=1",
            "platform": COCO_PLATFORM,
            "release_id": "v0.2.2",
            "service": "ztinfra-enclaveproducedhtml",
            "signed_at": headers.signed_at,
            "status": 200,
            "version": ATTESTED_RESPONSE_VERSION,
        });
        let canonical = canonical_json(&payload).expect("canonical payload");
        let signature_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(headers.signature)
            .expect("signature base64url");
        let signature = Signature::try_from(signature_bytes.as_slice()).expect("P1363 signature");
        public_key_from_jwk(&response_signing_public_jwk())
            .verify(canonical.as_bytes(), &signature)
            .expect("signature verifies");

        let tampered = canonical.replace("signed", "tampered");
        assert!(public_key_from_jwk(&response_signing_public_jwk())
            .verify(tampered.as_bytes(), &signature)
            .is_err());
    }
}
