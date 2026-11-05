use crate::config::Settings;
use crate::db::Database;
use crate::models::{
    BatchCheckRequest, HealthLiveResponse, ProblemDetails, UrlCheckRequest, MAX_BATCH_ITEMS,
    PROBLEM_JSON_CONTENT_TYPE,
};
use crate::ratelimit::{extract_client_ip, RateLimitDecision, SlidingWindowRateLimiter};
use crate::swagger::{
    build_branded_home_html, build_branded_openapi_schema, build_branded_swagger_html,
    resolve_brand_asset, DEFAULT_SWAGGER_TITLE,
};
use crate::types::{ArtifactSource, DgspamguardError, APP_VERSION};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use tower_http::cors::{Any, CorsLayer};

const MAX_JSON_BODY_BYTES: usize = 128 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub settings: Settings,
    pub limiter: Arc<SlidingWindowRateLimiter>,
}

impl AppState {
    pub fn new(db: Database, settings: Settings, initial_rate_limit: u32) -> Self {
        Self {
            db,
            settings,
            limiter: Arc::new(SlidingWindowRateLimiter::new(initial_rate_limit)),
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::HEAD, Method::OPTIONS])
        .allow_headers(Any);

    let v1_routes = Router::new()
        .route("/domain/:domain", get(handle_domain_lookup))
        .route("/url/check", post(handle_url_check))
        .route("/ip/:ip", get(handle_ip_lookup))
        .route("/hash/:sha256", get(handle_hash_lookup))
        .route("/check/batch", post(handle_batch_check))
        .route("/snapshots", get(handle_list_snapshots))
        .route("/snapshots/latest", get(handle_latest_snapshot))
        .route("/snapshots/:version", get(handle_get_snapshot))
        .route(
            "/snapshots/:version/bundle.tar.gz",
            get(handle_download_bundle),
        )
        .route(
            "/snapshots/:version/files/:filename",
            get(handle_download_file),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    Router::new()
        .route("/", get(handle_home))
        .route("/docs", get(handle_swagger_ui))
        .route("/docs/assets/:asset", get(handle_brand_asset))
        .route("/openapi.json", get(handle_openapi_json))
        .route("/healthz/live", get(handle_health_live))
        .route("/healthz/ready", get(handle_health_ready))
        .nest("/v1", v1_routes)
        .fallback(handle_not_found)
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(cors)
        .with_state(state)
}

fn problem_response(
    status: StatusCode,
    title: &str,
    detail: impl Into<String>,
    instance: Option<String>,
) -> Response {
    let body = ProblemDetails::new(status.as_u16(), title, detail, instance);
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Body::from(payload));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(PROBLEM_JSON_CONTENT_TYPE),
    );
    resp
}

fn map_dgspamguard_error(err: DgspamguardError, instance: Option<String>) -> Response {
    match err {
        DgspamguardError::Validation(msg) => {
            problem_response(StatusCode::BAD_REQUEST, "Bad Request", msg, instance)
        }
        DgspamguardError::NotFound(msg) => {
            problem_response(StatusCode::NOT_FOUND, "Not Found", msg, instance)
        }
        DgspamguardError::Unavailable(msg) => problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            msg,
            instance,
        ),
        DgspamguardError::Database(msg)
        | DgspamguardError::Sync(msg)
        | DgspamguardError::Compile(msg) => {
            tracing::error!(error = %msg, "Internal DGSPAMGUARD request error");
            problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An internal storage or processing error occurred.",
                instance,
            )
        }
        DgspamguardError::Io(e) => {
            tracing::error!(error = %e, "Internal I/O error");
            problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An internal I/O error occurred.",
                instance,
            )
        }
    }
}

fn apply_rate_headers(headers: &mut HeaderMap, decision: &RateLimitDecision) {
    for (k, v) in decision.headers() {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            headers.insert(name, val);
        }
    }
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());

    let catalog = state.db.load_runtime_catalog().await.ok();
    if let Some(cat) = &catalog {
        state.limiter.set_limit(cat.rate_limit_per_minute);
    }
    let proxies = catalog
        .as_ref()
        .map(|c| c.trusted_proxies.as_slice())
        .unwrap_or(&[]);

    let client_key = extract_client_ip(&peer_ip, xff, proxies);
    let decision = state.limiter.check(&client_key);

    if !decision.allowed {
        let path = req.uri().path().to_string();
        let mut resp = problem_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Requests",
            format!(
                "Rate limit of {} requests per minute exceeded. Retry in {} second(s).",
                decision.limit,
                decision.retry_after_seconds.unwrap_or(1)
            ),
            Some(path),
        );
        apply_rate_headers(resp.headers_mut(), &decision);
        return resp;
    }

    let mut resp = next.run(req).await;
    apply_rate_headers(resp.headers_mut(), &decision);
    resp
}

/// Return the route-scoped `Content-Security-Policy` directive for `path`.
pub fn csp_for_path(path: &str) -> &'static str {
    if path == "/" {
        concat!(
            "default-src 'self'; ",
            "script-src 'self' 'unsafe-inline'; ",
            "style-src 'self' 'unsafe-inline'; ",
            "img-src 'self' data:; ",
            "connect-src 'self'; ",
            "frame-ancestors 'none'; ",
            "base-uri 'self'; ",
            "form-action 'self'"
        )
    } else if path.starts_with("/docs/assets/") {
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    } else if path == "/docs" || path.starts_with("/docs/") {
        concat!(
            "default-src 'self'; ",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ",
            "img-src 'self' data:; ",
            "font-src 'self' https://cdn.jsdelivr.net data:; ",
            "connect-src 'self'; ",
            "frame-ancestors 'none'; ",
            "base-uri 'self'"
        )
    } else {
        "default-src 'none'; frame-ancestors 'none'"
    }
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    let csp = csp_for_path(&path);
    if let Ok(val) = HeaderValue::from_str(csp) {
        headers.insert(HeaderName::from_static("content-security-policy"), val);
    }
    resp
}

async fn read_bounded_body(
    req: Request,
    max_bytes: usize,
) -> Result<(Bytes, String), Box<Response>> {
    let path = req.uri().path().to_string();
    if let Some(cl) = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if cl > max_bytes {
            return Err(Box::new(problem_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload Too Large",
                format!("Request body exceeds maximum size of {max_bytes} bytes."),
                Some(path),
            )));
        }
    }

    let mut body_stream = req.into_body().into_data_stream();
    let mut buf = Vec::new();
    while let Some(chunk_res) = body_stream.next().await {
        let chunk = chunk_res.map_err(|e| {
            Box::new(problem_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                format!("Failed reading request body: {e}"),
                Some(path.clone()),
            ))
        })?;
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(Box::new(problem_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload Too Large",
                format!("Request body exceeds maximum size of {max_bytes} bytes."),
                Some(path),
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok((Bytes::from(buf), path))
}

async fn handle_home(State(state): State<AppState>) -> Response {
    let swagger_on = state
        .db
        .load_runtime_catalog()
        .await
        .map(|c| c.swagger_enabled)
        .unwrap_or(state.settings.swagger_enabled);
    Html(build_branded_home_html(APP_VERSION, swagger_on)).into_response()
}

async fn handle_swagger_ui(State(state): State<AppState>) -> Response {
    let swagger_on = state
        .db
        .load_runtime_catalog()
        .await
        .map(|c| c.swagger_enabled)
        .unwrap_or(state.settings.swagger_enabled);
    if !swagger_on {
        return problem_response(
            StatusCode::NOT_FOUND,
            "Not Found",
            "Swagger UI is disabled on this instance.",
            Some("/docs".to_string()),
        );
    }
    Html(build_branded_swagger_html(
        DEFAULT_SWAGGER_TITLE,
        "/openapi.json",
    ))
    .into_response()
}

async fn handle_openapi_json(State(state): State<AppState>) -> Response {
    let swagger_on = state
        .db
        .load_runtime_catalog()
        .await
        .map(|c| c.swagger_enabled)
        .unwrap_or(state.settings.swagger_enabled);
    if !swagger_on {
        return problem_response(
            StatusCode::NOT_FOUND,
            "Not Found",
            "OpenAPI schema endpoint is disabled on this instance.",
            Some("/openapi.json".to_string()),
        );
    }
    Json(build_branded_openapi_schema()).into_response()
}

async fn handle_brand_asset(State(state): State<AppState>, Path(asset): Path<String>) -> Response {
    match resolve_brand_asset(&state.settings.assets_dir, &asset) {
        Some((bytes, content_type)) => {
            let mut resp = Response::new(Body::from(bytes));
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
            resp.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            );
            resp
        }
        None => problem_response(
            StatusCode::NOT_FOUND,
            "Not Found",
            format!("Asset '{asset}' not found."),
            Some(format!("/docs/assets/{asset}")),
        ),
    }
}

async fn handle_health_live() -> impl IntoResponse {
    Json(HealthLiveResponse {
        status: "ok".to_string(),
        service: "dgspamguard".to_string(),
        version: APP_VERSION.to_string(),
    })
}

async fn handle_health_ready(State(state): State<AppState>) -> Response {
    match state.db.readiness().await {
        Ok(ready_resp) => {
            let status = if ready_resp.status == "ready" {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (status, Json(ready_resp)).into_response()
        }
        Err(err) => map_dgspamguard_error(err, Some("/healthz/ready".to_string())),
    }
}

async fn handle_domain_lookup(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Response {
    let inst = Some(format!("/v1/domain/{domain}"));
    match state.db.lookup_domain(&domain).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, inst),
    }
}

async fn handle_url_check(State(state): State<AppState>, req: Request) -> Response {
    let (bytes, path) = match read_bounded_body(req, MAX_JSON_BODY_BYTES).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let payload: UrlCheckRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                format!("Invalid JSON payload: {e}"),
                Some(path),
            )
        }
    };
    match state.db.lookup_url(&payload.url).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, Some(path)),
    }
}

async fn handle_ip_lookup(State(state): State<AppState>, Path(ip): Path<String>) -> Response {
    let inst = Some(format!("/v1/ip/{ip}"));
    match state.db.lookup_ip(&ip).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, inst),
    }
}

async fn handle_hash_lookup(State(state): State<AppState>, Path(sha256): Path<String>) -> Response {
    let inst = Some(format!("/v1/hash/{sha256}"));
    match state.db.lookup_hash(&sha256).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, inst),
    }
}

async fn handle_batch_check(State(state): State<AppState>, req: Request) -> Response {
    let (bytes, path) = match read_bounded_body(req, MAX_JSON_BODY_BYTES).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let payload: BatchCheckRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                format!("Invalid JSON payload: {e}"),
                Some(path),
            )
        }
    };
    if payload.items.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "Batch 'items' array must contain at least 1 indicator.",
            Some(path),
        );
    }
    if payload.items.len() > MAX_BATCH_ITEMS {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            format!(
                "Batch size {} exceeds maximum of {MAX_BATCH_ITEMS}.",
                payload.items.len()
            ),
            Some(path),
        );
    }

    match state.db.lookup_batch(&payload.items).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, Some(path)),
    }
}

async fn handle_list_snapshots(State(state): State<AppState>) -> Response {
    match state.db.list_snapshots().await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, Some("/v1/snapshots".to_string())),
    }
}

async fn handle_latest_snapshot(State(state): State<AppState>) -> Response {
    match state.db.get_snapshot_detail("latest").await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, Some("/v1/snapshots/latest".to_string())),
    }
}

async fn handle_get_snapshot(
    State(state): State<AppState>,
    Path(version): Path<String>,
) -> Response {
    let inst = Some(format!("/v1/snapshots/{version}"));
    match state.db.get_snapshot_detail(&version).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => map_dgspamguard_error(err, inst),
    }
}

async fn handle_download_bundle(
    State(state): State<AppState>,
    method: Method,
    Path(version): Path<String>,
    headers: HeaderMap,
) -> Response {
    stream_snapshot_artifact(&state, method, &version, "bundle.tar.gz", &headers).await
}

async fn handle_download_file(
    State(state): State<AppState>,
    method: Method,
    Path((version, filename)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    stream_snapshot_artifact(&state, method, &version, &filename, &headers).await
}

async fn stream_snapshot_artifact(
    state: &AppState,
    method: Method,
    version: &str,
    filename: &str,
    req_headers: &HeaderMap,
) -> Response {
    let inst = Some(format!("/v1/snapshots/{version}/files/{filename}"));
    let meta = match state.db.get_artifact_meta(version, filename).await {
        Ok(m) => m,
        Err(err) => return map_dgspamguard_error(err, inst),
    };

    let etag_val = format!("\"{}\"", meta.sha256);
    if let Some(inm) = req_headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        let matched = inm.split(',').any(|item| {
            let trimmed = item.trim();
            trimmed == "*" || trimmed == etag_val || trimmed == meta.sha256
        });
        if matched {
            let mut not_mod = Response::new(Body::empty());
            *not_mod.status_mut() = StatusCode::NOT_MODIFIED;
            if let Ok(hv) = HeaderValue::from_str(&etag_val) {
                not_mod.headers_mut().insert(ETAG, hv);
            }
            return not_mod;
        }
    }

    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        let artifact = match state.db.materialize_artifact(&meta).await {
            Ok(a) => a,
            Err(err) => return map_dgspamguard_error(err, inst),
        };
        match artifact.source {
            ArtifactSource::CachedFile(path) => match tokio::fs::File::open(&path).await {
                Ok(file) => Body::from_stream(ReaderStream::new(file)),
                Err(_) => match state.db.fetch_artifact_bytes(&meta.version, &meta.filename).await {
                    Ok(bytes) => Body::from(bytes),
                    Err(err) => return map_dgspamguard_error(err, inst),
                },
            },
            ArtifactSource::InMemory(bytes) => Body::from(bytes),
        }
    };

    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    if let Ok(ct) = HeaderValue::from_str(&meta.content_type) {
        h.insert(CONTENT_TYPE, ct);
    }
    if let Ok(cl) = HeaderValue::from_str(&meta.size_bytes.to_string()) {
        h.insert(CONTENT_LENGTH, cl);
    }
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", meta.filename))
    {
        h.insert(CONTENT_DISPOSITION, disp);
    }
    if let Ok(ev) = HeaderValue::from_str(&etag_val) {
        h.insert(ETAG, ev);
    }
    if let Ok(sha_hv) = HeaderValue::from_str(&meta.sha256) {
        h.insert(HeaderName::from_static("x-checksum-sha256"), sha_hv);
    }
    let cache_hdr = if version == "latest" {
        "public, max-age=300"
    } else {
        "public, max-age=604800, immutable"
    };
    h.insert(CACHE_CONTROL, HeaderValue::from_static(cache_hdr));
    resp
}

async fn handle_not_found(req: Request) -> Response {
    let _ = BodyExt::collect(req.into_body()).await;
    problem_response(
        StatusCode::NOT_FOUND,
        "Not Found",
        "The requested endpoint does not exist.",
        None,
    )
}
