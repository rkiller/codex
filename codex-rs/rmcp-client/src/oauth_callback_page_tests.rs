use super::super::*;
use super::*;
use crate::oauth::RefreshCredentialLock;
use crate::oauth::stored_oauth_credentials;
use crate::oauth::test_support::TempCodexHome;
use codex_exec_server::RouteAwareHttpClient;
use codex_http_client::HttpClientFactory;
use codex_http_client::OutboundProxyPolicy;
use oauth2::TokenResponse;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

async fn request(server: &Server, path: &str) -> String {
    let address = server.server_addr().to_ip().unwrap();
    let path = path.to_string();
    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    })
    .await
    .unwrap()
}

fn html(response: &str) -> String {
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let headers = headers.to_ascii_lowercase();
    assert!(headers.contains("content-type: text/html; charset=utf-8"));
    assert!(headers.contains("cache-control: no-store"));
    assert!(headers.contains("referrer-policy: no-referrer"));
    body.replace(STYLE, "[shared callback stylesheet]")
}

#[tokio::test]
async fn callback_renders_html_without_claiming_success_before_exchange() {
    let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
    let _guard = CallbackServerGuard {
        server: Arc::clone(&server),
    };
    let (tx, rx) = oneshot::channel();
    let completion = spawn_callback_server(
        Arc::clone(&server),
        tx,
        "/callback/server".to_string(),
        CallbackBrand::Codex,
    );
    let invalid = request(&server, "/wrong?code=synthetic-code&state=synthetic-state").await;
    assert!(invalid.starts_with("HTTP/1.1 400"));
    insta::assert_snapshot!("invalid_callback", html(&invalid));
    let response = request(
        &server,
        "/callback/server?code=synthetic-code&state=synthetic-state",
    )
    .await;
    insta::assert_snapshot!("pending_callback", html(&response));
    assert!(!response.contains("Authentication complete"));
    assert!(!response.contains("synthetic-code"));
    assert!(!response.contains("synthetic-state"));
    assert!(matches!(rx.await.unwrap(), CallbackResult::Success(_)));
    let ((), response) = tokio::join!(
        completion.finish(&Ok(())),
        request(&server, "/callback/server?codex_oauth_result=1")
    );
    assert!(response.starts_with("HTTP/1.1 200"));
    insta::assert_snapshot!("successful_callback", html(&response));
}

#[tokio::test]
async fn callback_failure_and_cancellation_do_not_render_provider_input() {
    for cancelled in [false, true] {
        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let _guard = CallbackServerGuard {
            server: Arc::clone(&server),
        };
        let (tx, rx) = oneshot::channel();
        let completion = spawn_callback_server(
            Arc::clone(&server),
            tx,
            "/callback".to_string(),
            CallbackBrand::Codex,
        );
        let pending = request(
            &server,
            "/callback?error=secret&error_description=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        )
        .await;
        assert!(!html(&pending).contains("secret"));
        assert!(matches!(rx.await.unwrap(), CallbackResult::Error(_)));
        let response = if cancelled {
            drop(completion);
            request(&server, "/callback?codex_oauth_result=1").await
        } else {
            let failure = Err(anyhow!("secret <script>alert(1)</script>"));
            let ((), response) = tokio::join!(
                completion.finish(&failure),
                request(&server, "/callback?codex_oauth_result=1")
            );
            response
        };
        assert!(response.starts_with("HTTP/1.1 400"));
        insta::assert_snapshot!("failed_callback", html(&response));
        assert!(!response.contains("secret"));
        assert!(!response.contains("<script>"));
    }
}

async fn login_fixture(token_response: ResponseTemplate) -> (MockServer, OauthLoginFlow, String) {
    let provider = MockServer::start().await;
    let issuer = format!("{}/mcp", provider.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/authorize", provider.uri()),
            "token_endpoint": format!("{}/token", provider.uri()),
            "authorization_response_iss_parameter_supported": true,
        })))
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response)
        .mount(&provider)
        .await;
    let flow = OauthLoginFlow::new(
        "callback-test",
        &issuer,
        OAuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
        OAuthHttpContext {
            http_headers: None,
            env_http_headers: None,
            http_client: Arc::new(RouteAwareHttpClient::new(HttpClientFactory::new(
                OutboundProxyPolicy::ReqwestDefault,
            ))),
            redirect_mode: StreamableHttpRedirectMode::Legacy,
        },
        &[],
        Some("synthetic-client"),
        OAuthLoginPurpose::Mcp,
        McpOAuthClientRegistration::Auto,
        /*oauth_resource*/ None,
        /*launch_browser*/ false,
        /*callback_port*/ None,
        /*callback_url*/ None,
        /*global_callback_url*/ None,
        Some(/*timeout_secs*/ 5),
    )
    .await
    .unwrap();
    let auth = Url::parse(&flow.authorization_url()).unwrap();
    let params: HashMap<_, _> = auth.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let mut callback = Url::parse(&params["redirect_uri"]).unwrap();
    assert_eq!(callback.host_str(), Some("127.0.0.1"));
    callback
        .query_pairs_mut()
        .append_pair("code", "synthetic-code")
        .append_pair("state", &params["state"])
        .append_pair("iss", &issuer);
    let callback = format!("{}?{}", callback.path(), callback.query().unwrap());
    (provider, flow, callback)
}

#[tokio::test]
async fn browser_success_waits_for_credential_persistence() {
    let _home = TempCodexHome::new();
    let (provider, flow, callback) =
        login_fixture(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "synthetic-token", "token_type": "Bearer"
        })))
        .await;
    let server_url = format!("{}/mcp", provider.uri());
    let lock = RefreshCredentialLock::acquire_for_server("callback-test", &server_url)
        .await
        .unwrap();
    let server = Arc::clone(&flow.guard.server);
    let result_path = format!(
        "{}?codex_oauth_result=1",
        callback.split_once('?').unwrap().0
    );
    let mut login = flow.spawn();
    let pending = request(&server, &callback).await;
    assert!(html(&pending).contains("Completing authentication"));
    let mut browser = Box::pin(request(&server, &result_path));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut browser)
            .await
            .is_err()
    );
    assert!(matches!(
        login.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(lock);
    let response = browser.await;
    assert!(html(&response).contains("Authentication complete"));
    login.await.unwrap().unwrap();
    let stored = stored_oauth_credentials(
        "callback-test",
        &server_url,
        OAuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        stored.token_response.0.access_token().secret(),
        "synthetic-token"
    );
    let requests = provider.received_requests().await.unwrap();
    let token = requests.iter().find(|r| r.url.path() == "/token").unwrap();
    let params: HashMap<_, _> = url::form_urlencoded::parse(&token.body)
        .into_owned()
        .collect();
    assert!(params.contains_key("code_verifier"));
}

#[tokio::test]
async fn browser_reports_exchange_validation_and_storage_failures() {
    for failure in ["token", "state", "issuer", "storage"] {
        let _home = TempCodexHome::new();
        let token_response = if failure == "token" {
            ResponseTemplate::new(400).set_body_json(
                json!({"error": "invalid_grant", "error_description": "synthetic-secret <script>"}),
            )
        } else {
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": "synthetic-token", "token_type": "Bearer"}))
        };
        let (provider, flow, mut callback) = login_fixture(token_response).await;
        let server_url = format!("{}/mcp", provider.uri());
        let server = Arc::clone(&flow.guard.server);
        let result_path = format!(
            "{}?codex_oauth_result=1",
            callback.split_once('?').unwrap().0
        );
        match failure {
            "state" => callback.push_str("&state=wrong-state"),
            "issuer" => callback.push_str("&iss=https%3A%2F%2Fwrong.example"),
            "storage" => {
                let home = std::path::PathBuf::from(std::env::var_os("CODEX_HOME").unwrap());
                std::fs::create_dir(home.join(".credentials.json")).unwrap();
            }
            "token" => {}
            _ => unreachable!(),
        }
        let login = flow.spawn();
        let pending = request(&server, &callback).await;
        assert!(!html(&pending).contains("Authentication complete"));
        let response = request(&server, &result_path).await;
        assert!(html(&response).contains("Authentication failed"));
        assert!(!response.contains("synthetic-"));
        assert!(!response.contains("<script>"));
        assert!(login.await.unwrap().is_err());
        let requests = provider.received_requests().await.unwrap();
        let expected = usize::from(matches!(failure, "token" | "storage"));
        assert_eq!(
            requests.iter().filter(|r| r.url.path() == "/token").count(),
            expected
        );
        if failure != "storage" {
            assert!(
                stored_oauth_credentials(
                    "callback-test",
                    &server_url,
                    OAuthCredentialsStoreMode::File,
                    AuthKeyringBackendKind::Direct
                )
                .unwrap()
                .is_none()
            );
        }
    }
}

#[test]
fn syntropic_branding_is_scoped_and_embedded_in_every_status() {
    assert_eq!(
        CallbackBrand::for_server_url("https://platform.syntropic.com/mcp"),
        CallbackBrand::Syntropic
    );
    assert_eq!(
        CallbackBrand::for_server_url("https://platform.syntropic.com.example/mcp"),
        CallbackBrand::Codex
    );
    assert_eq!(
        CallbackBrand::for_server_url("https://other.example/mcp"),
        CallbackBrand::Codex
    );
    let logo = format!("data:image/png;base64,{}", STANDARD.encode(SYNTROPIC_LOGO));
    let style_hash = STANDARD.encode(sha2::Sha256::digest(STYLE.as_bytes()));
    let mut rendered = Vec::new();
    for (name, page) in [
        ("pending", CallbackPage::Pending),
        ("success", CallbackPage::Success),
        ("failure", CallbackPage::Failure),
        ("invalid", CallbackPage::Invalid),
    ] {
        let response = page.response(CallbackBrand::Syntropic);
        let csp = response
            .headers()
            .iter()
            .find(|header| header.field.equiv("Content-Security-Policy"))
            .unwrap()
            .value
            .as_str();
        assert!(csp.contains(&format!("style-src 'sha256-{style_hash}'")));
        assert!(csp.contains("img-src data:"));
        let mut body = String::new();
        response.into_reader().read_to_string(&mut body).unwrap();
        assert!(body.contains(&logo));
        assert!(body.contains("alt=\"Syntropic logo\""));
        let body = body
            .replace(STYLE, "[shared callback stylesheet]")
            .replace(&logo, "[embedded Syntropic logo]");
        rendered.push(format!("--- {name} ---\n{body}"));
    }
    insta::assert_snapshot!("syntropic_status_pages", rendered.join("\n"));
}
