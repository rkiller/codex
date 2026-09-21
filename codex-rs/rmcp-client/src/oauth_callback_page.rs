//! Browser feedback for the loopback callback. A code is not a completed login:
//! the caller reports success only after it has persisted the credentials.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::Digest;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server;
use tokio::sync::oneshot;

use super::CallbackOutcome;
use super::CallbackResult;
use super::parse_oauth_callback;

const STYLE: &str = include_str!("oauth_callback_assets/page.css");
const SYNTROPIC_LOGO: &[u8] = include_bytes!("oauth_callback_assets/syntropic.png");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackBrand {
    Codex,
    Syntropic,
}

impl CallbackBrand {
    pub(crate) fn for_server_url(server_url: &str) -> Self {
        if url::Url::parse(server_url).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str() == Some("platform.syntropic.com")
                && url.path().trim_end_matches('/') == "/mcp"
        }) {
            Self::Syntropic
        } else {
            Self::Codex
        }
    }
}

const RESULT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct CallbackCompletion {
    outcome: oneshot::Sender<CallbackPage>,
    delivered: oneshot::Receiver<()>,
}

impl CallbackCompletion {
    pub(crate) async fn finish(self, result: &anyhow::Result<()>) {
        let page = if result.is_ok() {
            CallbackPage::Success
        } else {
            CallbackPage::Failure
        };
        let _ = self.outcome.send(page);
        // Let the browser read the result before a CLI process exits, but do not
        // prevent login if the user closed the tab or did not follow the refresh.
        let _ = tokio::time::timeout(RESULT_DELIVERY_TIMEOUT, self.delivered).await;
    }

    pub(crate) fn success(self) {
        let _ = self.outcome.send(CallbackPage::Success);
    }
}

enum CallbackPage {
    Pending,
    Success,
    Failure,
    Invalid,
}

impl CallbackPage {
    fn response(self, brand: CallbackBrand) -> Response<Cursor<Vec<u8>>> {
        let (state_class, status_label, step_mark, next_step) = match self {
            Self::Pending => (
                "pending",
                "CONNECTING",
                "…",
                "This page will update automatically.",
            ),
            Self::Success => (
                "success",
                "CONNECTED",
                "✓",
                "Return to Codex whenever you are ready.",
            ),
            Self::Failure => (
                "failure",
                "ACTION NEEDED",
                "↗",
                "Start a new sign-in from Codex.",
            ),
            Self::Invalid => (
                "invalid",
                "CHECK REQUEST",
                "↗",
                "Use the sign-in link provided by Codex.",
            ),
        };
        let (brand_name, artwork) = match brand {
            CallbackBrand::Syntropic => (
                "Syntropic",
                format!(
                    "<img class=\"logo\" src=\"data:image/png;base64,{}\" width=\"1024\" height=\"1024\" alt=\"Syntropic logo\">",
                    STANDARD.encode(SYNTROPIC_LOGO)
                ),
            ),
            CallbackBrand::Codex => (
                "Codex",
                "<span class=\"codex-mark\" aria-hidden=\"true\">&gt;_</span>".to_string(),
            ),
        };
        let (title, message, refresh, status) = match self {
            Self::Pending => (
                "Completing authentication",
                "Please wait while Codex verifies and saves your credentials.",
                "<meta http-equiv=\"refresh\" content=\"1;url=?codex_oauth_result=1\">",
                200,
            ),
            Self::Success => (
                "Authentication complete",
                "Your credentials have been saved. You may close this window.",
                "",
                200,
            ),
            Self::Failure => (
                "Authentication failed",
                "Codex could not complete authentication. Return to Codex and try again.",
                "",
                400,
            ),
            Self::Invalid => (
                "Invalid OAuth callback",
                "This request does not match the callback. Return to Codex to continue signing in.",
                "",
                400,
            ),
        };
        let mut response = Response::from_string(format!(
            include_str!("oauth_callback_assets/page.html"),
            title = title,
            message = message,
            refresh = refresh,
            style = STYLE,
            brand_name = brand_name,
            artwork = artwork,
            state_class = state_class,
            status_label = status_label,
            step_mark = step_mark,
            next_step = next_step,
        ))
        .with_status_code(status);
        let style_hash = STANDARD.encode(sha2::Sha256::digest(STYLE.as_bytes()));
        let content_security_policy = format!(
            "default-src 'none'; style-src 'sha256-{style_hash}'; img-src data:; base-uri 'none'; frame-ancestors 'none'"
        );
        for (name, value) in [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", content_security_policy.as_str()),
        ] {
            let Ok(header) = Header::from_bytes(name, value) else {
                unreachable!("static callback headers must be valid");
            };
            response.add_header(header);
        }
        response
    }
}

pub(crate) fn spawn_callback_server(
    server: Arc<Server>,
    tx: oneshot::Sender<CallbackResult>,
    expected_callback_path: String,
    brand: CallbackBrand,
) -> CallbackCompletion {
    let (outcome, result) = oneshot::channel();
    let (delivered, delivery) = oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let result_path = format!("{expected_callback_path}?codex_oauth_result=1");
        while let Ok(request) = server.recv() {
            let callback = match parse_oauth_callback(request.url(), &expected_callback_path) {
                CallbackOutcome::Success(callback) => CallbackResult::Success(callback),
                CallbackOutcome::Error(error) => CallbackResult::Error(error),
                CallbackOutcome::Invalid => {
                    let _ = request.respond(CallbackPage::Invalid.response(brand));
                    continue;
                }
            };
            let _ = request.respond(CallbackPage::Pending.response(brand));
            let _ = tx.send(callback);

            // Dropping the login or its uncommitted credentials is a failure,
            // never a successful browser login. No provider text is rendered.
            let page = result.blocking_recv().unwrap_or(CallbackPage::Failure);
            let deadline = Instant::now() + RESULT_DELIVERY_TIMEOUT;
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                match server.recv_timeout(remaining) {
                    Ok(Some(request)) if request.url() == result_path => {
                        let _ = request.respond(page.response(brand));
                        break;
                    }
                    Ok(Some(request)) => {
                        let _ = request.respond(CallbackPage::Invalid.response(brand));
                    }
                    Ok(None) => continue,
                    Err(_) => break,
                }
            }
            let _ = delivered.send(());
            break;
        }
    });
    CallbackCompletion {
        outcome,
        delivered: delivery,
    }
}

#[cfg(test)]
#[path = "oauth_callback_page_tests.rs"]
mod tests;
