//! Browser feedback for the loopback callback. A code is not a completed login:
//! the caller reports success only after it has persisted the credentials.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server;
use tokio::sync::oneshot;

use super::CallbackOutcome;
use super::CallbackResult;
use super::parse_oauth_callback;

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
    fn response(self) -> Response<Cursor<Vec<u8>>> {
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
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <title>{title}</title>\n{refresh}\n</head>\n<body>\n\
             <h1>{title}</h1>\n<p>{message}</p>\n</body>\n</html>\n"
        ))
        .with_status_code(status);
        for (name, value) in [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            (
                "Content-Security-Policy",
                "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
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
                    let _ = request.respond(CallbackPage::Invalid.response());
                    continue;
                }
            };
            let _ = request.respond(CallbackPage::Pending.response());
            let _ = tx.send(callback);

            // Dropping the login or its uncommitted credentials is a failure,
            // never a successful browser login. No provider text is rendered.
            let page = result.blocking_recv().unwrap_or(CallbackPage::Failure);
            let deadline = Instant::now() + RESULT_DELIVERY_TIMEOUT;
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                match server.recv_timeout(remaining) {
                    Ok(Some(request)) if request.url() == result_path => {
                        let _ = request.respond(page.response());
                        break;
                    }
                    Ok(Some(request)) => {
                        let _ = request.respond(CallbackPage::Invalid.response());
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
