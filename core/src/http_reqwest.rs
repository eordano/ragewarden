use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};

use crate::sync::{is_secure_url, HttpBody, HttpClient, HttpError, HttpResponse};

#[derive(Clone)]
pub struct ReqwestClient {
    inner: reqwest::Client,
}

impl ReqwestClient {
    pub fn new(user_agent: &str) -> Result<Self, HttpError> {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            HeaderName::from_static("bitwarden-client-version"),
            HeaderValue::from_static("2025.1.0"),
        );
        default_headers.insert(
            HeaderName::from_static("bitwarden-client-name"),
            HeaderValue::from_static("rageterm"),
        );
        let inner = reqwest::Client::builder()
            .user_agent(user_agent.to_string())
            .default_headers(default_headers)
            .connect_timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                // A 30x from https:// to http:// would otherwise replay the
                // Authorization header in cleartext. reqwest only strips
                // sensitive headers across a host change, so a same-host
                // scheme downgrade has to be refused here.
                if is_secure_url(attempt.url().as_str()) {
                    if attempt.previous().len() >= 10 {
                        attempt.error("too many redirects")
                    } else {
                        attempt.follow()
                    }
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|e| HttpError::Transport(format!("client build: {e}")))?;
        Ok(Self { inner })
    }
}

/// Last line of defence: this transport refuses a plaintext non-loopback URL
/// even if something outside `sync.rs` hands it one.
fn guard(url: &str) -> Result<(), HttpError> {
    if is_secure_url(url) {
        Ok(())
    } else {
        Err(HttpError::Transport(format!(
            "refusing to send to an insecure URL: {url}"
        )))
    }
}

fn header_map(headers: &[(String, String)]) -> Result<HeaderMap, HttpError> {
    let mut map = HeaderMap::new();
    for (k, v) in headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| HttpError::Transport(format!("header name {k:?}: {e}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|e| HttpError::Transport(format!("header value for {k:?}: {e}")))?;
        map.insert(name, value);
    }
    Ok(map)
}

async fn execute(req: reqwest::RequestBuilder) -> Result<HttpResponse, HttpError> {
    let res = req
        .send()
        .await
        .map_err(|e| HttpError::Transport(format!("send: {e}")))?;
    let status = res.status().as_u16();
    let body = res
        .bytes()
        .await
        .map_err(|e| HttpError::Decode(format!("body: {e}")))?
        .to_vec();
    Ok(HttpResponse { status, body })
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn post(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        guard(url)?;
        let mut headers = header_map(headers)?;
        let req = self.inner.post(url);
        let req = match body {
            HttpBody::Json(b) => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                req.body(b)
            }
            HttpBody::Form(b) => {
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
                req.body(b)
            }
        };
        execute(req.headers(headers)).await
    }

    async fn put(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        guard(url)?;
        let mut headers = header_map(headers)?;
        let req = self.inner.put(url);
        let req = match body {
            HttpBody::Json(b) => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                req.body(b)
            }
            HttpBody::Form(b) => {
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
                req.body(b)
            }
        };
        execute(req.headers(headers)).await
    }

    async fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        guard(url)?;
        let headers = header_map(headers)?;
        let req = self.inner.get(url).headers(headers);
        execute(req).await
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        guard(url)?;
        let headers = header_map(headers)?;
        let req = self.inner.delete(url).headers(headers);
        execute(req).await
    }
}
