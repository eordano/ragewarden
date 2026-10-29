use std::sync::{Arc, Mutex};

use ragewarden_core::http_reqwest::ReqwestClient as Inner;
use ragewarden_core::sync::{HttpBody, HttpClient, HttpError, HttpResponse, Server, Session};

/// Where the client finds and stores the session it refreshes.
pub trait SessionStore: Send + Sync {
    fn load(&self) -> Option<(Server, Session)>;
    fn save(&self, server: &Server, session: &Session);
}

struct DiskSessions;

impl SessionStore for DiskSessions {
    fn load(&self) -> Option<(Server, Session)> {
        crate::session::load()
            .ok()
            .flatten()
            .map(|o| (o.server, o.session))
    }
    fn save(&self, server: &Server, session: &Session) {
        if let Err(e) = crate::session::save(server, session) {
            eprintln!("rageterm: refreshed the session but could not save it ({e})");
        }
    }
}

/// An HTTP client that answers an expired access token itself: a 401 on a
/// request that carried a bearer token refreshes the saved session once
/// (`refresh_session`), saves it, and retries; later requests in the same
/// process that still carry the old token are sent with the new one.
pub struct Refreshing<C> {
    inner: C,
    store: Arc<dyn SessionStore>,
    swapped: Arc<Mutex<Option<(String, String)>>>,
}

impl<C: Clone> Clone for Refreshing<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            store: self.store.clone(),
            swapped: self.swapped.clone(),
        }
    }
}

const AUTHORIZATION: &str = "Authorization";

fn bearer(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(AUTHORIZATION))
        .map(|(_, v)| v.as_str())
}

fn with_bearer(headers: &[(String, String)], value: &str) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if k.eq_ignore_ascii_case(AUTHORIZATION) {
                (k.clone(), value.to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

enum Op {
    Post(HttpBody),
    Put(HttpBody),
    Get,
    Delete,
}

impl<C: HttpClient> Refreshing<C> {
    pub fn with_store(inner: C, store: Arc<dyn SessionStore>) -> Self {
        Self {
            inner,
            store,
            swapped: Arc::new(Mutex::new(None)),
        }
    }

    fn current(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let swapped = self.swapped.lock().unwrap_or_else(|e| e.into_inner());
        match (&*swapped, bearer(headers)) {
            (Some((old, new)), Some(b)) if b == old => with_bearer(headers, new),
            _ => headers.to_vec(),
        }
    }

    async fn send(
        &self,
        url: &str,
        op: &Op,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        match op {
            Op::Post(b) => self.inner.post(url, b.clone(), headers).await,
            Op::Put(b) => self.inner.put(url, b.clone(), headers).await,
            Op::Get => self.inner.get(url, headers).await,
            Op::Delete => self.inner.delete(url, headers).await,
        }
    }

    /// The bearer header to retry with, refreshing the stored session unless
    /// another process already did.
    async fn refreshed_bearer(&self, stale: &str) -> Option<String> {
        let (server, mut session) = self.store.load()?;
        if session.bearer() == stale {
            ragewarden_core::sync::refresh_session(&self.inner, &server, &mut session)
                .await
                .ok()?;
            self.store.save(&server, &session);
        }
        let fresh = session.bearer();
        *self.swapped.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((stale.to_string(), fresh.clone()));
        Some(fresh)
    }

    async fn call(
        &self,
        url: &str,
        op: Op,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let headers = self.current(headers);
        let res = self.send(url, &op, &headers).await?;
        if res.status != 401 {
            return Ok(res);
        }
        let Some(stale) = bearer(&headers).map(str::to_string) else {
            return Ok(res);
        };
        match self.refreshed_bearer(&stale).await {
            Some(fresh) if fresh != stale => {
                self.send(url, &op, &with_bearer(&headers, &fresh)).await
            }
            _ => Ok(res),
        }
    }
}

#[async_trait::async_trait]
impl<C: HttpClient> HttpClient for Refreshing<C> {
    async fn post(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.call(url, Op::Post(body), headers).await
    }
    async fn put(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.call(url, Op::Put(body), headers).await
    }
    async fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.call(url, Op::Get, headers).await
    }
    async fn delete(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.call(url, Op::Delete, headers).await
    }
}

pub type ReqwestClient = Refreshing<Inner>;

impl Refreshing<Inner> {
    pub fn new() -> Result<Self, HttpError> {
        Ok(Self::with_store(
            Inner::new(&format!("rageterm/{}", env!("CARGO_PKG_VERSION")))?,
            Arc::new(DiskSessions),
        ))
    }
}

impl Default for Refreshing<Inner> {
    fn default() -> Self {
        Self::new().expect("rustls client should always build")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct FakeServer {
        log: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeServer {
        async fn post(
            &self,
            url: &str,
            _b: HttpBody,
            h: &[(String, String)],
        ) -> Result<HttpResponse, HttpError> {
            if url.ends_with("/connect/token") {
                self.log.lock().unwrap().push(format!("POST {url}"));
                return Ok(HttpResponse {
                    status: 200,
                    body: br#"{"access_token":"fresh","refresh_token":"r2"}"#.to_vec(),
                });
            }
            self.get(url, h).await
        }
        async fn put(
            &self,
            url: &str,
            _b: HttpBody,
            h: &[(String, String)],
        ) -> Result<HttpResponse, HttpError> {
            self.get(url, h).await
        }
        async fn get(&self, url: &str, h: &[(String, String)]) -> Result<HttpResponse, HttpError> {
            let b = bearer(h).unwrap_or("").to_string();
            self.log.lock().unwrap().push(format!("{url} {b}"));
            Ok(HttpResponse {
                status: if b == "Bearer fresh" { 200 } else { 401 },
                body: b"{}".to_vec(),
            })
        }
        async fn delete(
            &self,
            url: &str,
            h: &[(String, String)],
        ) -> Result<HttpResponse, HttpError> {
            self.get(url, h).await
        }
    }

    struct Memory(Mutex<(Server, Session)>, Mutex<usize>);

    impl SessionStore for Memory {
        fn load(&self) -> Option<(Server, Session)> {
            Some(self.0.lock().unwrap().clone())
        }
        fn save(&self, server: &Server, session: &Session) {
            *self.0.lock().unwrap() = (server.clone(), session.clone());
            *self.1.lock().unwrap() += 1;
        }
    }

    fn session(token: &str) -> Session {
        Session {
            access_token: ragewarden_core::BearerToken::from_trusted(token.into()),
            refresh_token: ragewarden_core::RefreshToken::from_trusted("r1".into()),
            user_id: "u".into(),
            email: "e@x".into(),
            user_enc_key: vec![0u8; 32].into(),
            user_mac_key: vec![0u8; 32].into(),
            kdf: Default::default(),
            device_id: "d".into(),
        }
    }

    #[test]
    fn a_401_refreshes_once_saves_and_later_calls_reuse_the_new_token() {
        let server = Server::self_hosted("https://vault.test");
        let store = Arc::new(Memory(Mutex::new((server, session("old"))), Mutex::new(0)));
        let fake = FakeServer::default();
        let client = Refreshing::with_store(fake.clone(), store.clone());
        let old = vec![(AUTHORIZATION.to_string(), "Bearer old".to_string())];
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r1 = rt
            .block_on(client.get("https://vault.test/api/sync", &old))
            .unwrap();
        let r2 = rt
            .block_on(client.get("https://vault.test/api/sync", &old))
            .unwrap();
        assert_eq!((r1.status, r2.status), (200, 200));
        assert_eq!(*store.1.lock().unwrap(), 1, "exactly one refresh is saved");
        assert_eq!(store.0.lock().unwrap().1.bearer(), "Bearer fresh");
        let log = fake.log.lock().unwrap().clone();
        assert_eq!(
            log.iter().filter(|l| l.ends_with("/connect/token")).count(),
            1
        );
        assert_eq!(
            log.last().unwrap(),
            "https://vault.test/api/sync Bearer fresh"
        );
    }

    #[test]
    fn a_401_without_a_bearer_is_returned_as_is() {
        let server = Server::self_hosted("https://vault.test");
        let store = Arc::new(Memory(Mutex::new((server, session("old"))), Mutex::new(0)));
        let client = Refreshing::with_store(FakeServer::default(), store.clone());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r = rt
            .block_on(client.get("https://vault.test/x", &[]))
            .unwrap();
        assert_eq!(r.status, 401);
        assert_eq!(*store.1.lock().unwrap(), 0);
    }
}
