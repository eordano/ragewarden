use ragewarden_core::http_reqwest::ReqwestClient as Inner;
use ragewarden_core::sync::HttpError;

#[derive(Clone)]
pub struct ReqwestClient(Inner);

impl ReqwestClient {
    pub fn new() -> Result<Self, HttpError> {
        Inner::new(&format!("rageterm/{}", env!("CARGO_PKG_VERSION"))).map(Self)
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new().expect("rustls client should always build")
    }
}

impl std::ops::Deref for ReqwestClient {
    type Target = Inner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait::async_trait]
impl ragewarden_core::sync::HttpClient for ReqwestClient {
    async fn post(
        &self,
        url: &str,
        body: ragewarden_core::sync::HttpBody,
        headers: &[(String, String)],
    ) -> Result<ragewarden_core::sync::HttpResponse, HttpError> {
        self.0.post(url, body, headers).await
    }
    async fn put(
        &self,
        url: &str,
        body: ragewarden_core::sync::HttpBody,
        headers: &[(String, String)],
    ) -> Result<ragewarden_core::sync::HttpResponse, HttpError> {
        self.0.put(url, body, headers).await
    }
    async fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<ragewarden_core::sync::HttpResponse, HttpError> {
        self.0.get(url, headers).await
    }
    async fn delete(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<ragewarden_core::sync::HttpResponse, HttpError> {
        self.0.delete(url, headers).await
    }
}
