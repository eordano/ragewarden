use async_trait::async_trait;
use ragewarden_core::sync::{HttpBody, HttpClient, HttpError, HttpResponse};
use send_wrapper::SendWrapper;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

pub(crate) struct JsHttpClient;

impl JsHttpClient {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HttpClient for JsHttpClient {
    async fn post(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let url = url.to_string();
        let headers = headers.to_vec();
        SendWrapper::new(do_request("POST", url, Some(body), headers)).await
    }

    async fn put(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let url = url.to_string();
        let headers = headers.to_vec();
        SendWrapper::new(do_request("PUT", url, Some(body), headers)).await
    }

    async fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let url = url.to_string();
        let headers = headers.to_vec();
        SendWrapper::new(do_request("GET", url, None, headers)).await
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let url = url.to_string();
        let headers = headers.to_vec();
        SendWrapper::new(do_request("DELETE", url, None, headers)).await
    }
}

async fn do_request(
    method: &'static str,
    url: String,
    body: Option<HttpBody>,
    headers: Vec<(String, String)>,
) -> Result<HttpResponse, HttpError> {
    let init = RequestInit::new();
    init.set_method(method);

    let header_obj = web_sys::Headers::new()
        .map_err(|e| HttpError::Transport(format!("Headers::new: {}", js_err_msg(&e))))?;

    if let Some(body) = body.as_ref() {
        let ct = match body {
            HttpBody::Json(_) => "application/json",
            HttpBody::Form(_) => "application/x-www-form-urlencoded",
        };
        header_obj
            .set("content-type", ct)
            .map_err(|e| HttpError::Transport(format!("set content-type: {}", js_err_msg(&e))))?;
    }
    // Vaultwarden and Bitwarden withhold SSH key items from a client that does not
    // say it is new enough to read them; rageterm sends the same pair.
    let client_headers = [
        ("bitwarden-client-version", "2025.1.0"),
        ("bitwarden-client-name", "ragemanifest"),
    ];
    let pairs = client_headers
        .iter()
        .map(|(k, v)| (*k, *v))
        .chain(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    for (k, v) in pairs {
        header_obj
            .set(k, v)
            .map_err(|e| HttpError::Transport(format!("set {k}: {}", js_err_msg(&e))))?;
    }
    init.set_headers(&header_obj);

    if let Some(body) = body {
        let bytes: &[u8] = match &body {
            HttpBody::Json(b) | HttpBody::Form(b) => b,
        };
        let buf = js_sys::Uint8Array::from(bytes);
        init.set_body(&buf);
    }

    let req = Request::new_with_str_and_init(&url, &init)
        .map_err(|e| HttpError::Transport(format!("Request::new: {}", js_err_msg(&e))))?;

    let global = js_sys::global();
    let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|e| HttpError::Transport(format!("global.fetch lookup: {}", js_err_msg(&e))))?;
    let fetch_fn: js_sys::Function = fetch_fn
        .dyn_into()
        .map_err(|_| HttpError::Transport("global.fetch is not a function".into()))?;

    let promise = fetch_fn
        .call1(&global, req.as_ref())
        .map_err(|e| HttpError::Transport(format!("fetch call: {}", js_err_msg(&e))))?;
    let promise: js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| HttpError::Transport("fetch did not return a Promise".into()))?;

    let resp_value = JsFuture::from(promise)
        .await
        .map_err(|e| HttpError::Transport(format!("fetch await: {}", js_err_msg(&e))))?;
    let response: Response = resp_value
        .dyn_into()
        .map_err(|_| HttpError::Decode("fetch result not a Response".into()))?;

    let status = response.status();

    let buf_promise = response
        .array_buffer()
        .map_err(|e| HttpError::Decode(format!("array_buffer call: {}", js_err_msg(&e))))?;
    let buf_value = JsFuture::from(buf_promise)
        .await
        .map_err(|e| HttpError::Decode(format!("array_buffer await: {}", js_err_msg(&e))))?;
    let array = js_sys::Uint8Array::new(&buf_value);
    let mut body_out = vec![0u8; array.length() as usize];
    array.copy_to(&mut body_out);

    Ok(HttpResponse {
        status,
        body: body_out,
    })
}

fn js_err_msg(v: &JsValue) -> String {
    if let Some(s) = v.as_string() {
        return s;
    }
    if let Some(err) = v.dyn_ref::<js_sys::Error>() {
        return err.message().into();
    }
    format!("{v:?}")
}
