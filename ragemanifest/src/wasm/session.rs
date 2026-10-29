use super::js_err;

use crate::snapshot::WireSession;
use ragewarden_core::sync::{Server, Session};
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

pub(crate) fn session_to_jsvalue(server: &Server, session: &Session) -> Result<JsValue, JsValue> {
    let wire = WireSession::from_runtime(server, session);
    serde_wasm_bindgen_serialize(&wire).map_err(|e| js_err(format!("serialize session: {e}")))
}

thread_local! {
    static SESSIONS: RefCell<HashMap<u32, (Server, Session)>> = RefCell::new(HashMap::new());
    static NEXT_HANDLE: Cell<u32> = const { Cell::new(1) };
}

/// A session given as an opaque handle from [`wasm_session_open`], or (for callers that
/// hold only the stored envelope, like the tap window) as the session JSON itself.
pub(crate) fn jsvalue_to_session(value: &JsValue) -> Result<(Server, Session), JsValue> {
    if let Some(n) = value.as_f64() {
        let handle = n as u32;
        return SESSIONS
            .with(|s| s.borrow().get(&handle).cloned())
            .ok_or_else(|| js_err("unknown or closed session handle"));
    }
    let wire: WireSession = serde_wasm_bindgen_deserialize(value)
        .map_err(|e| js_err(format!("deserialize session: {e}")))?;
    wire.into_runtime().map_err(js_err)
}

/// Keep a refreshed session behind its handle. Returns false when the caller passed
/// JSON, which then has to receive the refreshed JSON instead.
pub(crate) fn update_handle(value: &JsValue, server: &Server, session: &Session) -> bool {
    let Some(n) = value.as_f64() else {
        return false;
    };
    SESSIONS.with(|s| {
        if let Some(slot) = s.borrow_mut().get_mut(&(n as u32)) {
            *slot = (server.clone(), session.clone());
        }
    });
    true
}

/// Parse the session once and keep its keys inside the wasm instance; every later
/// call takes the returned number instead of the key material.
#[wasm_bindgen(js_name = wasm_session_open)]
pub fn wasm_session_open(session_value: JsValue) -> Result<u32, JsValue> {
    let opened = jsvalue_to_session(&session_value)?;
    let handle = NEXT_HANDLE.with(|n| {
        let h = n.get();
        n.set(h.wrapping_add(1).max(1));
        h
    });
    SESSIONS.with(|s| s.borrow_mut().insert(handle, opened));
    Ok(handle)
}

#[wasm_bindgen(js_name = wasm_session_close)]
pub fn wasm_session_close(handle: u32) {
    SESSIONS.with(|s| s.borrow_mut().remove(&handle));
}

/// The session JSON, for sealing into the storage envelope after a refresh.
#[wasm_bindgen(js_name = wasm_session_export)]
pub fn wasm_session_export(handle: u32) -> Result<JsValue, JsValue> {
    let (server, session) = SESSIONS
        .with(|s| s.borrow().get(&handle).cloned())
        .ok_or_else(|| js_err("unknown or closed session handle"))?;
    session_to_jsvalue(&server, &session)
}

fn serde_wasm_bindgen_serialize<T: Serialize>(t: &T) -> Result<JsValue, String> {
    let s = serde_json::to_string(t).map_err(|e| e.to_string())?;
    js_sys::JSON::parse(&s).map_err(|e| format!("JSON.parse: {e:?}"))
}

fn serde_wasm_bindgen_deserialize<T: for<'de> Deserialize<'de>>(v: &JsValue) -> Result<T, String> {
    let s: String = js_sys::JSON::stringify(v)
        .map_err(|e| format!("JSON.stringify: {e:?}"))?
        .into();
    serde_json::from_str(&s).map_err(|e| e.to_string())
}
