use super::js_err;

use crate::snapshot::WireSession;
use ragewarden_core::sync::{Server, Session};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

pub(crate) fn session_to_jsvalue(server: &Server, session: &Session) -> Result<JsValue, JsValue> {
    let wire = WireSession::from_runtime(server, session);
    serde_wasm_bindgen_serialize(&wire).map_err(|e| js_err(format!("serialize session: {e}")))
}

pub(crate) fn jsvalue_to_session(value: &JsValue) -> Result<(Server, Session), JsValue> {
    let wire: WireSession = serde_wasm_bindgen_deserialize(value)
        .map_err(|e| js_err(format!("deserialize session: {e}")))?;
    wire.into_runtime().map_err(js_err)
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
