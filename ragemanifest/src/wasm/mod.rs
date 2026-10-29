mod crypto;
mod http;
mod session;
mod sync;

pub use crypto::*;
pub use session::{wasm_session_close, wasm_session_export, wasm_session_open};
pub use sync::*;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = wasm_module_tag)]
pub fn wasm_module_tag() -> String {
    format!(
        "ragemanifest {} / ragewarden-core linked",
        env!("CARGO_PKG_VERSION")
    )
}

pub(crate) fn js_err(msg: impl std::fmt::Display) -> JsValue {
    JsValue::from(js_sys::Error::new(&format!("{msg}")))
}

pub(crate) fn js_object(fields: &[(&str, JsValue)]) -> Result<JsValue, JsValue> {
    let obj = js_sys::Object::new();
    for (key, value) in fields {
        js_sys::Reflect::set(&obj, &JsValue::from_str(key), value)
            .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    }
    Ok(obj.into())
}

pub(crate) fn js_err_with_code(code: &str, msg: impl std::fmt::Display) -> JsValue {
    let e = js_sys::Error::new(&format!("{msg}"));
    let _ = js_sys::Reflect::set(
        e.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    e.into()
}
