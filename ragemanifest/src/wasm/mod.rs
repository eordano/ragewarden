mod crypto;
mod http;
mod session;
mod sync;

pub use crypto::*;
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

/*
 * A js_err carrying a stable `code` property (e.g. "no_matching_identity")
 * so glue/UI code branches on `err.code` instead of string-matching the
 * human-readable message.
 */
pub(crate) fn js_err_with_code(code: &str, msg: impl std::fmt::Display) -> JsValue {
    let e = js_sys::Error::new(&format!("{msg}"));
    let _ = js_sys::Reflect::set(
        e.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    e.into()
}
