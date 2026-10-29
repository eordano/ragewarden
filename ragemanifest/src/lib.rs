#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod decide;
pub mod prf_identity;
pub mod recipient_select;
pub mod reveal;
pub mod snapshot;

#[cfg(not(target_arch = "wasm32"))]
mod host {
    pub fn ragemanifest_smoke_check() -> &'static str {
        let _no_ids = ragewarden_core::no_hardware_identities();
        "ragemanifest linked"
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use host::ragemanifest_smoke_check;

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn smoke() {
    assert_eq!(ragemanifest_smoke_check(), "ragemanifest linked");
}

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::*;
