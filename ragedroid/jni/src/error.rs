use std::fmt::Display;

use jni::strings::{JNIStr, JNIString};
use jni::sys::jbyteArray;
use jni::{jni_str, Env};

pub enum ExKind {
    MalformedStanza,

    AeadFailure,

    IdentityMissing,
}

impl ExKind {
    fn class(&self) -> &'static JNIStr {
        match self {
            ExKind::MalformedStanza => {
                jni_str!("ragewarden/ragedroid/jni/RageNativeException$MalformedStanza")
            }
            ExKind::AeadFailure => {
                jni_str!("ragewarden/ragedroid/jni/RageNativeException$AeadFailure")
            }
            ExKind::IdentityMissing => {
                jni_str!("ragewarden/ragedroid/jni/RageNativeException$IdentityMissing")
            }
        }
    }
}

pub fn throw_kind(env: &mut Env<'_>, kind: ExKind, msg: impl Display) -> jbyteArray {
    let _ = env.throw_new(kind.class(), JNIString::from(msg.to_string()));
    std::ptr::null_mut()
}
