use std::fmt::Display;

use jni::strings::{JNIStr, JNIString};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

use jni::sys::{jbyteArray, jint, jobject};
use jni::{AttachGuard, Env, EnvUnowned, jni_str};

#[derive(Debug)]
pub enum ExKind {
    MalformedStanza,

    AeadFailure,

    IdentityMissing,

    Internal,
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
            ExKind::Internal => {
                jni_str!("ragewarden/ragedroid/jni/RageNativeException$Internal")
            }
        }
    }
}

pub fn throw_kind(env: &mut Env<'_>, kind: ExKind, msg: impl Display) -> jbyteArray {
    let _ = env.throw_new(kind.class(), JNIString::from(msg.to_string()));
    std::ptr::null_mut()
}

pub trait JniDefault {
    fn jni_default() -> Self;
}

impl JniDefault for jobject {
    fn jni_default() -> Self {
        std::ptr::null_mut()
    }
}

impl JniDefault for jint {
    fn jni_default() -> Self {
        0
    }
}

impl JniDefault for () {
    fn jni_default() -> Self {}
}

pub fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

pub fn guarded<'local, R: JniDefault>(
    env: EnvUnowned<'local>,
    f: impl FnOnce(&mut Env<'local>) -> R,
) -> R {
    // SAFETY: `env` is the JNIEnv the JVM passed to this native method, valid for the
    // duration of the call on this thread; the guard does not outlive the call.
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(r) => r,
        Err(payload) => {
            let msg = panic_message(payload.as_ref());
            let _ = catch_unwind(AssertUnwindSafe(|| drop(payload)));
            env.exception_clear();
            throw_kind(env, ExKind::Internal, format!("native panic: {msg}"));
            R::jni_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::panic_message;

    #[test]
    fn panic_message_reads_str_and_string_payloads() {
        let p = std::panic::catch_unwind(|| panic!("static")).unwrap_err();
        assert_eq!(panic_message(p.as_ref()), "static");
        let n = 7;
        let p = std::panic::catch_unwind(|| panic!("formatted {n}")).unwrap_err();
        assert_eq!(panic_message(p.as_ref()), "formatted 7");
        let p = std::panic::catch_unwind(|| std::panic::panic_any(42u8)).unwrap_err();
        assert_eq!(panic_message(p.as_ref()), "non-string panic payload");
    }
}
