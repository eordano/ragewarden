use jni::objects::{Global, JByteArray, JObject, JString, JValue};
use jni::{jni_sig, jni_str, Env, JavaVM};
use ragewarden_core::{FileKey, Identity, IdentityError, Stanza};

pub struct JniIdentity {
    vm: JavaVM,
    object: Global<JObject<'static>>,
    label: String,
}

impl JniIdentity {
    pub fn from_jobject(
        env: &mut Env<'_>,
        obj: &JObject<'_>,
        label: impl Into<String>,
    ) -> Result<Self, jni::errors::Error> {
        let global = env.new_global_ref(obj)?;
        let vm = env.get_java_vm()?;
        Ok(Self {
            vm,
            object: global,
            label: label.into(),
        })
    }

    fn try_unwrap_with_env(
        &self,
        env: &mut Env<'_>,
        stanza: &Stanza,
    ) -> Result<Option<FileKey>, IdentityError> {
        let tag_jstr: JString<'_> = env
            .new_string(&stanza.tag)
            .map_err(|e| IdentityError::Hardware(format!("new_string(tag): {e}")))?;

        let string_class = env
            .find_class(jni_str!("java/lang/String"))
            .map_err(|e| IdentityError::Hardware(format!("find_class(String): {e}")))?;
        let null_str = JObject::null();
        let args_arr = env
            .new_object_array(stanza.args.len() as i32, &string_class, &null_str)
            .map_err(|e| IdentityError::Hardware(format!("new_object_array: {e}")))?;
        for (i, arg) in stanza.args.iter().enumerate() {
            let s = env
                .new_string(arg)
                .map_err(|e| IdentityError::Hardware(format!("new_string(arg): {e}")))?;
            args_arr
                .set_element(env, i, &s)
                .map_err(|e| IdentityError::Hardware(format!("set_object_array_element: {e}")))?;
        }

        let body_arr: JByteArray<'_> = env
            .byte_array_from_slice(&stanza.body)
            .map_err(|e| IdentityError::Hardware(format!("byte_array_from_slice: {e}")))?;

        let result = env.call_method(
            self.object.as_obj(),
            jni_str!("tryUnwrapBlocking"),
            jni_sig!("(Ljava/lang/String;[Ljava/lang/String;[B)[B"),
            &[
                JValue::Object(&JObject::from(tag_jstr)),
                JValue::Object(&JObject::from(args_arr)),
                JValue::Object(&JObject::from(body_arr)),
            ],
        );

        if env.exception_check() {
            env.exception_describe();
            env.exception_clear();
            return Err(IdentityError::Hardware(format!(
                "{}: kotlin threw during tryUnwrapBlocking",
                self.label
            )));
        }

        let returned = match result {
            Ok(v) => v,
            Err(e) => {
                return Err(IdentityError::Hardware(format!(
                    "call_method tryUnwrapBlocking: {e}"
                )))
            }
        };

        let obj = returned
            .l()
            .map_err(|e| IdentityError::Hardware(format!("returned not object: {e}")))?;
        if obj.is_null() {
            return Ok(None);
        }

        let arr: JByteArray<'_> = env
            .cast_local::<JByteArray<'_>>(obj)
            .map_err(|e| IdentityError::Hardware(format!("returned not byte[]: {e}")))?;
        let bytes = env
            .convert_byte_array(&arr)
            .map_err(|e| IdentityError::Hardware(format!("convert_byte_array: {e}")))?;
        if bytes.len() != 16 {
            return Err(IdentityError::Crypto(format!(
                "kotlin returned {} bytes; expected 16",
                bytes.len()
            )));
        }
        let mut fk = [0u8; 16];
        fk.copy_from_slice(&bytes);
        Ok(Some(zeroize::Zeroizing::new(fk)))
    }
}

impl Identity for JniIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        self.vm
            .attach_current_thread(|env| -> Result<_, jni::errors::Error> {
                Ok(self.try_unwrap_with_env(env, stanza))
            })
            .map_err(|e| IdentityError::Hardware(format!("attach_current_thread: {e}")))?
    }

    fn display(&self) -> &str {
        &self.label
    }
}
