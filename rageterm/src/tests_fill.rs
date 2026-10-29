use zeroize::Zeroizing;

use crate::fill::{AutotypeBackend, FillError, WindowSpec, parse_window_spec};

struct RecordingBackend {
    calls: std::sync::Mutex<Vec<(WindowSpec, Vec<u8>)>>,
}

impl AutotypeBackend for RecordingBackend {
    fn name(&self) -> &'static str {
        "recording"
    }
    fn type_into(
        &self,
        plaintext: &Zeroizing<Vec<u8>>,
        spec: &WindowSpec,
    ) -> Result<(), FillError> {
        self.calls
            .lock()
            .unwrap()
            .push((spec.clone(), plaintext.to_vec()));
        Ok(())
    }
}

#[test]
fn backend_receives_focused_spec_and_plaintext() {
    let backend = RecordingBackend {
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let pt = Zeroizing::new(b"the-secret".to_vec());
    let spec = parse_window_spec(None).expect("parse");
    backend.type_into(&pt, &spec).expect("ok");
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, WindowSpec::Focused);
    assert_eq!(calls[0].1, b"the-secret");
}

#[test]
fn backend_receives_pid_spec() {
    let backend = RecordingBackend {
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let pt = Zeroizing::new(b"another-secret".to_vec());
    let spec = parse_window_spec(Some("pid:1234")).expect("parse");
    backend.type_into(&pt, &spec).expect("ok");
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls[0].0, WindowSpec::Pid(1234));
}

#[test]
fn backend_receives_class_spec() {
    let backend = RecordingBackend {
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let pt = Zeroizing::new(b"x".to_vec());
    let spec = parse_window_spec(Some("class:firefox-bin")).expect("parse");
    backend.type_into(&pt, &spec).expect("ok");
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls[0].0, WindowSpec::Class("firefox-bin".into()));
}

#[test]
fn backend_receives_title_spec() {
    let backend = RecordingBackend {
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let pt = Zeroizing::new(b"y".to_vec());
    let spec = parse_window_spec(Some("title:Sign in - GitHub")).expect("parse");
    backend.type_into(&pt, &spec).expect("ok");
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls[0].0, WindowSpec::Title("Sign in - GitHub".into()));
}

#[test]
fn parse_window_spec_describe_includes_target_for_prompt() {
    let spec = parse_window_spec(Some("title:GitHub")).unwrap();
    let desc = spec.describe();
    assert!(desc.contains("GitHub"));
}
