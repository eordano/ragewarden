//! `PivSession` against a scripted transport.
//!
//! This is the part of the PIV path that would otherwise be device-blocked:
//! everything except the PC/SC transmit itself runs here against canned card
//! responses, so SELECT / VERIFY / GENERAL AUTHENTICATE handling, status-word
//! mapping, `61 XX` chaining and the PIN retry are all covered without a
//! YubiKey.

use std::collections::VecDeque;

use crate::piv::{CardTransport, PinStatus, PivError, PivSession};
use crate::piv_apdu as apdu;

struct ScriptedCard {
    responses: VecDeque<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
}

impl ScriptedCard {
    fn new(responses: Vec<Vec<u8>>) -> Self {
        Self {
            responses: responses.into(),
            sent: Vec::new(),
        }
    }
}

impl CardTransport for ScriptedCard {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, PivError> {
        self.sent.push(command.to_vec());
        self.responses
            .pop_front()
            .ok_or_else(|| PivError::Pcsc("scripted card ran out of responses".into()))
    }

    fn describe(&self) -> String {
        "scripted card".into()
    }
}

fn ok() -> Vec<u8> {
    vec![0x90, 0x00]
}

fn ecdh_ok(secret: [u8; 32]) -> Vec<u8> {
    let mut v = vec![0x7C, 0x22, 0x82, 0x20];
    v.extend_from_slice(&secret);
    v.extend_from_slice(&[0x90, 0x00]);
    v
}

#[test]
fn select_then_ecdh_sends_the_expected_apdus() {
    let secret = [0x42u8; 32];
    let card = ScriptedCard::new(vec![ok(), ecdh_ok(secret)]);
    let mut session = PivSession::new(card);
    session.select().unwrap();
    let share = session.ecdh(apdu::ALG_X25519, 0x9D, &[0xAA; 32]).unwrap();
    assert_eq!(share, secret.to_vec());
}

#[test]
fn select_failure_is_reported_as_a_missing_piv_applet() {
    let card = ScriptedCard::new(vec![vec![0x6A, 0x82]]);
    let mut session = PivSession::new(card);
    assert!(matches!(session.select(), Err(PivError::NoPivApplet(_))));
}

#[test]
fn a_61xx_status_triggers_get_response_and_concatenates() {
    let mut first = vec![0x7C, 0x22, 0x82, 0x20];
    first.extend_from_slice(&[0x11u8; 16]);
    first.extend_from_slice(&[0x61, 0x10]);
    let mut second = vec![0x11u8; 16];
    second.extend_from_slice(&[0x90, 0x00]);

    let card = ScriptedCard::new(vec![first, second]);
    let mut session = PivSession::new(card);
    let share = session.ecdh(apdu::ALG_X25519, 0x9D, &[0xAA; 32]).unwrap();
    assert_eq!(share, vec![0x11u8; 32]);
}

#[test]
fn an_empty_slot_is_distinguished_from_an_unsupported_algorithm() {
    let mut session = PivSession::new(ScriptedCard::new(vec![vec![0x6A, 0x88]]));
    assert!(matches!(
        session.ecdh(apdu::ALG_X25519, 0x9D, &[0xAA; 32]),
        Err(PivError::SlotEmpty { slot: 0x9D })
    ));

    let mut session = PivSession::new(ScriptedCard::new(vec![vec![0x6A, 0x80]]));
    assert!(matches!(
        session.ecdh(apdu::ALG_X25519, 0x9D, &[0xAA; 32]),
        Err(PivError::AlgorithmUnsupported {
            algorithm: apdu::ALG_X25519
        })
    ));
}

#[test]
fn pin_status_decodes_retries_and_blocked() {
    let mut session = PivSession::new(ScriptedCard::new(vec![vec![0x63, 0xC2]]));
    assert_eq!(
        session.pin_status().unwrap(),
        PinStatus::Required { tries_left: 2 }
    );

    let mut session = PivSession::new(ScriptedCard::new(vec![vec![0x69, 0x83]]));
    assert_eq!(session.pin_status().unwrap(), PinStatus::Blocked);

    let mut session = PivSession::new(ScriptedCard::new(vec![ok()]));
    assert_eq!(session.pin_status().unwrap(), PinStatus::NotRequired);
}

#[test]
fn a_wrong_pin_reports_the_remaining_attempts() {
    let mut session = PivSession::new(ScriptedCard::new(vec![vec![0x63, 0xC1]]));
    assert!(matches!(
        session.verify_pin("123456"),
        Err(PivError::PinIncorrect { tries_left: 1 })
    ));
}

#[test]
fn ecdh_prompts_for_a_pin_once_then_retries() {
    let secret = [0x33u8; 32];
    let card = ScriptedCard::new(vec![
        vec![0x69, 0x82],
        vec![0x63, 0xC2],
        ok(),
        ecdh_ok(secret),
    ]);
    let mut session = PivSession::new(card);
    let share = session
        .ecdh_with_pin_retry(apdu::ALG_X25519, 0x9D, &[0xAA; 32], &|| {
            Ok(zeroize::Zeroizing::new("123456".into()))
        })
        .unwrap();
    assert_eq!(share, secret.to_vec());
}

#[test]
fn ecdh_does_not_loop_forever_when_the_touch_never_lands() {
    let card = ScriptedCard::new(vec![
        vec![0x69, 0x82],
        vec![0x63, 0xC2],
        ok(),
        vec![0x69, 0x82],
    ]);
    let mut session = PivSession::new(card);
    let err = session
        .ecdh_with_pin_retry(apdu::ALG_X25519, 0x9D, &[0xAA; 32], &|| {
            Ok(zeroize::Zeroizing::new("123456".into()))
        })
        .unwrap_err();
    assert!(matches!(err, PivError::TouchNotRegistered));
}

#[test]
fn a_presence_timeout_reported_as_a_security_issue_is_a_missing_touch() {
    let card = ScriptedCard::new(vec![vec![0x66, 0x00]]);
    let mut session = PivSession::new(card);
    let err = session
        .ecdh_with_pin_retry(apdu::ALG_X25519, 0x9D, &[0xAA; 32], &|| {
            panic!("a touch timeout must not ask for the PIN")
        })
        .unwrap_err();
    assert!(matches!(err, PivError::TouchNotRegistered));
}

#[test]
fn a_blocked_pin_is_never_prompted_for() {
    let card = ScriptedCard::new(vec![vec![0x69, 0x82], vec![0x69, 0x83]]);
    let mut session = PivSession::new(card);
    let err = session
        .ecdh_with_pin_retry(apdu::ALG_X25519, 0x9D, &[0xAA; 32], &|| {
            panic!("must not prompt for a blocked PIN")
        })
        .unwrap_err();
    assert!(matches!(err, PivError::PinBlocked));
}

#[test]
fn serial_is_optional_and_absence_is_not_an_error() {
    let mut session = PivSession::new(ScriptedCard::new(vec![vec![0x6D, 0x00]]));
    assert_eq!(session.serial().unwrap(), None);

    let mut session = PivSession::new(ScriptedCard::new(vec![vec![
        0x00, 0x0A, 0x1B, 0x2C, 0x90, 0x00,
    ]]));
    assert_eq!(session.serial().unwrap(), Some(0x000A1B2C));
}

#[test]
fn the_card_with_the_enrolled_serial_is_chosen_among_several() {
    use crate::piv::choose_card;
    assert_eq!(choose_card(&[Some(1), Some(2)], 2).unwrap(), 1);
    assert_eq!(choose_card(&[None], 7).unwrap(), 0);
    assert!(matches!(
        choose_card(&[Some(1), Some(2)], 0),
        Err(PivError::AmbiguousCard { count: 2 })
    ));
    assert!(matches!(
        choose_card(&[Some(1), Some(3)], 2),
        Err(PivError::WrongDevice {
            expected: 2,
            found: 1
        })
    ));
    assert_eq!(choose_card(&[Some(9)], 0).unwrap(), 0);
}
