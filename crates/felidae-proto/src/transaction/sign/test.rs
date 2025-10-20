#[allow(unused)]
use super::*;

#[test]
fn sign_and_verify() {
    use crate::transaction::{Action, Signature, Transaction, action};

    let keypair = KeyPair::generate().unwrap();
    let public_key = keypair.public_key().as_ref().to_vec();

    let signed_tx = Transaction {
        chain_id: "test_chain".into(),
        actions: vec![Action {
            action: Some(action::Action::Reconfigure(action::Reconfigure {
                signature: Some(Signature::unsigned(public_key.clone().into())),
                config: None,
                not_before: None,
                not_after: None,
            })),
        }],
    }
    .sign_all(keypair, Context::new(&ring::digest::SHA256))
    .unwrap();

    let action::Action::Reconfigure(reconfigure) = signed_tx.actions[0].action.as_ref().unwrap()
    else {
        panic!("expected reconfigure action");
    };
    let signature = reconfigure.signature.as_ref().unwrap();
    assert!(!signature.signature.is_empty());

    signed_tx
        .verify_all(Context::new(&ring::digest::SHA256))
        .unwrap();
}

#[test]
fn sign_and_verify_bad_sig() {
    use crate::transaction::{Action, Signature, Transaction, action};

    let keypair = KeyPair::generate().unwrap();
    let public_key = keypair.public_key().as_ref().to_vec();

    let mut signed_tx = Transaction {
        chain_id: "test_chain".into(),
        actions: vec![Action {
            action: Some(action::Action::Reconfigure(action::Reconfigure {
                signature: Some(Signature::unsigned(public_key.clone().into())),
                config: None,
                not_before: None,
                not_after: None,
            })),
        }],
    }
    .sign_all(keypair, Context::new(&ring::digest::SHA256))
    .unwrap();

    let action::Action::Reconfigure(reconfigure) = signed_tx.actions[0].action.as_mut().unwrap()
    else {
        panic!("expected reconfigure action");
    };
    let signature = reconfigure.signature.as_mut().unwrap();

    // Corrupt the signature by cloning to a mutable bytes and flipping a bit:
    let mut sig_bytes = signature.signature.to_vec();
    sig_bytes[0] ^= 0xFF;
    signature.signature = sig_bytes.into();

    // Ensure the signature is still non-empty:
    assert!(!signature.signature.is_empty());

    assert!(
        signed_tx
            .verify_all(Context::new(&ring::digest::SHA256))
            .is_err()
    );
}

#[test]
fn sign_and_verify_missing_sig() {
    use crate::transaction::{Action, Signature, Transaction, action};

    let keypair = KeyPair::generate().unwrap();
    let public_key = keypair.public_key().as_ref().to_vec();

    let mut signed_tx = Transaction {
        chain_id: "test_chain".into(),
        actions: vec![Action {
            action: Some(action::Action::Reconfigure(action::Reconfigure {
                signature: Some(Signature::unsigned(public_key.clone().into())),
                config: None,
                not_before: None,
                not_after: None,
            })),
        }],
    }
    .sign_all(keypair, Context::new(&ring::digest::SHA256))
    .unwrap();

    let action::Action::Reconfigure(reconfigure) = signed_tx.actions[0].action.as_mut().unwrap()
    else {
        panic!("expected reconfigure action");
    };
    let signature = reconfigure.signature.as_mut().unwrap();

    // Strip the signature by setting it to empty:
    signature.signature = Bytes::new();

    assert!(
        signed_tx
            .verify_all(Context::new(&ring::digest::SHA256))
            .is_err()
    );
}
