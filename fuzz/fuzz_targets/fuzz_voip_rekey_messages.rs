#![no_main]
use libfuzzer_sys::fuzz_target;

use ecliptix_protocol::core::constants::*;
use ecliptix_protocol::crypto::CryptoInterop;
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::proto::{CallRekey, CallRekeyAck};
use ecliptix_protocol::protocol::voip::call_key_exchange::{
    callee_accept_with_context, caller_finish_with_context, caller_init_with_context,
    sign_rekey_material, CallInitAuthContext,
};
use ecliptix_protocol::protocol::voip::{CallRole, VoipSession};
use prost::Message;

fn default_call_context() -> CallInitAuthContext {
    CallInitAuthContext {
        version: VOIP_PROTOCOL_VERSION,
        media_type: 1,
        ratchet_interval_frames: DEFAULT_RATCHET_INTERVAL_FRAMES,
        pq_rekey_interval_secs: DEFAULT_PQ_REKEY_INTERVAL_SECS,
        shield_mode: false,
    }
}

fn setup_voip_pair(
) -> Result<(IdentityKeys, IdentityKeys, VoipSession, VoipSession), ecliptix_protocol::core::errors::ProtocolError>
{
    let alice = IdentityKeys::create(111)?;
    let bob = IdentityKeys::create(222)?;

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy()?;
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key()?;

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy()?;
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key()?;

    let auth_context = default_call_context();
    let init_output = caller_init_with_context(
        &alice_ed_secret,
        &alice_ed_public,
        &bob_kyber_pub,
        &auth_context,
    )?;
    let call_id = init_output.call_id.clone();

    let accept_output = callee_accept_with_context(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        &auth_context,
    )?;

    let alice_keys = caller_finish_with_context(
        &init_output,
        &alice_kyber_sec,
        &call_id,
        &accept_output.ephemeral_x25519_public,
        &accept_output.kyber_ciphertext,
        &accept_output.identity_ed25519_public,
        &accept_output.signature,
        &accept_output.key_confirmation_mac,
        &auth_context,
    )?;

    let alice_session = VoipSession::from_key_material(
        call_id.clone(),
        CallRole::Caller,
        alice_keys,
        512,
        60,
        false,
    )?;

    let bob_session = VoipSession::from_key_material(
        call_id,
        CallRole::Callee,
        accept_output.key_material,
        512,
        60,
        false,
    )?;

    Ok((alice, bob, alice_session, bob_session))
}

fn take_fuzz_slice(data: &[u8], offset: usize, max_len: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = usize::from(data[offset % data.len()]) % (max_len + 1);
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(data[(offset + 1 + i) % data.len()]);
    }
    out
}

fn mutate_rekey_fields(rekey: &mut CallRekey, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    match data[0] % 5 {
        0 => {
            rekey.ephemeral_x25519_public = take_fuzz_slice(data, 1, 96);
        }
        1 => {
            rekey.kyber_ciphertext = take_fuzz_slice(data, 2, KYBER_CIPHERTEXT_BYTES * 2);
        }
        2 => {
            rekey.signature = take_fuzz_slice(data, 3, 128);
        }
        3 => {
            rekey.call_id = take_fuzz_slice(data, 4, CALL_ID_BYTES * 2);
        }
        4 => {
            if data.len() >= 5 {
                rekey.rekey_generation = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            }
        }
        _ => {}
    }
}

fn mutate_ack_fields(ack: &mut CallRekeyAck, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    match data[0] % 5 {
        0 => {
            ack.ephemeral_x25519_public = take_fuzz_slice(data, 5, 96);
        }
        1 => {
            ack.kyber_ciphertext = take_fuzz_slice(data, 6, KYBER_CIPHERTEXT_BYTES * 2);
        }
        2 => {
            ack.signature = take_fuzz_slice(data, 7, 128);
        }
        3 => {
            ack.call_id = take_fuzz_slice(data, 8, CALL_ID_BYTES * 2);
        }
        4 => {
            if data.len() >= 10 {
                ack.rekey_generation = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
            }
        }
        _ => {}
    }
}

fn fuzz_process_rekey(data: &[u8]) {
    let Ok((alice_id, bob_id, alice, bob)) = setup_voip_pair() else {
        return;
    };

    let Ok(alice_ed_secret) = alice_id.get_identity_ed25519_private_key_copy() else {
        return;
    };
    let alice_ed_public = alice_id.get_identity_ed25519_public();
    let alice_kyber_pub = alice_id.get_kyber_public();
    let Ok(bob_ed_secret) = bob_id.get_identity_ed25519_private_key_copy() else {
        return;
    };
    let bob_kyber_pub = bob_id.get_kyber_public();
    let Ok(bob_kyber_secret) = bob_id.clone_kyber_secret_key() else {
        return;
    };

    let Ok(rekey_bytes) = alice.initiate_rekey(&alice_ed_secret, &bob_kyber_pub) else {
        return;
    };
    let Ok(mut rekey) = CallRekey::decode(rekey_bytes.as_slice()) else {
        return;
    };
    mutate_rekey_fields(&mut rekey, data);

    let resigned = sign_rekey_material(
        &alice_ed_secret,
        &rekey.call_id,
        rekey.rekey_generation,
        &rekey.ephemeral_x25519_public,
        &rekey.kyber_ciphertext,
    );
    if let Ok(signature) = resigned {
        rekey.signature = signature;
    }

    let mut encoded = Vec::new();
    if rekey.encode(&mut encoded).is_err() {
        return;
    }

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = bob.process_rekey(
            &encoded,
            &alice_ed_public,
            &bob_kyber_secret,
            &alice_kyber_pub,
            &bob_ed_secret,
        );
    }));
}

fn fuzz_process_rekey_ack(data: &[u8]) {
    let Ok((alice_id, bob_id, alice, bob)) = setup_voip_pair() else {
        return;
    };

    let Ok(alice_ed_secret) = alice_id.get_identity_ed25519_private_key_copy() else {
        return;
    };
    let Ok(alice_kyber_secret) = alice_id.clone_kyber_secret_key() else {
        return;
    };
    let alice_kyber_pub = alice_id.get_kyber_public();

    let bob_ed_public = bob_id.get_identity_ed25519_public();
    let Ok(bob_ed_secret) = bob_id.get_identity_ed25519_private_key_copy() else {
        return;
    };
    let bob_kyber_pub = bob_id.get_kyber_public();
    let Ok(bob_kyber_secret) = bob_id.clone_kyber_secret_key() else {
        return;
    };

    let Ok(rekey_bytes) = alice.initiate_rekey(&alice_ed_secret, &bob_kyber_pub) else {
        return;
    };
    let Ok(ack_bytes) = bob.process_rekey(
        &rekey_bytes,
        &alice_id.get_identity_ed25519_public(),
        &bob_kyber_secret,
        &alice_kyber_pub,
        &bob_ed_secret,
    ) else {
        return;
    };

    let Ok(mut ack) = CallRekeyAck::decode(ack_bytes.as_slice()) else {
        return;
    };
    mutate_ack_fields(&mut ack, data);

    let resigned = sign_rekey_material(
        &bob_ed_secret,
        &ack.call_id,
        ack.rekey_generation,
        &ack.ephemeral_x25519_public,
        &ack.kyber_ciphertext,
    );
    if let Ok(signature) = resigned {
        ack.signature = signature;
    }

    let mut encoded = Vec::new();
    if ack.encode(&mut encoded).is_err() {
        return;
    }

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = alice.process_rekey_ack(&encoded, &bob_ed_public, &alice_kyber_secret);
    }));
}

fuzz_target!(|data: &[u8]| {
    let _ = CryptoInterop::initialize();
    fuzz_process_rekey(data);
    fuzz_process_rekey_ack(data);
});
