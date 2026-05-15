// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use aura_protected_protocol::crypto::{
    AesGcm, CryptoInterop, HkdfSha256, KyberInterop, ShamirSecretSharing,
};
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::interfaces::StaticStateKeyProvider;
use aura_protected_protocol::proto::{OneTimePreKey, PreKeyBundle};
use aura_protected_protocol::protocol::{HandshakeInitiator, HandshakeResponder, Session};
use prost::Message;

const PAPER_TRAFFIC_MESSAGES: u32 = 128;
const PAPER_TRAFFIC_PAYLOAD_BYTES: usize = 256;

fn init() {
    CryptoInterop::initialize().expect("crypto init");
}

fn build_proto_bundle(ik: &IdentityKeys) -> Vec<u8> {
    let lb = ik.create_public_bundle().unwrap();
    let opks: Vec<OneTimePreKey> = lb
        .one_time_pre_keys()
        .iter()
        .map(|o| OneTimePreKey {
            one_time_pre_key_id: o.id(),
            public_key: o.public_key_vec(),
        })
        .collect();
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: opks,
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    let mut buf = Vec::new();
    pb.encode(&mut buf).unwrap();
    buf
}

fn create_session_pair() -> (Session, Session) {
    create_session_pair_with_chain_limit(1000)
}

fn create_session_pair_with_chain_limit(max_messages_per_chain: u32) -> (Session, Session) {
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator =
        HandshakeInitiator::start(&mut alice, &bob_bundle, max_messages_per_chain).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder =
        HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, max_messages_per_chain)
            .unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();
    (alice_session, bob_session)
}

fn bench_identity_create(c: &mut Criterion) {
    init();
    c.bench_function("identity_create (5 OPKs)", |b| {
        b.iter(|| {
            let _ = IdentityKeys::create(black_box(5)).unwrap();
        });
    });
}

fn bench_handshake_full(c: &mut Criterion) {
    init();
    c.bench_function("handshake_full (keygen + X3DH + confirm)", |b| {
        b.iter(|| {
            let _ = create_session_pair();
        });
    });
}

fn bench_encrypt_message(c: &mut Criterion) {
    init();
    let payload = vec![0xABu8; 256];

    c.bench_function("encrypt_message (256B)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            let mut remaining = iters;
            while remaining > 0 {
                let batch = remaining.min(60_000);
                let (alice, _bob) = create_session_pair();
                let start = std::time::Instant::now();
                for i in 0..batch {
                    let _ = alice
                        .encrypt(black_box(&payload), 0, u32::try_from(i).unwrap(), None)
                        .unwrap();
                }
                total += start.elapsed();
                remaining -= batch;
            }
            total
        });
    });
}

fn bench_decrypt_message(c: &mut Criterion) {
    init();
    let payload = vec![0xABu8; 256];
    c.bench_function("decrypt_message (256B)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            let mut remaining = iters;
            while remaining > 0 {
                let batch = remaining.min(60_000);
                let (alice, bob) = create_session_pair();
                let mut envelopes = Vec::with_capacity(usize::try_from(batch).unwrap());
                for i in 0..batch {
                    envelopes.push(
                        alice
                            .encrypt(&payload, 0, u32::try_from(i).unwrap(), None)
                            .unwrap(),
                    );
                }
                let start = std::time::Instant::now();
                for env in &envelopes {
                    let _ = bob.decrypt(black_box(env)).unwrap();
                }
                total += start.elapsed();
                remaining -= batch;
            }
            total
        });
    });
}

fn bench_encrypt_decrypt_roundtrip(c: &mut Criterion) {
    init();

    let mut group = c.benchmark_group("encrypt_decrypt_roundtrip");
    for size in [64, 256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let payload = vec![0xABu8; size];
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                let mut remaining = iters;
                while remaining > 0 {
                    let batch = remaining.min(60_000);
                    let (alice, bob) = create_session_pair();
                    let mut envelopes = Vec::with_capacity(usize::try_from(batch).unwrap());
                    for i in 0..batch {
                        envelopes.push(
                            alice
                                .encrypt(&payload, 0, u32::try_from(i).unwrap(), None)
                                .unwrap(),
                        );
                    }
                    let start = std::time::Instant::now();
                    for env in &envelopes {
                        let _ = bob.decrypt(black_box(env)).unwrap();
                    }
                    total += start.elapsed();
                    remaining -= batch;
                }
                total
            });
        });
    }
    group.finish();
}

fn bench_hkdf_derive(c: &mut Criterion) {
    init();
    let ikm = CryptoInterop::get_random_bytes(32);
    let salt = CryptoInterop::get_random_bytes(32);
    let info = b"Aura-Bench";

    c.bench_function("hkdf_sha256_derive (32B out)", |b| {
        b.iter(|| {
            let _ = HkdfSha256::derive_key_bytes(
                black_box(&ikm),
                32,
                black_box(&salt),
                black_box(info),
            )
            .unwrap();
        });
    });
}

fn bench_kyber_keygen(c: &mut Criterion) {
    init();
    c.bench_function("kyber768_keygen", |b| {
        b.iter(|| {
            let _ = KyberInterop::generate_keypair().unwrap();
        });
    });
}

fn bench_kyber_encap_decap(c: &mut Criterion) {
    init();
    let (sk, pk) = KyberInterop::generate_keypair().unwrap();

    c.bench_function("kyber768_encapsulate", |b| {
        b.iter(|| {
            let _ = KyberInterop::encapsulate(black_box(&pk)).unwrap();
        });
    });

    c.bench_function("kyber768_decapsulate", |b| {
        b.iter_custom(|iters| {
            let cts: Vec<_> = (0..iters)
                .map(|_| KyberInterop::encapsulate(&pk).unwrap().0)
                .collect();
            let start = std::time::Instant::now();
            for ct in &cts {
                let _ = KyberInterop::decapsulate(black_box(ct), &sk).unwrap();
            }
            start.elapsed()
        });
    });
}

fn bench_aes_gcm_siv(c: &mut Criterion) {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let aad = b"benchmark-aad";

    let mut group = c.benchmark_group("aes256_gcm_siv");
    for size in [256, 1024, 4096, 16_384] {
        let payload = vec![0xABu8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &payload, |b, payload| {
            b.iter(|| {
                let _ =
                    AesGcm::encrypt(black_box(&key), black_box(&nonce), black_box(payload), aad)
                        .unwrap();
            });
        });

        let ct = AesGcm::encrypt(&key, &nonce, &payload, aad).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), &ct, |b, ct| {
            b.iter(|| {
                let _ = AesGcm::decrypt(black_box(&key), black_box(&nonce), black_box(ct), aad)
                    .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_session_export_import(c: &mut Criterion) {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"warm up", 0, 1, None).unwrap();
    bob.decrypt(&env).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);

    c.bench_function("session_export (sealed state)", |b| {
        b.iter(|| {
            let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
            let _ = bob.export_sealed_state(black_box(&provider), 1).unwrap();
        });
    });

    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob.export_sealed_state(&provider, 1).unwrap();

    c.bench_function("session_import (sealed state)", |b| {
        b.iter(|| {
            let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
            let _ = Session::from_sealed_state(black_box(&sealed), &provider, 0).unwrap();
        });
    });
}

fn bench_shamir(c: &mut Criterion) {
    init();
    let secret = CryptoInterop::get_random_bytes(32);
    let auth_key = CryptoInterop::get_random_bytes(32);

    c.bench_function("shamir_split (3-of-5, 32B)", |b| {
        b.iter(|| {
            let _ = ShamirSecretSharing::split(
                black_box(&secret),
                black_box(3),
                black_box(5),
                black_box(&auth_key),
            )
            .unwrap();
        });
    });

    let shares = ShamirSecretSharing::split(&secret, 3, 5, &auth_key).unwrap();

    c.bench_function("shamir_reconstruct (3-of-5, 32B)", |b| {
        b.iter(|| {
            let _ = ShamirSecretSharing::reconstruct(
                black_box(&shares),
                black_box(&auth_key),
                black_box(3),
            )
            .unwrap();
        });
    });
}

fn bench_direction_change_ratchet(c: &mut Criterion) {
    init();

    c.bench_function("direction_change_ratchet (single step)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            let mut remaining = iters;
            while remaining > 0 {
                let batch = remaining.min(60_000);
                let (alice, bob) = create_session_pair();
                let env = alice.encrypt(b"warmup", 0, 0, None).unwrap();
                bob.decrypt(&env).unwrap();

                let start = std::time::Instant::now();
                for i in 0..batch {
                    if i % 2 == 0 {
                        let env = bob
                            .encrypt(b"ratchet", 1, u32::try_from(i).unwrap(), None)
                            .unwrap();
                        alice.decrypt(black_box(&env)).unwrap();
                    } else {
                        let env = alice
                            .encrypt(b"ratchet", 0, u32::try_from(i + 100).unwrap(), None)
                            .unwrap();
                        bob.decrypt(black_box(&env)).unwrap();
                    }
                }
                total += start.elapsed();
                remaining -= batch;
            }
            total
        });
    });
}

fn bench_alternating_throughput(c: &mut Criterion) {
    init();

    c.bench_function("alternating_throughput (256B, ratchet each msg)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            let mut remaining = iters;
            while remaining > 0 {
                let batch = remaining.min(60_000);
                let (alice, bob) = create_session_pair();
                let payload = vec![0xABu8; 256];

                let start = std::time::Instant::now();
                for i in 0..batch {
                    if i % 2 == 0 {
                        let env = alice
                            .encrypt(&payload, 0, u32::try_from(i).unwrap(), None)
                            .unwrap();
                        bob.decrypt(black_box(&env)).unwrap();
                    } else {
                        let env = bob
                            .encrypt(&payload, 1, u32::try_from(i).unwrap(), None)
                            .unwrap();
                        alice.decrypt(black_box(&env)).unwrap();
                    }
                }
                total += start.elapsed();
                remaining -= batch;
            }
            total
        });
    });
}

fn bench_burst_throughput(c: &mut Criterion) {
    init();

    c.bench_function("burst_throughput (256B, no ratchet)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            let mut remaining = iters;
            while remaining > 0 {
                let batch = remaining.min(60_000);
                let (alice, bob) = create_session_pair();
                let payload = vec![0xABu8; 256];

                let mut envelopes = Vec::with_capacity(usize::try_from(batch).unwrap());
                for i in 0..batch {
                    envelopes.push(
                        alice
                            .encrypt(&payload, 0, u32::try_from(i).unwrap(), None)
                            .unwrap(),
                    );
                }

                let start = std::time::Instant::now();
                for env in &envelopes {
                    bob.decrypt(black_box(env)).unwrap();
                }
                total += start.elapsed();
                remaining -= batch;
            }
            total
        });
    });
}

fn bench_out_of_order_decrypt(c: &mut Criterion) {
    init();

    c.bench_function("out_of_order_decrypt (reverse 20 msgs, 256B)", |b| {
        b.iter_custom(|iters| {
            let payload = vec![0xABu8; 256];
            let mut total = std::time::Duration::ZERO;

            for _ in 0..iters {
                let (alice, bob) = create_session_pair();
                let envelopes: Vec<_> = (0..20_i32)
                    .map(|i| {
                        alice
                            .encrypt(&payload, 0, u32::try_from(i).unwrap(), None)
                            .unwrap()
                    })
                    .collect();

                let start = std::time::Instant::now();
                for env in envelopes.iter().rev() {
                    bob.decrypt(black_box(env)).unwrap();
                }
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_cross_epoch_decrypt(c: &mut Criterion) {
    init();

    c.bench_function("cross_epoch_decrypt (old-epoch msg after ratchet)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;

            for i in 0..iters {
                let (alice, bob) = create_session_pair();

                let env0 = alice.encrypt(b"msg-0", 0, 0, None).unwrap();
                let env1 = alice.encrypt(b"msg-1", 0, 1, None).unwrap();
                bob.decrypt(&env0).unwrap();

                let bob_reply = bob
                    .encrypt(b"reply", 1, u32::try_from(i).unwrap(), None)
                    .unwrap();
                alice.decrypt(&bob_reply).unwrap();

                let start = std::time::Instant::now();
                bob.decrypt(black_box(&env1)).unwrap();
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_hybrid_vs_classical_ratchet(c: &mut Criterion) {
    init();
    let mut group = c.benchmark_group("ratchet_overhead");
    group.sample_size(200);

    group.bench_function("hybrid_ratchet (X25519+Kyber)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (alice, bob) = create_session_pair();
                let env1 = alice.encrypt(b"msg", 0, 1, None).unwrap();
                bob.decrypt(&env1).unwrap();
                let start = std::time::Instant::now();
                let _env2 = bob.encrypt(black_box(b"reply"), 1, 1, None).unwrap();
                total += start.elapsed();
            }
            total
        });
    });

    group.bench_function("x25519_dh_scalarmult", |b| {
        let (_, pk) = CryptoInterop::generate_x25519_keypair("bench").unwrap();
        let (sk_handle, _) = CryptoInterop::generate_x25519_keypair("bench2").unwrap();
        let sk_bytes = sk_handle.read_bytes(32).unwrap();
        let sk_arr: [u8; 32] = sk_bytes.as_slice().try_into().unwrap();
        let pk_arr: [u8; 32] = pk.as_slice().try_into().unwrap();
        b.iter(|| {
            let secret = x25519_dalek::StaticSecret::from(sk_arr);
            let public = x25519_dalek::PublicKey::from(pk_arr);
            let shared = secret.diffie_hellman(&public).to_bytes().to_vec();
            black_box(shared);
        });
    });

    group.bench_function("kyber768_encap_decap", |b| {
        let (sk_handle, pk) = KyberInterop::generate_keypair().unwrap();
        b.iter(|| {
            let (ct, _ss) = KyberInterop::encapsulate(black_box(&pk)).unwrap();
            let _ss2 = KyberInterop::decapsulate(black_box(&ct), &sk_handle).unwrap();
        });
    });

    group.finish();
}

fn bench_pq_traffic_profiles(c: &mut Criterion) {
    init();

    let payload = vec![0xABu8; PAPER_TRAFFIC_PAYLOAD_BYTES];
    let mut group = c.benchmark_group("pq_traffic_profiles");

    group.bench_function("handshake_only_pq/128x256B_unidirectional", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (alice, bob) = create_session_pair_with_chain_limit(PAPER_TRAFFIC_MESSAGES + 1);
                let start = std::time::Instant::now();
                for i in 0..PAPER_TRAFFIC_MESSAGES {
                    let env = alice.encrypt(&payload, 0, i, None).unwrap();
                    bob.decrypt(black_box(&env)).unwrap();
                }
                total += start.elapsed();
            }
            total
        });
    });

    group.bench_function("sparse_pq_chain64/128x256B_unidirectional", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (alice, bob) = create_session_pair_with_chain_limit(64);
                let start = std::time::Instant::now();
                for i in 0..PAPER_TRAFFIC_MESSAGES {
                    let env = alice.encrypt(&payload, 0, i, None).unwrap();
                    bob.decrypt(black_box(&env)).unwrap();
                }
                total += start.elapsed();
            }
            total
        });
    });

    group.bench_function("periodic_pq_chain16/128x256B_unidirectional", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (alice, bob) = create_session_pair_with_chain_limit(16);
                let start = std::time::Instant::now();
                for i in 0..PAPER_TRAFFIC_MESSAGES {
                    let env = alice.encrypt(&payload, 0, i, None).unwrap();
                    bob.decrypt(black_box(&env)).unwrap();
                }
                total += start.elapsed();
            }
            total
        });
    });

    group.bench_function("per_reply_pq/128x256B_alternating", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (alice, bob) = create_session_pair_with_chain_limit(PAPER_TRAFFIC_MESSAGES + 1);
                let start = std::time::Instant::now();
                for i in 0..PAPER_TRAFFIC_MESSAGES {
                    if i % 2 == 0 {
                        let env = alice.encrypt(&payload, 0, i, None).unwrap();
                        bob.decrypt(black_box(&env)).unwrap();
                    } else {
                        let env = bob.encrypt(&payload, 1, i, None).unwrap();
                        alice.decrypt(black_box(&env)).unwrap();
                    }
                }
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

fn bench_handshake_only(c: &mut Criterion) {
    init();

    c.bench_function("handshake_only (pre-created identity)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let mut alice_i = IdentityKeys::create(5).unwrap();
                let mut bob_i = IdentityKeys::create(5).unwrap();
                let bob_b = PreKeyBundle::decode(build_proto_bundle(&bob_i).as_slice()).unwrap();

                let start = std::time::Instant::now();
                let initiator = HandshakeInitiator::start(&mut alice_i, &bob_b, 1000).unwrap();
                let init_bytes = initiator.encoded_message().to_vec();
                let responder =
                    HandshakeResponder::process(&mut bob_i, &bob_b, &init_bytes, 1000).unwrap();
                let ack_bytes = responder.encoded_ack().to_vec();
                let _bob_session = responder.finish().unwrap();
                let _alice_session = initiator.finish(black_box(&ack_bytes)).unwrap();
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_identity_create_deterministic(c: &mut Criterion) {
    init();
    let master_key = CryptoInterop::get_random_bytes(32);

    c.bench_function("identity_create_deterministic (5 OPKs)", |b| {
        b.iter(|| {
            let _ = IdentityKeys::create_from_master_key(
                black_box(&master_key),
                black_box("bench-member-id"),
                black_box(5),
            )
            .unwrap();
        });
    });
}

fn bench_encrypt_decrypt_large_payloads(c: &mut Criterion) {
    init();

    let mut group = c.benchmark_group("large_payload_roundtrip");
    for &size in &[16_384, 65_536, 262_144, 1_048_576] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let payload = vec![0xABu8; size];
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                let mut remaining = iters;
                while remaining > 0 {
                    let batch = remaining.min(60_000);
                    let (alice, bob) = create_session_pair();
                    let mut envelopes = Vec::with_capacity(usize::try_from(batch).unwrap());
                    for i in 0..batch {
                        envelopes.push(
                            alice
                                .encrypt(&payload, 0, u32::try_from(i).unwrap(), None)
                                .unwrap(),
                        );
                    }
                    let start = std::time::Instant::now();
                    for env in &envelopes {
                        let _ = bob.decrypt(black_box(env)).unwrap();
                    }
                    total += start.elapsed();
                    remaining -= batch;
                }
                total
            });
        });
    }
    group.finish();
}

fn bench_aes_gcm_siv_large(c: &mut Criterion) {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let aad = b"bench-aad";

    let mut group = c.benchmark_group("aes256_gcm_siv_large");
    for &size in &[65_536, 262_144, 1_048_576] {
        let payload = vec![0xABu8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &payload, |b, payload| {
            b.iter(|| {
                let _ =
                    AesGcm::encrypt(black_box(&key), black_box(&nonce), black_box(payload), aad)
                        .unwrap();
            });
        });

        let ct = AesGcm::encrypt(&key, &nonce, &payload, aad).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), &ct, |b, ct| {
            b.iter(|| {
                let _ = AesGcm::decrypt(black_box(&key), black_box(&nonce), black_box(ct), aad)
                    .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_session_lifecycle_allocations(c: &mut Criterion) {
    init();

    c.bench_function(
        "session_lifecycle (create + 10msg + export + import)",
        |b| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let (alice, bob) = create_session_pair();
                    let payload = vec![0xABu8; 256];

                    let start = std::time::Instant::now();

                    for i in 0..10u32 {
                        let env = alice.encrypt(&payload, 0, i, None).unwrap();
                        bob.decrypt(black_box(&env)).unwrap();
                        let env = bob.encrypt(&payload, 1, i, None).unwrap();
                        alice.decrypt(black_box(&env)).unwrap();
                    }

                    let key = CryptoInterop::get_random_bytes(32);
                    let provider = StaticStateKeyProvider::new(key.clone()).unwrap();
                    let sealed = bob.export_sealed_state(&provider, 1).unwrap();
                    let _restored =
                        Session::from_sealed_state(black_box(&sealed), &provider, 0).unwrap();

                    total += start.elapsed();
                }
                total
            });
        },
    );
}

use aura_protected_protocol::protocol::group::GroupSession;

fn bench_group_create(c: &mut Criterion) {
    init();
    c.bench_function("group_create", |b| {
        let ik = IdentityKeys::create(5).unwrap();
        b.iter(|| {
            let _ = GroupSession::create(black_box(&ik), b"bench-cred".to_vec()).unwrap();
        });
    });
}

fn bench_group_add_member(c: &mut Criterion) {
    init();
    let alice_ik = IdentityKeys::create(5).unwrap();
    let session = GroupSession::create(&alice_ik, b"alice".to_vec()).unwrap();

    c.bench_function("group_add_member", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let bob_ik = IdentityKeys::create(5).unwrap();
                let (kp, _x, _k) =
                    aura_protected_protocol::protocol::group::key_package::create_key_package(
                        &bob_ik,
                        b"bob".to_vec(),
                    )
                    .unwrap();
                let start = std::time::Instant::now();
                let _ = session.add_member(black_box(&kp)).unwrap();
                total += start.elapsed();
            }
            total
        });
    });
}

fn create_group_pair() -> (GroupSession, GroupSession) {
    let alice_ik = IdentityKeys::create(5).unwrap();
    let bob_ik = IdentityKeys::create(5).unwrap();

    let alice_session = GroupSession::create(&alice_ik, b"alice".to_vec()).unwrap();
    let (kp, x25519_priv, kyber_sec) =
        aura_protected_protocol::protocol::group::key_package::create_key_package(
            &bob_ik,
            b"bob".to_vec(),
        )
        .unwrap();
    let (_commit_bytes, welcome_bytes) = alice_session.add_member(&kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome_bytes,
        x25519_priv,
        kyber_sec,
        &bob_ik.get_identity_ed25519_public(),
        &bob_ik.get_identity_x25519_public(),
        bob_ik.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    (alice_session, bob_session)
}

fn bench_group_encrypt_decrypt(c: &mut Criterion) {
    init();

    let mut group = c.benchmark_group("group_encrypt_decrypt");
    for size in [64, 256, 1024, 4096] {
        let payload = vec![0xABu8; size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &payload, |b, payload| {
            b.iter_custom(|iters| {
                // SHIELD_MAX_MESSAGES_PER_EPOCH = 1000; stay well under it per session.
                const BATCH: u64 = 500;
                let mut total = std::time::Duration::ZERO;
                let mut remaining = iters;
                while remaining > 0 {
                    let n = remaining.min(BATCH);
                    let (alice_session, _bob_session) = create_group_pair();
                    let start = std::time::Instant::now();
                    for _ in 0..n {
                        let _ = alice_session.encrypt(black_box(payload)).unwrap();
                    }
                    total += start.elapsed();
                    remaining -= n;
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &payload, |b, payload| {
            b.iter_custom(|iters| {
                const BATCH: u64 = 500;
                let mut total = std::time::Duration::ZERO;
                let mut remaining = iters;
                while remaining > 0 {
                    let n = remaining.min(BATCH);
                    let (alice_session, bob_session) = create_group_pair();
                    let cts: Vec<_> = (0..n)
                        .map(|_| alice_session.encrypt(payload).unwrap())
                        .collect();
                    let start = std::time::Instant::now();
                    for ct in &cts {
                        let _ = bob_session.decrypt(black_box(ct)).unwrap();
                    }
                    total += start.elapsed();
                    remaining -= n;
                }
                total
            });
        });
    }
    group.finish();
}

fn bench_group_update(c: &mut Criterion) {
    init();

    c.bench_function("group_update (create + process commit)", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (alice_session, bob_session) = create_group_pair();
                let start = std::time::Instant::now();
                let commit = alice_session.update().unwrap();
                bob_session.process_commit(black_box(&commit)).unwrap();
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_group_sealed_state(c: &mut Criterion) {
    init();

    let alice_ik = IdentityKeys::create(5).unwrap();
    let session = GroupSession::create(&alice_ik, b"alice".to_vec()).unwrap();
    let key = CryptoInterop::get_random_bytes(32);

    c.bench_function("group_export_sealed_state", |b| {
        b.iter(|| {
            let _ = session.export_sealed_state(black_box(&key), 1).unwrap();
        });
    });

    let sealed = session.export_sealed_state(&key, 1).unwrap();
    let ed25519_sk = alice_ik.get_identity_ed25519_private_key_copy().unwrap();
    c.bench_function("group_import_sealed_state", |b| {
        b.iter(|| {
            let _ =
                GroupSession::from_sealed_state(black_box(&sealed), &key, ed25519_sk.clone(), 0)
                    .unwrap();
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(200)
        .measurement_time(std::time::Duration::from_secs(5));
    targets =
        bench_identity_create,
        bench_identity_create_deterministic,
        bench_handshake_full,
        bench_handshake_only,
        bench_encrypt_message,
        bench_decrypt_message,
        bench_encrypt_decrypt_roundtrip,
        bench_encrypt_decrypt_large_payloads,
        bench_hkdf_derive,
        bench_kyber_keygen,
        bench_kyber_encap_decap,
        bench_aes_gcm_siv,
        bench_aes_gcm_siv_large,
        bench_session_export_import,
        bench_session_lifecycle_allocations,
        bench_shamir,
        bench_direction_change_ratchet,
        bench_alternating_throughput,
        bench_burst_throughput,
        bench_out_of_order_decrypt,
        bench_cross_epoch_decrypt,
        bench_hybrid_vs_classical_ratchet,
        bench_pq_traffic_profiles,
        bench_group_create,
        bench_group_add_member,
        bench_group_encrypt_decrypt,
        bench_group_update,
        bench_group_sealed_state,
        bench_voip_encrypt_frame,
        bench_voip_decrypt_frame,
        bench_voip_key_exchange,
        bench_voip_ratchet_advance,
}
criterion_main!(benches);

fn create_voip_session_pair() -> (
    aura_protected_protocol::protocol::voip::VoipSession,
    aura_protected_protocol::protocol::voip::VoipSession,
) {
    use aura_protected_protocol::protocol::voip::{
        callee_accept_with_context, caller_finish_with_context, caller_init_with_context,
        CallInitAuthContext, CallRole, VoipSession,
    };

    let alice = IdentityKeys::create(1).unwrap();
    let bob = IdentityKeys::create(1).unwrap();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let auth_context = CallInitAuthContext {
        version: 1,
        media_type: 1,
        ratchet_interval_frames: 512,
        pq_rekey_interval_secs: 60,
        shield_mode: false,
    };
    let init_output = caller_init_with_context(
        &alice_ed_secret,
        &alice_ed_public,
        &bob_kyber_pub,
        &auth_context,
    )
    .unwrap();
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
    )
    .unwrap();

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
    )
    .unwrap();

    let alice_session = VoipSession::from_key_material(
        call_id.clone(),
        CallRole::Caller,
        alice_keys,
        512,
        60,
        false,
    )
    .unwrap();
    let bob_session = VoipSession::from_key_material(
        call_id,
        CallRole::Callee,
        accept_output.key_material,
        512,
        60,
        false,
    )
    .unwrap();

    (alice_session, bob_session)
}

fn bench_voip_encrypt_frame(c: &mut Criterion) {
    init();
    let (alice, _bob) = create_voip_session_pair();
    let payload = vec![0xABu8; 320];

    c.bench_function("voip_encrypt_frame_320B", |b| {
        let mut seq = 0u16;
        b.iter(|| {
            let header = aura_protected_protocol::protocol::voip::frame::FrameHeader {
                payload_type: 111,
                ssrc: alice.ssrc(),
                timestamp: u32::from(seq) * 160,
                sequence_number: seq,
            };
            let result = alice.encrypt_frame(&header, black_box(&payload));
            seq = seq.wrapping_add(1);
            black_box(result).unwrap();
        });
    });
}

fn bench_voip_decrypt_frame(c: &mut Criterion) {
    init();
    let (alice, bob) = create_voip_session_pair();
    let payload = vec![0xABu8; 320];

    let mut frames = Vec::new();
    for i in 0u16..1000 {
        let header = aura_protected_protocol::protocol::voip::frame::FrameHeader {
            payload_type: 111,
            ssrc: alice.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        frames.push(alice.encrypt_frame(&header, &payload).unwrap());
    }

    let mut idx = 0;
    c.bench_function("voip_decrypt_frame_320B", |b| {
        b.iter(|| {
            let result = bob.decrypt_frame(black_box(&frames[idx]));
            idx += 1;
            if idx >= frames.len() {
                idx = 0;
            }
            black_box(result)
        });
    });
}

fn bench_voip_key_exchange(c: &mut Criterion) {
    init();
    c.bench_function("voip_full_key_exchange", |b| {
        b.iter(|| {
            black_box(create_voip_session_pair());
        });
    });
}

fn bench_voip_ratchet_advance(c: &mut Criterion) {
    init();
    use aura_protected_protocol::crypto::SecureMemoryHandle;
    use aura_protected_protocol::protocol::voip::key_ratchet::MediaKeyRatchet;

    let key_bytes = CryptoInterop::get_random_bytes(32);
    let mut handle = SecureMemoryHandle::allocate(32).unwrap();
    handle.write(&key_bytes).unwrap();
    let prefix = [0x01u8, 0x02, 0x03, 0x04];
    let mut ratchet = MediaKeyRatchet::new(handle, prefix);

    c.bench_function("voip_ratchet_advance", |b| {
        b.iter(|| {
            black_box(ratchet.advance().unwrap());
        });
    });
}
