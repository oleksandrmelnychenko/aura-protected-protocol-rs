use aura_protected_protocol::api::AuraProtocol;

#[test]
fn completed_handshakes_reuse_large_secure_memory_slots() {
    std::env::set_var("AURA_SECURE_POOL_SMALL_SLOTS", "256");
    std::env::set_var("AURA_SECURE_POOL_LARGE_SLOTS", "8");

    let bob_seed = [0x42u8; 32];

    for _ in 0..32 {
        let mut alice = AuraProtocol::new(0).expect("alice protocol");
        let mut bob = AuraProtocol::from_seed(&bob_seed, "server", 1).expect("bob protocol");
        let bob_bundle = bob.pre_key_bundle().expect("bob pre-key bundle");

        let (initiator, init_msg) = alice.begin_session(&bob_bundle).expect("begin session");
        let (responder, ack_msg) = bob.accept_session(&init_msg).expect("accept session");

        let alice_session = initiator.complete(&ack_msg).expect("initiator complete");
        let bob_session = responder.complete().expect("responder complete");

        drop(alice_session);
        drop(bob_session);
        drop(bob);
        drop(alice);
    }
}
