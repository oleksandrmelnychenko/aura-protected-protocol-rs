#![cfg(not(any(feature = "no-secure-memory", target_os = "ios", target_os = "windows")))]

use aura_protected_protocol::core::errors::CryptoError;
use aura_protected_protocol::crypto::SecureMemoryHandle;

#[test]
fn secure_memory_pool_initialization_failure_returns_error() {
    std::env::set_var("AURA_SECURE_POOL_SMALL_SLOTS", "1");
    std::env::set_var("AURA_SECURE_POOL_LARGE_SLOTS", usize::MAX.to_string());

    match SecureMemoryHandle::allocate(32) {
        Err(CryptoError::AllocationFailed { .. }) => {}
        Ok(_) => panic!("pool init must return an error"),
        Err(e) => panic!("unexpected secure memory error: {e}"),
    }
}
