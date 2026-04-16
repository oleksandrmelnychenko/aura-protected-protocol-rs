#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::proto::GroupKeyPackage;
use aura_protected_protocol::protocol::group::key_package;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    if let Ok(pkg) = GroupKeyPackage::decode(data) {
        let _ = key_package::validate_key_package(&pkg);
    }

    let ik = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };
    let (pkg, _, _) = match key_package::create_key_package(&ik, b"fuzz-cred".to_vec()) {
        Ok(v) => v,
        Err(_) => return,
    };
    key_package::validate_key_package(&pkg).expect("valid key package must pass validation");
});
