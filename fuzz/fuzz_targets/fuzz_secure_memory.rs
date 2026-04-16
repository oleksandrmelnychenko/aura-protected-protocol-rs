#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::SecureMemoryHandle;

#[derive(Arbitrary, Debug)]
struct MemInput {
    alloc_size: u16,
    data: Vec<u8>,
    read_len: u16,
}

fuzz_target!(|input: MemInput| {
    let size = input.alloc_size as usize;
    let mut handle = match SecureMemoryHandle::allocate(size) {
        Ok(h) => h,
        Err(_) => return,
    };

    let _ = handle.write(&input.data);

    let _ = handle.read_bytes(input.read_len as usize);

    if !input.data.is_empty() && input.data.len() <= size {
        handle.write(&input.data).expect("write within bounds must succeed");
        let readback = handle
            .read_bytes(input.data.len())
            .expect("read within bounds must succeed");
        assert_eq!(readback, input.data, "write/read roundtrip mismatch");

        let cloned = handle.try_clone().expect("clone must succeed");
        let clone_data = cloned
            .read_bytes(input.data.len())
            .expect("clone read must succeed");
        assert_eq!(clone_data, input.data, "clone data mismatch");
    }
});
