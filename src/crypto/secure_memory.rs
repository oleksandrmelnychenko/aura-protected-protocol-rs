// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::MAX_BUFFER_SIZE;
use crate::core::errors::CryptoError;
use zeroize::Zeroize;

#[cfg(all(feature = "no-secure-memory", not(debug_assertions)))]
compile_error!("no-secure-memory disables mlock — do NOT use in release builds");

#[cfg(any(feature = "no-secure-memory", target_os = "ios", target_os = "windows"))]
mod inner {
    use super::*;

    pub struct SecureMemoryHandle {
        data: Box<[u8]>,
    }

    #[allow(unsafe_code)]
    unsafe impl Send for SecureMemoryHandle {}
    #[allow(unsafe_code)]
    unsafe impl Sync for SecureMemoryHandle {}

    impl SecureMemoryHandle {
        #[allow(unsafe_code)]
        pub fn allocate(size: usize) -> Result<Self, CryptoError> {
            if size == 0 || size > MAX_BUFFER_SIZE {
                return Err(CryptoError::AllocationFailed { size });
            }
            Ok(Self {
                data: vec![0u8; size].into_boxed_slice(),
            })
        }

        pub fn size(&self) -> usize {
            self.data.len()
        }

        pub fn write(&mut self, data: &[u8]) -> Result<(), CryptoError> {
            if data.len() > self.data.len() {
                return Err(CryptoError::BufferTooSmall {
                    capacity: self.data.len(),
                    required: data.len(),
                });
            }
            self.data[..data.len()].copy_from_slice(data);
            if data.len() < self.data.len() {
                self.data[data.len()..].zeroize();
            }
            Ok(())
        }

        pub fn read(&self, out: &mut [u8]) -> Result<(), CryptoError> {
            if out.len() > self.data.len() {
                return Err(CryptoError::BufferTooSmall {
                    capacity: self.data.len(),
                    required: out.len(),
                });
            }
            out.copy_from_slice(&self.data[..out.len()]);
            Ok(())
        }

        pub fn read_bytes(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
            if len > self.data.len() {
                return Err(CryptoError::BufferTooSmall {
                    capacity: self.data.len(),
                    required: len,
                });
            }
            Ok(self.data[..len].to_vec())
        }

        pub fn read_zeroizing(
            &self,
            len: usize,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
            self.read_bytes(len).map(zeroize::Zeroizing::new)
        }

        pub fn with_read_access<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.data)
        }

        pub fn with_write_access<F, R>(&mut self, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            f(&mut self.data)
        }

        pub fn try_clone(&self) -> Result<Self, CryptoError> {
            let mut copy = Self::allocate(self.data.len())?;
            copy.data.copy_from_slice(&self.data);
            Ok(copy)
        }
    }

    impl Drop for SecureMemoryHandle {
        fn drop(&mut self) {
            self.data.zeroize();
        }
    }
}

#[cfg(not(any(feature = "no-secure-memory", target_os = "ios", target_os = "windows")))]
mod inner {
    use super::*;
    use std::ptr::NonNull;
    use std::sync::{Mutex, OnceLock};

    // Two size classes cover essentially every secret-sized allocation
    // in the protocol crate. ~95% of `allocate(N)` sites pass 32, with
    // a handful passing 64 (Ed25519 secret) and a few passing 2400
    // (ML-KEM-768 secret key). Anything larger is rejected up-front
    // and falls outside the secret-key footprint anyway.
    const SMALL_SLOT_BYTES: usize = 64;
    const LARGE_SLOT_BYTES: usize = 4096;

    fn env_usize(key: &str, default: usize) -> usize {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(default)
    }

    struct SizeClass {
        slot_size: usize,
        // One contiguous mlock'd region. We never call mlock again
        // during the process lifetime — the kernel sees one big
        // locked region instead of N tiny ones.
        slots: Box<[u8]>,
        free_list: Mutex<Vec<u32>>,
    }

    #[allow(unsafe_code)]
    impl SizeClass {
        fn new(slot_size: usize, slot_count: usize) -> Result<Self, CryptoError> {
            if slot_count == 0 {
                return Err(CryptoError::AllocationFailed { size: slot_size });
            }
            let total = slot_size
                .checked_mul(slot_count)
                .ok_or(CryptoError::AllocationFailed { size: slot_size })?;
            let slots = vec![0u8; total].into_boxed_slice();
            let rc = unsafe { libc::mlock(slots.as_ptr().cast::<libc::c_void>(), slots.len()) };
            if rc != 0 {
                return Err(CryptoError::AllocationFailed { size: slot_size });
            }
            #[cfg(target_os = "linux")]
            unsafe {
                libc::madvise(
                    slots.as_ptr() as *mut libc::c_void,
                    slots.len(),
                    libc::MADV_DONTDUMP,
                );
            }
            let free_list = (0..slot_count as u32).rev().collect();
            Ok(Self {
                slot_size,
                slots,
                free_list: Mutex::new(free_list),
            })
        }

        fn pop(&self) -> Option<NonNull<u8>> {
            let mut fl = self
                .free_list
                .lock()
                .expect("secure pool free-list poisoned");
            let idx = fl.pop()?;
            let off = (idx as usize) * self.slot_size;
            unsafe { NonNull::new((self.slots.as_ptr() as *mut u8).add(off)) }
        }

        fn push(&self, ptr: NonNull<u8>) {
            let off = (ptr.as_ptr() as usize) - (self.slots.as_ptr() as usize);
            debug_assert!(off + self.slot_size <= self.slots.len());
            let idx = (off / self.slot_size) as u32;
            unsafe {
                std::ptr::write_bytes(ptr.as_ptr(), 0, self.slot_size);
            }
            let mut fl = self
                .free_list
                .lock()
                .expect("secure pool free-list poisoned");
            fl.push(idx);
        }
    }

    struct SecurePool {
        small: SizeClass,
        large: SizeClass,
    }

    impl SecurePool {
        fn build() -> Result<Self, CryptoError> {
            // Defaults sized for ~1M concurrent sessions on a 1-vCPU
            // gateway: 1M small slots × 64 B = 64 MiB, 256K large
            // slots × 4 KiB = 1 GiB. Operators tune via env. The
            // entire region is mlocked once at first use and never
            // grows — no further calls to mlock() under load, so
            // sustained throughput cannot exhaust per-process or
            // per-cgroup mlock-rate budgets.
            let small_count = env_usize("AURA_SECURE_POOL_SMALL_SLOTS", 1_048_576);
            let large_count = env_usize("AURA_SECURE_POOL_LARGE_SLOTS", 262_144);
            Ok(Self {
                small: SizeClass::new(SMALL_SLOT_BYTES, small_count)?,
                large: SizeClass::new(LARGE_SLOT_BYTES, large_count)?,
            })
        }

        fn allocate(&self, size: usize) -> Option<(NonNull<u8>, usize)> {
            if size <= SMALL_SLOT_BYTES {
                self.small.pop().map(|p| (p, SMALL_SLOT_BYTES))
            } else if size <= LARGE_SLOT_BYTES {
                self.large.pop().map(|p| (p, LARGE_SLOT_BYTES))
            } else {
                None
            }
        }

        fn release(&self, ptr: NonNull<u8>, slot_size: usize) {
            if slot_size == SMALL_SLOT_BYTES {
                self.small.push(ptr);
            } else if slot_size == LARGE_SLOT_BYTES {
                self.large.push(ptr);
            }
        }
    }

    static POOL: OnceLock<SecurePool> = OnceLock::new();

    fn pool() -> &'static SecurePool {
        POOL.get_or_init(|| {
            SecurePool::build().expect(
                "failed to build secure memory pool — \
                 mlock denied at startup; check RLIMIT_MEMLOCK / cgroup memory.max / \
                 AURA_SECURE_POOL_*_SLOTS env",
            )
        })
    }

    pub struct SecureMemoryHandle {
        ptr: NonNull<u8>,
        len: usize,
        slot_size: usize,
    }

    #[allow(unsafe_code)]
    unsafe impl Send for SecureMemoryHandle {}
    #[allow(unsafe_code)]
    unsafe impl Sync for SecureMemoryHandle {}

    #[allow(unsafe_code)]
    impl SecureMemoryHandle {
        /// Fails-closed if the secure pool is exhausted. The pool is
        /// pre-mlocked at first use (idempotent), so this returns an
        /// error only when the caller has run past the configured
        /// `AURA_SECURE_POOL_*_SLOTS` budget — a real, recoverable
        /// signal of capacity overload, not a kernel-level
        /// mlock-rate transient.
        pub fn allocate(size: usize) -> Result<Self, CryptoError> {
            if size == 0 || size > MAX_BUFFER_SIZE {
                return Err(CryptoError::AllocationFailed { size });
            }
            let (ptr, slot_size) = pool()
                .allocate(size)
                .ok_or(CryptoError::AllocationFailed { size })?;
            Ok(Self {
                ptr,
                len: size,
                slot_size,
            })
        }

        pub fn size(&self) -> usize {
            self.len
        }

        fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }

        fn as_slice_mut(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }

        pub fn write(&mut self, data: &[u8]) -> Result<(), CryptoError> {
            if data.len() > self.len {
                return Err(CryptoError::BufferTooSmall {
                    capacity: self.len,
                    required: data.len(),
                });
            }
            let dst = self.as_slice_mut();
            dst[..data.len()].copy_from_slice(data);
            if data.len() < dst.len() {
                dst[data.len()..].zeroize();
            }
            Ok(())
        }

        pub fn read(&self, out: &mut [u8]) -> Result<(), CryptoError> {
            if out.len() > self.len {
                return Err(CryptoError::BufferTooSmall {
                    capacity: self.len,
                    required: out.len(),
                });
            }
            out.copy_from_slice(&self.as_slice()[..out.len()]);
            Ok(())
        }

        pub fn read_bytes(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
            if len > self.len {
                return Err(CryptoError::BufferTooSmall {
                    capacity: self.len,
                    required: len,
                });
            }
            Ok(self.as_slice()[..len].to_vec())
        }

        pub fn read_zeroizing(
            &self,
            len: usize,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
            self.read_bytes(len).map(zeroize::Zeroizing::new)
        }

        pub fn with_read_access<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(self.as_slice())
        }

        pub fn with_write_access<F, R>(&mut self, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            f(self.as_slice_mut())
        }

        pub fn try_clone(&self) -> Result<Self, CryptoError> {
            let mut copy = Self::allocate(self.len)?;
            copy.as_slice_mut().copy_from_slice(self.as_slice());
            Ok(copy)
        }
    }

    impl Drop for SecureMemoryHandle {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // Zero what the caller actually wrote first; the pool's
            // release() will zero the rest of the slot before
            // returning it to the free-list, preserving the
            // invariant that no fresh allocation ever reads stale
            // secret bytes.
            self.as_slice_mut().zeroize();
            pool().release(self.ptr, self.slot_size);
        }
    }
}

pub use inner::SecureMemoryHandle;

#[cfg(test)]
#[cfg(not(any(feature = "no-secure-memory", target_os = "ios", target_os = "windows")))]
mod tests {
    use super::*;

    #[test]
    fn allocate_then_drop_does_not_call_munlock() {
        // Indirect check: we get many small allocations and they all
        // succeed even though we never expose munlock to userland.
        // Earlier the per-allocation mlock would fail with EAGAIN at
        // ~1.5 GB locked; with the pool, every small allocation lands
        // inside the pre-mlocked region.
        let mut handles = Vec::with_capacity(10_000);
        for _ in 0..10_000 {
            handles.push(SecureMemoryHandle::allocate(32).unwrap());
        }
        // drop all
    }

    #[test]
    fn write_and_read_roundtrips() {
        let mut h = SecureMemoryHandle::allocate(40).unwrap();
        h.write(b"hello world some payload                ")
            .unwrap();
        let mut out = [0u8; 40];
        h.read(&mut out).unwrap();
        assert_eq!(&out[..11], b"hello world");
    }

    #[test]
    fn requested_len_is_what_caller_sees_not_slot_size() {
        let h = SecureMemoryHandle::allocate(33).unwrap();
        // Slot rounded to 64 internally, but the API reports the
        // requested size — callers depend on this for slice bounds.
        assert_eq!(h.size(), 33);
    }
}
