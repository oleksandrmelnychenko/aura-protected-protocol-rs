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

    pub struct SecureMemoryHandle {
        data: Box<[u8]>,
        mlocked: bool,
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
            #[allow(unused_mut)]
            let mut data = vec![0u8; size].into_boxed_slice();
            let mlocked =
                unsafe { libc::mlock(data.as_ptr().cast::<libc::c_void>(), data.len()) == 0 };
            #[cfg(target_os = "linux")]
            if mlocked {
                unsafe {
                    libc::madvise(
                        data.as_mut_ptr().cast::<libc::c_void>(),
                        data.len(),
                        libc::MADV_DONTDUMP,
                    );
                }
            }
            Ok(Self { data, mlocked })
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
            let mut new = Self::allocate(self.data.len())?;
            new.data.copy_from_slice(&self.data);
            Ok(new)
        }
    }

    impl Drop for SecureMemoryHandle {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            self.data.zeroize();
            if self.mlocked {
                unsafe {
                    libc::munlock(self.data.as_ptr().cast::<libc::c_void>(), self.data.len());
                }
            }
        }
    }
}

pub use inner::SecureMemoryHandle;
