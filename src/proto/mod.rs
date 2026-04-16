// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::redundant_closure,
    clippy::match_single_binding,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::default_trait_access,
    clippy::missing_const_for_fn
)]
mod proto_inner {
    include!(concat!(env!("OUT_DIR"), "/aura.proto.protocol.rs"));
}
pub use proto_inner::*;

pub mod e2e {
    #[allow(
        clippy::derive_partial_eq_without_eq,
        clippy::redundant_closure,
        clippy::match_single_binding,
        clippy::must_use_candidate,
        clippy::struct_excessive_bools,
        clippy::default_trait_access,
        clippy::missing_const_for_fn
    )]
    mod inner {
        include!(concat!(env!("OUT_DIR"), "/aura.proto.e2e.rs"));
    }
    pub use inner::*;
}
