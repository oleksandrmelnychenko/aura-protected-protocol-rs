// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::io::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let proto_root = PathBuf::from("proto");
    let proto_files = [
        "proto/protocol/state.proto",
        "proto/protocol/handshake.proto",
        "proto/protocol/envelope.proto",
        "proto/protocol/sealed_state.proto",
        "proto/protocol/attachment.proto",
        "proto/protocol/error.proto",
        "proto/protocol/group.proto",
        "proto/protocol/voip.proto",
        "proto/e2e/crypto_envelope.proto",
    ];

    for f in &proto_files {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-changed=proto/google/protobuf/timestamp.proto");

    prost_build::compile_protos(&proto_files, &[proto_root])?;

    Ok(())
}
