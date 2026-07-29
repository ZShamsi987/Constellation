//! Generates the canonical Rust protobuf and `Tonic` bindings.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protocol_root = PathBuf::from("../../protocol");
    let files = [
        "constellation/v1/common.proto",
        "constellation/v1/enrollment.proto",
        "constellation/v1/event.proto",
        "constellation/v1/model.proto",
        "constellation/v1/node.proto",
        "constellation/v1/runtime.proto",
        "constellation/v1/workload.proto",
    ]
    .map(|file| protocol_root.join(file));
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(
            PathBuf::from(std::env::var("OUT_DIR")?).join("constellation_descriptor.bin"),
        )
        .compile_with_config(
            prost,
            &files,
            &[protocol_root, protoc_bin_vendored::include_path()?],
        )?;
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    Ok(())
}
