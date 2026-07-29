//! Generated, versioned protobuf and `Tonic` service contracts.

/// Stable v1 protocol package generated from the canonical `.proto` sources.
#[allow(missing_docs, clippy::all, clippy::pedantic)] // Generated code is linted by Buf/protoc, not handwritten Rust policy.
pub mod v1 {
    tonic::include_proto!("constellation.v1");

    /// Canonical descriptor set used by protocol golden and reflection tests.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("constellation_descriptor");
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::v1::{FILE_DESCRIPTOR_SET, ProtocolVersion};

    #[test]
    fn generated_contract_round_trips_and_has_descriptors() {
        let version = ProtocolVersion {
            current: 1,
            minimum_supported: 1,
            maximum_supported: 1,
        };
        let encoded = version.encode_to_vec();
        assert_eq!(
            ProtocolVersion::decode(encoded.as_slice()).ok(),
            Some(version)
        );
        assert!(!FILE_DESCRIPTOR_SET.is_empty());
    }
}
