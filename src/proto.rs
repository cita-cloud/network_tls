mod blockchain {
    tonic::include_proto!("blockchain");
}

mod common {
    tonic::include_proto!("common");
}

mod network {
    tonic::include_proto!("network");
}

pub use network::NetworkMsg;
