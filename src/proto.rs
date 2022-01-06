// protos are from https://github.com/cita-cloud/cita_cloud_proto
// version: 6.3.0

mod blockchain {
    tonic::include_proto!("blockchain");
}

mod common {
    tonic::include_proto!("common");
}

mod network {
    tonic::include_proto!("network");
}

pub use common::Empty;
pub use common::NodeNetInfo;
pub use common::StatusCode;
pub use common::TotalNodeNetInfo;

pub use network::network_msg_handler_service_client::NetworkMsgHandlerServiceClient;
pub use network::network_service_server::{NetworkService, NetworkServiceServer};
pub use network::NetworkMsg;
pub use network::NetworkStatusResponse;
pub use network::RegisterInfo;
