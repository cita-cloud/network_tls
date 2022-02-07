// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
