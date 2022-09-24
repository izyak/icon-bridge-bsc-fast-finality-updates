//! BTP Message Center

use btp_common::errors::{BmcError, BtpException, Exception, BshError};
use libraries::{
    emit_message,
    types::{
        messages::{
            BmcServiceMessage, BmcServiceType, BtpMessage, ErrorMessage, SerializedBtpMessages,
            SerializedMessage,
        },
        Service,

        HashedCollection,
        Address, BTPAddress, BmcEvent, Connection, Connections, Links, RelayStatus,
        Network, Owners, Routes, Services, Math, LinkStatus, Link
    },
};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde_json::{to_value, Value};
use near_sdk::AccountId;
use near_sdk::{
    PromiseResult,
    env,
    json_types::{Base64VecU8, U128, U64},
    log, near_bindgen, require, serde_json, Gas, PanicOnDefault,
};
use std::convert::TryInto;

mod assertion;
mod estimate;
mod external;
mod internal_service;
mod link_management;
mod messaging;
mod owner_management;
mod relay_management;
mod route_management;
mod service_management;
mod types;
pub use types::RelayMessage;
use external::*;

const SERVICE: &str = "bmc";

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct BtpMessageCenter {
    block_interval: u64,
    btp_address: BTPAddress,
    owners: Owners,
    services: Services,
    links: Links,
    routes: Routes,
    connections: Connections,
    event: BmcEvent,
}

#[near_bindgen]
impl BtpMessageCenter {
    #[init]
    pub fn new(network: String, block_interval: u64) -> Self {
        require!(!env::state_exists(), "Already initialized");
        let mut owners = Owners::new();
        owners.add(&env::current_account_id());
        Self {
            block_interval,
            btp_address: BTPAddress::new(format!(
                "btp://{}/{}",
                network,
                env::current_account_id()
            )),
            owners,
            services: Services::new(),
            links: Links::new(),
            routes: Routes::new(),
            connections: Connections::new(),
            event: BmcEvent::new(),
        }
    }
}