use crate::collect;
use crate::dpf;
use crate::FieldElm;
use crate::fastfield::FE;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHResetRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHAddKeysRequest {
    pub client_idx: u8,
    pub keys: Vec<dpf::DPFKey<FE,FieldElm>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHTreeInitRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHTreeCrawlRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHTreeCrawlLastRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHTreePruneRequest {
    pub client_idx: u8,
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHTreePruneLastRequest {
    pub client_idx: u8,
    pub keep: Vec<bool>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHComputeHashesRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHAddLeavesBetweenClientsRequest {
    pub client_idx: u8,
    pub verified: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HHFinalSharesRequest {
    pub client_idx: u8,
    pub verified: Vec<bool>,
}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: HHResetRequest) -> String;
    async fn add_keys(add: HHAddKeysRequest) -> String;
    async fn tree_init(req: HHTreeInitRequest) -> String;
    async fn tree_crawl(req: HHTreeCrawlRequest) -> String;
    async fn tree_crawl_last(req: HHTreeCrawlLastRequest) -> (Vec<Vec<u8>>, Vec<FieldElm>);
    // async fn tree_prune(req: HHTreePruneRequest) -> String;
    // async fn tree_prune_last(req: HHTreePruneLastRequest) -> String;
    async fn compute_hashes(req: HHComputeHashesRequest) -> Vec<Vec<u8>>;
    async fn add_leaves_between_clients(req: HHAddLeavesBetweenClientsRequest) -> Vec<collect::Result<FieldElm>>;
    // async fn final_shares(req: HHFinalSharesRequest) -> Vec<collect::Result<FieldElm>>;
}
