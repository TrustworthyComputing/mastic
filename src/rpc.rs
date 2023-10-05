use crate::collect;
use crate::dpf;
use crate::fastfield::FE;
use crate::FieldElm;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub keys: Vec<dpf::DPFKey<FE, FieldElm>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeInitRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeCrawlRequest {
    pub split_by: usize,
    pub malicious: Vec<usize>,
    pub is_last: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeCrawlLastRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreePruneRequest {
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreePruneLastRequest {
    pub keep: Vec<bool>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct ComputeHashesRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddLeavesBetweenClientsRequest {
    pub verified: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalSharesRequest {}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: ResetRequest) -> String;
    async fn add_keys(add: AddKeysRequest) -> String;
    async fn tree_init(req: TreeInitRequest) -> String;
    async fn tree_crawl(req: TreeCrawlRequest) -> (Vec<FE>, Vec<Vec<Vec<u8>>>, Vec<Vec<usize>>);
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> (Vec<Vec<u8>>, Vec<FieldElm>);
    async fn tree_prune(req: TreePruneRequest) -> String;
    async fn tree_prune_last(req: TreePruneLastRequest) -> String;
    // async fn compute_hashes(req: ComputeHashesRequest) -> Vec<Vec<u8>>;
    async fn add_leaves_between_clients(
        req: AddLeavesBetweenClientsRequest,
    ) -> Vec<collect::Result<FieldElm>>;
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result<FieldElm>>;
}
