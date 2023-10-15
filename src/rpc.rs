use crate::collect;
use crate::dpf;

use prio::field::Field64;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub keys: Vec<dpf::DPFKey<Field64, Field64>>,
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
pub struct FinalSharesRequest {}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: ResetRequest) -> String;
    async fn add_keys(add: AddKeysRequest) -> String;
    async fn tree_init(req: TreeInitRequest) -> String;
    async fn tree_crawl(req: TreeCrawlRequest) -> (Vec<Field64>, Vec<Vec<u8>>, Vec<usize>);
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> (Vec<Field64>, Vec<[u8; 32]>);
    async fn tree_prune(req: TreePruneRequest) -> String;
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result<Field64>>;
}
