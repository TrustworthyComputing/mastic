use crate::collect;
use crate::dpf;
use crate::FieldElm;
use crate::fastfield::FE;
// use crate::mpc::{ManyCor, ManyOutShare};

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub keys: Vec<dpf::DPFKey<FE,FieldElm>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeInitRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeCrawlRequest {}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalSharesRequest {}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: ResetRequest) -> String;
    async fn add_keys(add: AddKeysRequest) -> String;
    async fn tree_init(req: TreeInitRequest) -> String;
    async fn tree_crawl(req: TreeCrawlRequest) -> Vec<FE>;
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> Vec<FieldElm>;
    async fn tree_prune(req: TreePruneRequest) -> String;
    async fn tree_prune_last(req: TreePruneLastRequest) -> String;
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result<FieldElm>>;
}
