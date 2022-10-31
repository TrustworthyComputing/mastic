use crate::collect;
use crate::dpf;
use crate::FieldElm;
use crate::fastfield::FE;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfResetRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfAddKeysRequest {
    pub keys: Vec<dpf::DPFKey<FE,FieldElm>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfTreeInitRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfTreeCrawlRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfTreeCrawlLastRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfTreePruneRequest {
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfTreePruneLastRequest {
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpfFinalSharesRequest {}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: IdpfResetRequest) -> String;
    async fn add_keys(add: IdpfAddKeysRequest) -> String;
    async fn tree_init(req: IdpfTreeInitRequest) -> String;
    async fn tree_crawl(req: IdpfTreeCrawlRequest) -> Vec<FE>;
    async fn tree_crawl_last(req: IdpfTreeCrawlLastRequest) -> Vec<FieldElm>;
    async fn tree_prune(req: IdpfTreePruneRequest) -> String;
    async fn tree_prune_last(req: IdpfTreePruneLastRequest) -> String;
    async fn final_shares(req: IdpfFinalSharesRequest) -> Vec<collect::Result<FieldElm>>;
}
