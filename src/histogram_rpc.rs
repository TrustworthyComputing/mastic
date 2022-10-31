use crate::collect;
use crate::dpf;
use crate::FieldElm;
use crate::fastfield::FE;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramResetRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramAddKeysRequest {
    pub keys: Vec<dpf::DPFKey<FE,FieldElm>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramTreeInitRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramTreeCrawlRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramTreeCrawlLastRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramTreePruneRequest {
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramTreePruneLastRequest {
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistogramFinalSharesRequest {}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: HistogramResetRequest) -> String;
    async fn add_keys(add: HistogramAddKeysRequest) -> String;
    async fn tree_init(req: HistogramTreeInitRequest) -> String;
    async fn tree_crawl(req: HistogramTreeCrawlRequest) -> Vec<FE>;
    async fn tree_crawl_last(req: HistogramTreeCrawlLastRequest) -> Vec<FieldElm>;
    async fn tree_prune(req: HistogramTreePruneRequest) -> String;
    async fn tree_prune_last(req: HistogramTreePruneLastRequest) -> String;
    async fn final_shares(req: HistogramFinalSharesRequest) -> Vec<collect::Result<FieldElm>>;
}
