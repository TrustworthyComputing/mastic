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
pub struct HistogramAddLeavesBetweenClientsRequest {
    pub verified: Vec<bool>,
}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: HistogramResetRequest) -> String;
    async fn add_keys(add: HistogramAddKeysRequest) -> String;
    async fn tree_init(req: HistogramTreeInitRequest) -> String;
    async fn histogram_tree_crawl(req: HistogramTreeCrawlRequest) -> String;
    async fn histogram_tree_crawl_last(req: HistogramTreeCrawlLastRequest) -> (Vec<Vec<u8>>, Vec<FieldElm>);
    async fn histogram_add_leaves_between_clients(req: HistogramAddLeavesBetweenClientsRequest) -> Vec<collect::Result<FieldElm>>;
}
