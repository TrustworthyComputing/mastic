use prio::field::Field64;
use serde::{Deserialize, Serialize};

use crate::{collect, dpf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {
    pub verify_key: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub keys: Vec<dpf::DPFKey<Field64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddFLPsRequest {
    pub flp_proof_shares: Vec<Vec<Field64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyFLPResultsRequest {
    pub keep: Vec<bool>,
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
pub struct RunFlpQueriesRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreePruneRequest {
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalSharesRequest {}

#[tarpc::service]
pub trait Collector {
    async fn reset(req: ResetRequest) -> String;
    async fn add_keys(req: AddKeysRequest) -> String;
    async fn add_all_flp_proof_shares(req: AddFLPsRequest) -> String;
    async fn run_flp_queries(req: RunFlpQueriesRequest) -> Vec<Vec<Field64>>;
    async fn apply_flp_results(req: ApplyFLPResultsRequest) -> String;
    async fn tree_crawl(req: TreeCrawlRequest) -> (Vec<Field64>, Vec<Vec<u8>>, Vec<usize>);
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> (Vec<Field64>, Vec<[u8; 32]>);
    async fn tree_init(req: TreeInitRequest) -> String;
    async fn tree_prune(req: TreePruneRequest) -> String;
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result<Field64>>;
}
