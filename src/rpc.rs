use prio::field::Field64;
use serde::{Deserialize, Serialize};

use crate::{collect, vidpf, BetaType, HASH_SIZE};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {
    pub verify_key: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub keys: Vec<vidpf::VIDPFKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddFLPsRequest {
    pub flp_proof_shares: Vec<Vec<Field64>>,
    pub nonces: Vec<[u8; 16]>,
    pub jr_parts: Vec<[[u8; 16]; 2]>,
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
pub struct GetProofsRequest {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunFlpQueriesRequest {
    pub start: usize,
    pub end: usize,
}

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
    async fn tree_crawl(req: TreeCrawlRequest) -> (Vec<BetaType>, Vec<Vec<u8>>, Vec<usize>);
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> Vec<BetaType>;
    async fn get_proofs(req: GetProofsRequest) -> Vec<[u8; HASH_SIZE]>;
    async fn tree_init(req: TreeInitRequest) -> String;
    async fn tree_prune(req: TreePruneRequest) -> String;
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result>;
}
