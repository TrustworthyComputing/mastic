use prio::field::Field64;
use serde::{Deserialize, Serialize};

use crate::{collect, vidpf, HASH_SIZE};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {
    pub verify_key: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub keys: Vec<vidpf::VidpfKey>,
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
    /// Initialize the tree (single root that has all the clients keys and values).
    async fn tree_init(req: TreeInitRequest) -> String;

    /// Reset the collector to its initial state.
    async fn reset(req: ResetRequest) -> String;

    /// Add a batch of keys to the collector.
    async fn add_keys(req: AddKeysRequest) -> String;

    /// Add a batch of FLP proof shares to the collector.
    async fn add_all_flp_proof_shares(req: AddFLPsRequest) -> String;

    /// Run FLP proof queries.
    async fn run_flp_queries(req: RunFlpQueriesRequest) -> Vec<Vec<Field64>>;

    /// Apply FLP proof results and remove the malicious clients (i.e., the clients whose the FLP
    /// was not successful) from the key collection.
    async fn apply_flp_results(req: ApplyFLPResultsRequest) -> String;

    /// Crawl the tree and return the evaluations, the Merkle tree root, and the indices of the
    /// Merkle tree.
    async fn tree_crawl(req: TreeCrawlRequest) -> (Vec<Vec<Field64>>, Vec<Vec<u8>>, Vec<usize>);

    /// Crawl the last level of the tree and return the evaluations for different prefixes.
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> Vec<Vec<Field64>>;

    /// Return the final VIDPF proofs.
    async fn get_proofs(req: GetProofsRequest) -> Vec<[u8; HASH_SIZE]>;

    /// Prune the tree and keep only heavy-hitter paths.
    async fn tree_prune(req: TreePruneRequest) -> String;

    /// Get the final paths and secret shared values.
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result>;
}
