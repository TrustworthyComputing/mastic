use prio::field::Field128;
use serde::{Deserialize, Serialize};

use crate::{
    collect::{self, ReportShare},
    HASH_SIZE,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {
    pub verify_key: [u8; 16],
    pub hist_buckets: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddReportSharesRequest {
    pub report_shares: Vec<ReportShare>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateByAttributesValidateRequest {
    pub attributes: Vec<String>,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateByAttributesResultRequest {
    pub rejected: Vec<usize>,
    pub num_attributes: usize,
    pub start: usize,
    pub end: usize,
}

#[tarpc::service]
pub trait Collector {
    /// Initialize the tree (single root that has all the clients keys and values).
    async fn tree_init(req: TreeInitRequest) -> String;

    /// Reset the collector to its initial state.
    async fn reset(req: ResetRequest) -> String;

    /// Add a batch of report shares to the collector.
    async fn add_report_shares(req: AddReportSharesRequest) -> String;

    /// Run FLP proof queries.
    async fn run_flp_queries(req: RunFlpQueriesRequest) -> Vec<Vec<Field128>>;

    /// Apply FLP proof results and remove the malicious clients (i.e., the clients whose the FLP
    /// was not successful) from the key collection.
    async fn apply_flp_results(req: ApplyFLPResultsRequest) -> String;

    /// Crawl the tree and return the evaluations, the Merkle tree root, and the indices of the
    /// Merkle tree.
    async fn tree_crawl(req: TreeCrawlRequest) -> (Vec<Vec<Field128>>, Vec<Vec<u8>>, Vec<usize>);

    /// Crawl the last level of the tree and return the evaluations for different prefixes.
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> Vec<Vec<Field128>>;

    /// Return the final VIDPF proofs.
    async fn get_proofs(req: GetProofsRequest) -> Vec<[u8; HASH_SIZE]>;

    /// Prune the tree and keep only heavy-hitter paths.
    async fn tree_prune(req: TreePruneRequest) -> String;

    /// Get the final paths and secret shared values.
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result>;

    /// For the subset of reports indicated by the caller, evaluate the VIDPF key on the provided set
    /// of attributes and return the VIDPF proof and FLP verifier share.
    async fn aggregate_by_attributes_start(
        req: AggregateByAttributesValidateRequest,
    ) -> Vec<(Vec<Field128>, [u8; blake3::OUT_LEN])>;

    /// For the subset of reports indicated by the caller, compute the aggregate share, rejecting
    /// the reports indicated by the caller. This method should be called only after calling
    /// `aggregate_by_attributes_start` on the same set of reports.
    async fn aggregate_by_attributes_finish(
        req: AggregateByAttributesResultRequest,
    ) -> Vec<Vec<Field128>>;
}
