use std::{
    io,
    sync::{Arc, Mutex},
    time::Instant,
};

use futures::{future, prelude::*};
use itertools::Itertools;
use mastic::{
    collect::{self, ReportShare},
    config::{self, Mode},
    histogram_chunk_length, prg,
    rpc::{
        AddReportSharesRequest, ApplyFLPResultsRequest, AttributeBasedMetricsResultRequest,
        AttributeBasedMetricsValidateRequest, Collector, FinalSharesRequest, GetProofsRequest,
        PlainMetricsResultRequest, PlainMetricsValidateRequest, ResetRequest, RunFlpQueriesRequest,
        TreeCrawlLastRequest, TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    string_to_bits, vec_add, Mastic, HASH_SIZE,
};
use prio::{
    codec::{Encode, ParameterizedDecode},
    field::{Field128, FieldElement},
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PrepareShare, Prio3PublicShare},
        AggregateShare, Aggregator, PrepareTransition,
    },
};
use rayon::iter::{IntoParallelIterator, ParallelExtend, ParallelIterator};
use tarpc::{
    context,
    serde_transport::tcp,
    server::{
        Channel, {self},
    },
    tokio_serde::formats::Bincode,
};

#[derive(Clone)]
struct CollectorServer {
    server_id: i8,
    seed: prg::PrgSeed,
    data_bytes: usize,
    arc: Arc<Mutex<collect::KeyCollection>>,
}

#[tarpc::server]
impl Collector for CollectorServer {
    async fn reset(self, _: context::Context, req: ResetRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(
            Mastic::new_histogram(req.hist_buckets).unwrap(),
            self.server_id,
            &self.seed,
            self.data_bytes,
            req.verify_key,
        );
        "Done".to_string()
    }

    async fn add_report_shares(self, _: context::Context, req: AddReportSharesRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        for report_share in req.report_shares.into_iter() {
            coll.add_report_share(report_share);
        }
        if coll.report_shares.len() % 10000 == 0 {
            println!("Number of report shares: {:?}", coll.report_shares.len());
        }
        "Done".to_string()
    }

    async fn tree_init(self, _: context::Context, _req: TreeInitRequest) -> String {
        let start = Instant::now();
        let mut coll = self.arc.lock().unwrap();
        coll.tree_init();
        println!("tree_init: {:?}", start.elapsed().as_secs_f64());
        "Done".to_string()
    }

    async fn tree_crawl(
        self,
        _: context::Context,
        req: TreeCrawlRequest,
    ) -> (Vec<Vec<Field128>>, Vec<Vec<u8>>, Vec<usize>) {
        let start = Instant::now();
        let split_by = req.split_by;
        let malicious = req.malicious;
        let is_last = req.is_last;
        let mut coll = self.arc.lock().unwrap();

        let res = coll.tree_crawl(split_by, &malicious, is_last);
        println!("Tree crawl: {:?} sec.", start.elapsed().as_secs_f64());

        res
    }

    async fn run_flp_queries(
        self,
        _: context::Context,
        req: RunFlpQueriesRequest,
    ) -> Vec<Vec<Field128>> {
        let mut coll = self.arc.lock().unwrap();
        debug_assert!(req.start < req.end);

        coll.run_flp_queries(req.start, req.end)
    }

    async fn apply_flp_results(self, _: context::Context, req: ApplyFLPResultsRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        coll.apply_flp_results(&req.keep);
        "Done".to_string()
    }

    async fn tree_crawl_last(
        self,
        _: context::Context,
        _req: TreeCrawlLastRequest,
    ) -> Vec<Vec<Field128>> {
        let start = Instant::now();
        let mut coll = self.arc.lock().unwrap();

        let res = coll.tree_crawl_last();
        println!("Tree crawl last: {:?} sec.", start.elapsed().as_secs_f64());

        res
    }

    async fn get_proofs(self, _: context::Context, req: GetProofsRequest) -> Vec<[u8; HASH_SIZE]> {
        let coll = self.arc.lock().unwrap();
        debug_assert!(req.start < req.end);

        coll.get_proofs(req.start, req.end)
    }

    async fn tree_prune(self, _: context::Context, req: TreePruneRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune(&req.keep);
        "Done".to_string()
    }

    async fn final_shares(
        self,
        _: context::Context,
        _req: FinalSharesRequest,
    ) -> Vec<collect::Result> {
        let coll = self.arc.lock().unwrap();
        coll.final_shares()
    }

    async fn attribute_based_metrics_validate(
        self,
        _: context::Context,
        req: AttributeBasedMetricsValidateRequest,
    ) -> Vec<(Vec<Field128>, [u8; blake3::OUT_LEN])> {
        debug_assert!(req.start < req.end);
        let mut coll = self.arc.lock().unwrap();
        let mut results = Vec::with_capacity(req.end - req.start);

        results.par_extend((req.start..req.end).into_par_iter().map(|client_index| {
            let mut eval_proof = blake3::Hasher::new();
            let (values_share, beta_share) = coll.report_shares[client_index]
                .1
                .unwrap_vidpf_key()
                .eval_tree(
                    req.attributes
                        .iter()
                        .map(|attribute| string_to_bits(attribute)),
                    coll.mastic.input_len(),
                    &mut eval_proof,
                );

            let joint_rand = coll.flp_joint_rand(client_index);
            let query_rand = coll.flp_query_rand(client_index);
            let verifier_share = coll
                .mastic
                .query(
                    &beta_share,
                    coll.report_shares[client_index].1.unwrap_flp_proof_share(),
                    &query_rand,
                    &joint_rand,
                    2,
                )
                .unwrap();

            (
                client_index,
                values_share,
                verifier_share,
                *eval_proof.finalize().as_bytes(),
            )
        }));

        let mut resp = Vec::with_capacity(req.end - req.start);
        for (client_index, values_share, verifier_share, eval_proof) in results.into_iter() {
            resp.push((verifier_share, eval_proof));
            coll.attribute_based_metrics_state
                .insert(client_index, values_share);
        }

        resp
    }

    async fn attribute_based_metrics_result(
        self,
        _: context::Context,
        req: AttributeBasedMetricsResultRequest,
    ) -> Vec<Vec<Field128>> {
        debug_assert!(req.start < req.end);
        let mut coll = self.arc.lock().unwrap();

        for rejected_client_index in req.rejected {
            debug_assert!(
                coll.attribute_based_metrics_state
                    .remove(&rejected_client_index)
                    .is_some()
            );
        }

        let mut agg_share =
            vec![vec![Field128::zero(); coll.mastic.input_len()]; req.num_attributes];
        for (_clinet_index, values_share) in coll.attribute_based_metrics_state.iter() {
            for (a, v) in agg_share.iter_mut().zip(values_share.iter()) {
                vec_add(a, v);
            }
        }

        agg_share
    }

    async fn plain_metrics_validate(
        self,
        _: context::Context,
        req: PlainMetricsValidateRequest,
    ) -> Vec<Vec<u8>> {
        debug_assert!(req.start < req.end);
        let mut coll = self.arc.lock().unwrap();
        let mut results = Vec::with_capacity(req.end - req.start);
        let agg_id = self.server_id.try_into().unwrap();
        let chunk_length = histogram_chunk_length(coll.mastic.input_len(), Mode::PlainMetrics);
        let prio3 = Prio3::new_histogram(2, coll.mastic.input_len(), chunk_length).unwrap();

        results.par_extend((req.start..req.end).into_par_iter().map(|client_index| {
            let ReportShare::Prio3 {
                nonce,
                public_share_bytes,
                input_share_bytes,
            } = &coll.report_shares[client_index].1
            else {
                panic!("tried to call plain_metrics_validate() on report of incorrect type");
            };

            let public_share =
                Prio3PublicShare::get_decoded_with_param(&prio3, public_share_bytes).unwrap();
            let input_share =
                Prio3InputShare::get_decoded_with_param(&(&prio3, agg_id), input_share_bytes)
                    .unwrap();

            let (prep_state, prep_share) = prio3
                .prepare_init(
                    &coll.verify_key,
                    agg_id,
                    &(),
                    nonce,
                    &public_share,
                    &input_share,
                )
                .unwrap();

            (client_index, prep_state, prep_share)
        }));

        let mut resp = Vec::with_capacity(req.end - req.start);
        for (client_index, prep_state, prep_share) in results.into_iter() {
            resp.push(prep_share.get_encoded());
            coll.plain_metrics_state
                .insert(client_index, (prep_state, prep_share));
        }

        resp
    }

    async fn plain_metrics_result(
        self,
        _: context::Context,
        req: PlainMetricsResultRequest,
    ) -> (AggregateShare<Field128>, usize) {
        debug_assert!(req.start < req.end);
        let mut coll = self.arc.lock().unwrap();
        let chunk_length = histogram_chunk_length(coll.mastic.input_len(), Mode::PlainMetrics);
        let prio3 = Prio3::new_histogram(2, coll.mastic.input_len(), chunk_length).unwrap();

        let out_shares = (req.start..req.end)
            .zip(req.peer_prep_shares.into_iter())
            .filter_map(|(client_index, peer_prep_share)| {
                let (prep_state, prep_share) =
                    coll.plain_metrics_state.remove(&client_index).unwrap();
                let peer_prep_share =
                    Prio3PrepareShare::get_decoded_with_param(&prep_state, &peer_prep_share)
                        .unwrap();
                let prep_shares = if self.server_id == 0 {
                    [prep_share, peer_prep_share]
                } else {
                    [peer_prep_share, prep_share]
                };

                let Ok(prep_msg) = prio3.prepare_shares_to_prepare_message(&(), prep_shares) else {
                    return None; // rejected
                };

                match prio3.prepare_next(prep_state, prep_msg) {
                    Ok(PrepareTransition::Finish(out_share)) => Some(out_share),
                    Ok(..) => panic!("unexpected transition"),
                    Err(_) => None, // rejected
                }
            })
            .collect_vec();

        let rejected = req.end - req.start - out_shares.len();
        let agg_share = prio3.aggregate(&(), out_shares).unwrap();

        (agg_share, rejected)
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let (cfg, server_id, _, _) = config::get_args("Server", true, false, false);
    let server_addr = match server_id {
        0 => cfg.server_0,
        1 => cfg.server_1,
        _ => panic!("Oh no!"),
    };

    let seed = prg::PrgSeed { key: [1u8; 16] };
    let mastic = Mastic::new_histogram(cfg.hist_buckets).unwrap();

    let coll = collect::KeyCollection::new(
        mastic.clone(),
        server_id,
        &seed,
        cfg.data_bytes * 8,
        [0u8; 16],
    );
    let arc = Arc::new(Mutex::new(coll));

    println!("Server {} running at {:?}", server_id, server_addr);
    // Listen on any IP
    let listener = tcp::listen(&server_addr, Bincode::default).await?;
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let server = CollectorServer {
                server_id,
                seed: seed.clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc.clone(),
            };

            channel.execute(server.serve())
        })
        // Max 10 channels.
        .buffer_unordered(100)
        .for_each(|_| async {})
        .await;

    Ok(())
}
