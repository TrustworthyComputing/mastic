use std::{
    io,
    sync::{Arc, Mutex},
    time::Instant,
};

use futures::{future, prelude::*};
use mastic::{
    collect, config, prg,
    rpc::{
        AddFLPsRequest, AddKeysRequest, ApplyFLPResultsRequest, Collector, FinalSharesRequest,
        GetProofsRequest, ResetRequest, RunFlpQueriesRequest, TreeCrawlLastRequest,
        TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    HASH_SIZE,
};
use prio::{field::Field64, flp::types::Count};
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
    data_bits: usize,
    arc: Arc<Mutex<collect::KeyCollection>>,
}

#[tarpc::server]
impl Collector for CollectorServer {
    async fn reset(self, _: context::Context, req: ResetRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(
            Count::new(),
            self.server_id,
            &self.seed,
            self.data_bits,
            req.verify_key,
        );
        "Done".to_string()
    }

    async fn add_keys(self, _: context::Context, req: AddKeysRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        for k in req.keys {
            coll.add_key(k);
        }
        if coll.keys.len() % 10000 == 0 {
            println!("Number of keys: {:?}", coll.keys.len());
        }
        "Done".to_string()
    }

    async fn add_all_flp_proof_shares(self, _: context::Context, req: AddFLPsRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        for ((flp_proof_share, nonce), jr_parts) in req
            .flp_proof_shares
            .into_iter()
            .zip(req.nonces)
            .zip(req.jr_parts)
        {
            coll.add_flp_proof_share(flp_proof_share, nonce, jr_parts);
        }
        if coll.keys.len() % 10000 == 0 {
            println!("Number of keys: {:?}", coll.keys.len());
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
    ) -> (Vec<Vec<Field64>>, Vec<Vec<u8>>, Vec<usize>) {
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
    ) -> Vec<Vec<Field64>> {
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
    ) -> Vec<Vec<Field64>> {
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
    let typ = Count::<Field64>::new();

    let coll = collect::KeyCollection::new(typ.clone(), server_id, &seed, cfg.data_bits, [0u8; 16]);
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
                data_bits: cfg.data_bits,
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
