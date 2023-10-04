use mastic::{
    collect, config,
    fastfield::FE,
    prg,
    rpc::{
        AddKeysRequest, AddLeavesBetweenClientsRequest, Collector, ComputeHashesRequest,
        FinalSharesRequest, ResetRequest, TreeCrawlLastRequest, TreeCrawlRequest, TreeInitRequest,
        TreePruneLastRequest, TreePruneRequest,
    },
    xor_vec, FieldElm,
};

use futures::{future, prelude::*};
use sha2::{Digest, Sha256};
use std::time::Instant;
use std::{
    io,
    sync::{Arc, Mutex},
};
use tarpc::{
    context,
    serde_transport::tcp,
    server::{self, Channel},
    tokio_serde::formats::Bincode,
};

#[derive(Clone)]
struct CollectorServer {
    seed: prg::PrgSeed,
    data_bytes: usize,
    arc: Arc<Mutex<collect::KeyCollection<FE, FieldElm>>>,
}

#[tarpc::server]
impl Collector for CollectorServer {
    async fn reset(self, _: context::Context, _req: ResetRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(&self.seed, self.data_bytes * 8);
        "Done".to_string()
    }

    async fn add_keys(self, _: context::Context, req: AddKeysRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        for k in req.keys {
            coll.add_key(k);
        }
        if coll.keys.len() % 1000 == 0 {
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
    ) -> (Vec<FE>, Vec<Vec<Vec<u8>>>, Vec<Vec<usize>>) {
        // let start = Instant::now();
        let split_by = req.split_by;
        let malicious = req.malicious;
        let is_last = req.is_last;
        let mut coll = self.arc.lock().unwrap();

        coll.tree_crawl(split_by, &malicious, is_last)
    }

    async fn tree_crawl_last(
        self,
        _: context::Context,
        _req: TreeCrawlLastRequest,
    ) -> (Vec<Vec<u8>>, Vec<FieldElm>) {
        let start = Instant::now();
        let mut coll = self.arc.lock().unwrap();
        let res = coll.tree_crawl_last();
        println!("tree_crawl_last: {:?}", start.elapsed().as_secs_f64());
        res
    }

    async fn tree_prune(self, _: context::Context, req: TreePruneRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune(&req.keep);
        "Done".to_string()
    }

    async fn tree_prune_last(self, _: context::Context, req: TreePruneLastRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune_last(&req.keep);
        "Done".to_string()
    }

    async fn compute_hashes(self, _: context::Context, _req: ComputeHashesRequest) -> Vec<Vec<u8>> {
        let start = Instant::now();
        let coll_0 = self.arc.lock().unwrap();
        let y_0 = coll_0.get_ys();

        // let mut y0_y1: Vec<Vec<FieldElm>> = vec![];
        // for i in 0..y_0[0].len() {
        //     y0_y1.push(
        //         y_0.par_iter()
        //             // .zip_eq(y_1.par_iter())
        //             .map(|(h0)| {
        //                 let elm = h0[i].clone();
        //                 // elm.sub(&h1[i]);
        //                 elm
        //             })
        //             .collect(),
        //     );
        // }
        let mut hashes: Vec<Vec<u8>> = vec![];
        let mut hasher = Sha256::new();
        for _client in 0..y_0.len() {
            // for y in y0_y1[client].iter() {
            //     hasher.update(y.value().to_string());
            // }
            hashes.push(hasher.finalize_reset().to_vec());
        }
        println!("compute_hashes: {:?}", start.elapsed().as_secs_f64());

        if mastic::consts::BATCH {
            let mut batched_hash = vec![0u8; 32];
            for hash in hashes {
                batched_hash = xor_vec(&batched_hash, &hash);
            }
            vec![batched_hash]
        } else {
            hashes
        }
    }

    async fn add_leaves_between_clients(
        self,
        _: context::Context,
        req: AddLeavesBetweenClientsRequest,
    ) -> Vec<collect::Result<FieldElm>> {
        let start = Instant::now();
        let mut coll = self.arc.lock().unwrap();
        let res = coll.add_leaves_between_clients(&req.verified);
        println!(
            "add_leaves_between_clients: {:?}",
            start.elapsed().as_secs_f64()
        );
        res
    }

    async fn final_shares(
        self,
        _: context::Context,
        _req: FinalSharesRequest,
    ) -> Vec<collect::Result<FieldElm>> {
        let coll = self.arc.lock().unwrap();
        coll.final_shares()
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let (cfg, sid, _, _) = config::get_args("Server", true, false, false);
    let server_addr = match sid {
        0 => cfg.server_0,
        1 => cfg.server_1,
        _ => panic!("Oh no!"),
    };

    let seed = prg::PrgSeed { key: [1u8; 16] };

    let coll_0 = collect::KeyCollection::new(&seed, cfg.data_bytes * 8);
    let arc = Arc::new(Mutex::new(coll_0));

    println!("Server {} running at {:?}", sid, server_addr);
    // Listen on any IP
    let listener = tcp::listen(&server_addr, Bincode::default).await?;
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| {
            let server = CollectorServer {
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
