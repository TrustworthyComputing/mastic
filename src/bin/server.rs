use mastic::{
    collect, config, prg,
    rpc::{
        AddKeysRequest, Collector, FinalSharesRequest, ResetRequest, TreeCrawlLastRequest,
        TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
};

use futures::{future, prelude::*};
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
    server_id: i8,
    seed: prg::PrgSeed,
    data_bytes: usize,
    arc: Arc<Mutex<collect::KeyCollection<u64>>>,
}

#[tarpc::server]
impl Collector for CollectorServer {
    async fn reset(self, _: context::Context, _req: ResetRequest) -> String {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(self.server_id, &self.seed, self.data_bytes);
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
    ) -> (Vec<u64>, Vec<Vec<u8>>, Vec<usize>) {
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
    ) -> (Vec<u64>, Vec<[u8; 32]>) {
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

    async fn final_shares(
        self,
        _: context::Context,
        _req: FinalSharesRequest,
    ) -> Vec<collect::Result<u64>> {
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

    let coll = collect::KeyCollection::new(server_id, &seed, cfg.data_bytes * 8);
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
