use plasma::{
    collect,
    config,
    FieldElm,
    fastfield::FE,
    Group,
    histogram_rpc::{
        Collector,
        HistogramAddKeysRequest,
        HistogramTreeInitRequest,
        HistogramResetRequest,
        HistogramTreeCrawlRequest, 
        HistogramTreeCrawlLastRequest,
        HistogramComputeHashesRequest,
        HistogramAddLeavesBetweenClientsRequest,
    },
    prg,
    xor_vec,
};

use futures::{future, prelude::*,};
use std::{io, sync::{Arc, Mutex},};
use sha2::{Sha256, Digest};
use rayon::prelude::*;
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Json,
    serde_transport::tcp,
};
use std::time::Instant;
#[derive(Clone)]
struct CollectorServer {
    seed: prg::PrgSeed,
    data_bytes: usize,
    arc: Arc<Mutex<collect::KeyCollection<FE,FieldElm>>>,
}

#[derive(Clone)]
struct BatchCollectorServer {
    cs: Vec<CollectorServer>,
}

#[tarpc::server]
impl Collector for BatchCollectorServer {

    async fn reset(self,
         _: context::Context, req: HistogramResetRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        *coll = collect::KeyCollection::new(
            &self.cs[client_idx].seed, self.cs[client_idx].data_bytes * 8
        );
        "Done".to_string()
    }

    async fn add_keys(self,
         _: context::Context, req: HistogramAddKeysRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        for k in req.keys {
            coll.add_key(k);
        }
        if coll.keys.len() % 1000 == 0 {
            println!("SID {}) Number of keys: {:?}", client_idx, coll.keys.len());
        }
        "Done".to_string()
    }

    async fn tree_init(self,
        _: context::Context, req: HistogramTreeInitRequest
    ) -> String {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.tree_init();
        println!("session {:?}: tree_init: {:?}", client_idx, start.elapsed().as_secs_f64());
        "Done".to_string()
    }

    async fn histogram_tree_crawl(self, 
        _: context::Context, req: HistogramTreeCrawlRequest
    ) -> String {
        // let start = Instant::now();
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.histogram_tree_crawl();
        // println!("session {:?}: histogram_tree_crawl: {:?}", client_idx, start.elapsed().as_secs_f64());
        "Done".to_string()
    }

    async fn tree_crawl_last(self, 
        _: context::Context, req: HistogramTreeCrawlLastRequest
    ) -> (Vec<Vec<u8>>, Vec<FieldElm>) {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        let res = coll.tree_crawl_last();
        println!("session {:?}: tree_crawl_last: {:?}", client_idx, start.elapsed().as_secs_f64());
        res
    }

    async fn histogram_compute_hashes(self, 
        _: context::Context, req: HistogramComputeHashesRequest
    ) -> Vec<Vec<u8>> {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let coll_0 = self.cs[0].arc.lock().unwrap();
        let coll_1 = self.cs[1].arc.lock().unwrap();
        let coll_2 = self.cs[2].arc.lock().unwrap();
        let (y_0, y_1) = match client_idx {
            0 => (coll_2.get_ys(), coll_0.get_ys()),
            1 => (coll_1.get_ys(), coll_2.get_ys()),
            _ => panic!("Oh no!"),
        };
        let mut y0_y1: Vec<Vec<FieldElm>> = vec![];
        for i in 0..y_0[0].len() {
            y0_y1.push(
                y_0
                    .par_iter()
                    .zip_eq(y_1.par_iter())
                    .map(|(h0, h1)| {
                        let mut elm = h0[i].clone();
                        elm.sub(&h1[i]);
                        elm
                    })
                    .collect()
            );
        }
        let mut hashes: Vec<Vec<u8>> = vec![];
        let mut hasher = Sha256::new();
        for client in 0..y0_y1.len() {
            for y in y0_y1[client].iter() {
                hasher.update(y.value().to_string());
            }
            hashes.push(hasher.finalize_reset().to_vec());
        }
        println!("session {:?}: histogram_compute_hashes: {:?}", client_idx, start.elapsed().as_secs_f64());

        if plasma::consts::BATCH {
            let mut batched_hash = vec![0u8; 32];
            for hash in hashes {
                batched_hash = xor_vec(&batched_hash, &hash);
            }
            vec![batched_hash]
        } else {
            hashes
        }
    }

    async fn add_leaves_between_clients(self, 
        _: context::Context, req: HistogramAddLeavesBetweenClientsRequest
    ) -> Vec<collect::Result<FieldElm>> {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        let res = coll.add_leaves_between_clients(&req.verified);
        println!("session {:?}: add_leaves_between_clients: {:?}", client_idx, start.elapsed().as_secs_f64());
        res 
    }

}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let (cfg, sid, _) = config::get_args("Server", true, false);
    let server_addr = match sid {
        0 => cfg.server_0,
        1 => cfg.server_1,
        2 => cfg.server_2,
        _ => panic!("Oh no!"),
    };

    let seeds = vec![
        prg::PrgSeed { key: [1u8; 16] }, 
        prg::PrgSeed { key: [2u8; 16] },
        prg::PrgSeed { key: [3u8; 16] }
    ];

    let coll_0 = collect::KeyCollection::new(&seeds[0], cfg.data_bytes * 8);
    let coll_1 = collect::KeyCollection::new(&seeds[1], cfg.data_bytes * 8);
    let coll_2 = collect::KeyCollection::new(&seeds[2], cfg.data_bytes * 8);
    let arc_0 = Arc::new(Mutex::new(coll_0));
    let arc_1 = Arc::new(Mutex::new(coll_1));
    let arc_2 = Arc::new(Mutex::new(coll_2));

    println!("Server {} running at {:?}", sid, server_addr);
    // Listen on any IP
    let listener = tcp::listen(&server_addr, Json::default).await?;
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        // Limit channels to 1 per IP.
        .map(|channel| {
            let local_0 = CollectorServer {
                seed: seeds[0].clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc_0.clone(),
            };
            let local_1 = CollectorServer {
                seed: seeds[1].clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc_1.clone(),
            };
            let local_2 = CollectorServer {
                seed: seeds[2].clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc_2.clone(),
            };
            let server = BatchCollectorServer {
                cs: vec![local_0, local_1, local_2],
            };

            channel.execute(server.serve())
        })
        // Max 10 channels.
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;
        
    Ok(())
}
