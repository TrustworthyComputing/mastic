use dpf_codes::{
    collect,
    config,
    FieldElm,
    fastfield::FE,
    histogram_rpc::{
        Collector,
        HistogramAddKeysRequest,
        HistogramTreeInitRequest,
        HistogramResetRequest,
        HistogramTreeCrawlRequest, 
        HistogramTreeCrawlLastRequest,
        HistogramAddLeavesBetweenClientsRequest,
    },
    prg,
};

use futures::{future, prelude::*,};
use std::{io, sync::{Arc, Mutex},};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Json,
    serde_transport::tcp,
};

#[derive(Clone)]
struct CollectorServer {
    seed: prg::PrgSeed,
    data_len: usize,
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
            &self.cs[client_idx].seed, self.cs[client_idx].data_len * 8
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
        println!("SID {}) Number of keys: {:?}", client_idx, coll.keys.len());
        "Done".to_string()
    }

    async fn tree_init(self,
        _: context::Context, req: HistogramTreeInitRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.tree_init();
        "Done".to_string()
    }

    async fn histogram_tree_crawl(self, 
        _: context::Context, req: HistogramTreeCrawlRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.histogram_tree_crawl();
        "Done".to_string()
    }

    async fn histogram_tree_crawl_last(self, 
        _: context::Context, req: HistogramTreeCrawlLastRequest
    ) -> (Vec<Vec<u8>>, Vec<FieldElm>) {
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.histogram_tree_crawl_last()
    }

    async fn histogram_add_leaves_between_clients(self, 
        _: context::Context, req: HistogramAddLeavesBetweenClientsRequest
    ) -> Vec<collect::Result<FieldElm>> {
        let client_idx = req.client_idx as usize;
        assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.histogram_add_leaves_between_clients(&req.verified)
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

    let coll_0 = collect::KeyCollection::new(&seeds[0], cfg.data_len * 8);
    let coll_1 = collect::KeyCollection::new(&seeds[1], cfg.data_len * 8);
    let coll_2 = collect::KeyCollection::new(&seeds[2], cfg.data_len * 8);
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
                data_len: cfg.data_len * 8,
                arc: arc_0.clone(),
            };
            let local_1 = CollectorServer {
                seed: seeds[1].clone(),
                data_len: cfg.data_len * 8,
                arc: arc_1.clone(),
            };
            let local_2 = CollectorServer {
                seed: seeds[2].clone(),
                data_len: cfg.data_len * 8,
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
