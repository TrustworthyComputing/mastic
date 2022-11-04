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
        assert!(client_idx == 0 || client_idx == 1);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        *coll = collect::KeyCollection::new(&self.cs[client_idx].seed, self.cs[client_idx].data_len * 8);

        "Done".to_string()
    }

    async fn add_keys(self,
         _: context::Context, req: HistogramAddKeysRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx == 0 || client_idx == 1);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        for k in req.keys {
            coll.add_key(k);
        }
        println!("Number of keys: {:?}", coll.keys.len());

        "".to_string()
    }

    async fn tree_init(self,
        _: context::Context, req: HistogramTreeInitRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx == 0 || client_idx == 1);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.tree_init();
        "Done".to_string()
    }

    async fn histogram_tree_crawl(self, 
        _: context::Context, req: HistogramTreeCrawlRequest
    ) -> String {
        let client_idx = req.client_idx as usize;
        assert!(client_idx == 0 || client_idx == 1);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.histogram_tree_crawl();
        "Done".to_string()
    }

    async fn histogram_tree_crawl_last(self, 
        _: context::Context, req: HistogramTreeCrawlLastRequest
    ) -> (Vec<Vec<u8>>, Vec<FieldElm>) {
        let client_idx = req.client_idx as usize;
        assert!(client_idx == 0 || client_idx == 1);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.histogram_tree_crawl_last()
    }

    async fn histogram_add_leaves_between_clients(self, 
        _: context::Context, req: HistogramAddLeavesBetweenClientsRequest
    ) -> Vec<collect::Result<FieldElm>> {
        let client_idx = req.client_idx as usize;
        assert!(client_idx == 0 || client_idx == 1);
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

    let seed = prg::PrgSeed { key: [1u8; 16] };

    let coll = collect::KeyCollection::new(&seed, cfg.data_len * 8);
    let coll2 = collect::KeyCollection::new(&seed, cfg.data_len * 8);
    let arc = Arc::new(Mutex::new(coll));
    let arc2 = Arc::new(Mutex::new(coll2));

    println!("Server {} running at {:?}", sid, server_addr);
    // Listen on any IP
    let listener = tcp::listen(&server_addr, Json::default).await?;
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        // Limit channels to 1 per IP.
        .map(|channel| {
            let local = CollectorServer {
                seed: seed.clone(),
                data_len: cfg.data_len * 8,
                arc: arc.clone(),
            };
            let local2 = CollectorServer {
                seed: seed.clone(),
                data_len: cfg.data_len * 8,
                arc: arc2.clone(),
            };
            let server = BatchCollectorServer {
                cs: vec![local.clone(), local2],
            };

            channel.execute(server.serve())
        })
        // Max 10 channels.
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;
        
    Ok(())
}
