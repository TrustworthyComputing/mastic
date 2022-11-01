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

use futures::{future::{self, Ready}, prelude::*,};
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

impl Collector for CollectorServer {
    type AddKeysFut = Ready<String>;
    type TreeInitFut = Ready<String>;
    type HistogramTreeCrawlFut = Ready<String>;
    type HistogramTreeCrawlLastFut = Ready<(Vec<Vec<u8>>, Vec<FieldElm>)>;
    type HistogramAddLeavesBetweenClientsFut = Ready<Vec<collect::Result<FieldElm>>>;
    type ResetFut = Ready<String>;

    fn reset(self,
         _: context::Context, _rst: HistogramResetRequest
    ) -> Self::ResetFut {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(&self.seed, self.data_len * 8);

        future::ready("Done".to_string())
    }

    fn add_keys(self,
         _: context::Context, add: HistogramAddKeysRequest
    ) -> Self::AddKeysFut {
        let mut coll = self.arc.lock().unwrap();
        for k in add.keys {
            coll.add_key(k);
        }
        println!("Number of keys: {:?}", coll.keys.len());

        future::ready("".to_string())
    }

    fn tree_init(self,
        _: context::Context, _req: HistogramTreeInitRequest
    ) -> Self::TreeInitFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_init();
        future::ready("Done".to_string())
    }

    fn histogram_tree_crawl(self, 
        _: context::Context, _req: HistogramTreeCrawlRequest
    ) -> Self::HistogramTreeCrawlFut {
        let mut coll = self.arc.lock().unwrap();
        coll.histogram_tree_crawl();
        future::ready("Done".to_string())
    }

    fn histogram_tree_crawl_last(self, 
        _: context::Context, _req: HistogramTreeCrawlLastRequest
    ) -> Self::HistogramTreeCrawlLastFut {
        let mut coll = self.arc.lock().unwrap();
        future::ready(coll.histogram_tree_crawl_last())
    }

    fn histogram_add_leaves_between_clients(self, 
        _: context::Context, req: HistogramAddLeavesBetweenClientsRequest
    ) -> Self::HistogramAddLeavesBetweenClientsFut {
        let mut coll = self.arc.lock().unwrap();
        future::ready(coll.histogram_add_leaves_between_clients(&req.verified))
    }

}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let (cfg, sid, _) = config::get_args("Server", true, false);
    let mut server_addr = match sid {
        0 => cfg.server0,
        1 => cfg.server1,
        _ => panic!("Oh no!"),
    };

    _ = match sid {
        0 => 0,
        1 => 1,
        _ => panic!("Oh no!"),
    };

    let seed = prg::PrgSeed { key: [1u8; 16] };

    let coll = collect::KeyCollection::new(&seed, cfg.data_len * 8);
    let arc = Arc::new(Mutex::new(coll));

    // Listen on any IP
    server_addr.set_ip("0.0.0.0".parse().expect("Could not parse"));
    let listener = tcp::listen(&server_addr, Json::default).await?;
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        // Limit channels to 1 per IP.
        // .max_channels_per_key(1, |t| t.transport().peer_addr().unwrap().ip())
        .map(|channel| {
            let server = CollectorServer {
                seed: seed.clone(),
                data_len: cfg.data_len * 8,
                arc: arc.clone(),
            };

            channel.execute(server.serve())
        })
        // Max 10 channels.
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;
        
    Ok(())
}
