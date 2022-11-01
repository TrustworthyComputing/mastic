use dpf_codes::{
    collect,
    config,
    FieldElm,
    fastfield::FE,
    idpf_rpc::{
        Collector,
        IdpfAddKeysRequest,
        IdpfFinalSharesRequest,
        IdpfResetRequest,
        IdpfTreeCrawlRequest, 
        IdpfTreeCrawlLastRequest,
        IdpfTreeInitRequest,
        IdpfTreePruneRequest, 
        IdpfTreePruneLastRequest, 
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
    type TreeCrawlFut = Ready<Vec<FE>>;
    type TreeCrawlLastFut = Ready<Vec<FieldElm>>;
    type TreePruneFut = Ready<String>;
    type TreePruneLastFut = Ready<String>;
    type FinalSharesFut = Ready<Vec<collect::Result<FieldElm>>>;
    type ResetFut = Ready<String>;

    fn reset(self, _: context::Context, _rst: IdpfResetRequest) -> Self::ResetFut {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(&self.seed, self.data_len);

        future::ready("Done".to_string())
    }

    fn add_keys(self, _: context::Context, add: IdpfAddKeysRequest) -> Self::AddKeysFut {
        let mut coll = self.arc.lock().unwrap();
        for k in add.keys {
            coll.add_key(k);
        }
        println!("Number of keys: {:?}", coll.keys.len());

        future::ready("".to_string())
    }

    fn tree_init(self, _: context::Context, _req: IdpfTreeInitRequest) -> Self::TreeInitFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_init();
        future::ready("Done".to_string())
    }

    fn tree_crawl(self, _: context::Context, _req: IdpfTreeCrawlRequest) -> Self::TreeCrawlFut {
        let mut coll = self.arc.lock().unwrap();
        future::ready(coll.tree_crawl())
    }

    fn tree_crawl_last(self, _: context::Context, _req: IdpfTreeCrawlLastRequest) -> Self::TreeCrawlLastFut {
        let mut coll = self.arc.lock().unwrap();
        future::ready(coll.tree_crawl_last())
    }

    fn tree_prune(self, _: context::Context, req: IdpfTreePruneRequest) -> Self::TreePruneFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune(&req.keep);
        future::ready("Done".to_string())
    }

    fn tree_prune_last(self, _: context::Context, req: IdpfTreePruneLastRequest) -> Self::TreePruneLastFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune_last(&req.keep);
        future::ready("Done".to_string())
    }

    fn final_shares(self, _: context::Context, _req: IdpfFinalSharesRequest) -> Self::FinalSharesFut {
        let coll = self.arc.lock().unwrap();
        let out = coll.final_shares();
        future::ready(out)
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

    let _server_idx = match sid {
        0 => 0,
        1 => 1,
        _ => panic!("Oh no!"),
    };

    let seed = prg::PrgSeed { key: [1u8; 16] };

    let bitlen = cfg.data_len * 8;
    let coll = collect::KeyCollection::new(&seed, bitlen);
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
                data_len: bitlen,
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
