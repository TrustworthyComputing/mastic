// Starter code from:
//   https://github.com/google/tarpc/blob/master/example-service/src/server.rs

use dpf_codes::{
    collect, config,
    FieldElm,
    fastfield::FE,
    prg,
    rpc::Collector,
    rpc::{
        AddKeysRequest, FinalSharesRequest, ResetRequest, TreeCrawlRequest, 
        TreeCrawlLastRequest, TreeInitRequest,
        TreePruneRequest, 
        TreePruneLastRequest, 
    },
};

use futures::{
    future::{self, Ready},
    prelude::*,
};
use std::{
    io,
    sync::{Arc, Mutex},
};
use tarpc::{
    context,
    server::{self, Channel},
};

use tokio::net::TcpListener;
use tokio_serde::formats::Bincode;

#[derive(Clone)]
struct CollectorServer {
    seed: prg::PrgSeed,
    data_len: usize,
    server_idx: u16,
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

    fn reset(self, _: context::Context, _rst: ResetRequest) -> Self::ResetFut {
        let mut coll = self.arc.lock().unwrap();
        *coll = collect::KeyCollection::new(&self.seed, self.data_len);

        future::ready("Done".to_string())
    }

    fn add_keys(self, _: context::Context, add: AddKeysRequest) -> Self::AddKeysFut {
        let mut coll = self.arc.lock().unwrap();
        for k in add.keys {
            coll.add_key(k);
        }
        println!("Number of keys: {:?}", coll.keys.len());

        future::ready("".to_string())
    }

    fn tree_init(self, _: context::Context, _req: TreeInitRequest) -> Self::TreeInitFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_init();
        future::ready("Done".to_string())
    }

    fn tree_crawl(self, _: context::Context, _req: TreeCrawlRequest) -> Self::TreeCrawlFut {
        let mut coll = self.arc.lock().unwrap();
        future::ready(coll.tree_crawl())
    }

    fn tree_crawl_last(self, _: context::Context, _req: TreeCrawlLastRequest) -> Self::TreeCrawlLastFut {
        let mut coll = self.arc.lock().unwrap();
        future::ready(coll.tree_crawl_last())
    }

    fn tree_prune(self, _: context::Context, req: TreePruneRequest) -> Self::TreePruneFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune(&req.keep);
        future::ready("Done".to_string())
    }

    fn tree_prune_last(self, _: context::Context, req: TreePruneLastRequest) -> Self::TreePruneLastFut {
        let mut coll = self.arc.lock().unwrap();
        coll.tree_prune_last(&req.keep);
        future::ready("Done".to_string())
    }

    fn final_shares(self, _: context::Context, _req: FinalSharesRequest) -> Self::FinalSharesFut {
        let coll = self.arc.lock().unwrap();
        let out = coll.final_shares();
        future::ready(out)
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let (cfg, sid, _) = config::get_args("Server", true, false);
    let server_addr = match sid {
        0 => cfg.server0,
        1 => cfg.server1,
        _ => panic!("Oh no!"),
    };

    let server_idx = match sid {
        0 => 0,
        1 => 1,
        _ => panic!("Oh no!"),
    };

    // XXX This is bogus
    let seed = prg::PrgSeed { key: [1u8; 16] };

    let der = include_bytes!("identity.p12");
    // XXX This password is also bogus.
    let cert = native_tls::Identity::from_pkcs12(der, "mypass").unwrap();

    let acc = native_tls::TlsAcceptor::builder(cert).build().unwrap();
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(acc);

    let coll = collect::KeyCollection::new(&seed, cfg.data_len);
    let arc = Arc::new(Mutex::new(coll));

    let mut server_addr = server_addr;
    // Listen on any IP
    server_addr.set_ip("0.0.0.0".parse().expect("Could not parse"));
    TcpListener::bind(&server_addr)
        .await?
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(|channel| async {
            let tls_acceptor = tls_acceptor.clone();
            let socket = tls_acceptor.accept(channel).await.unwrap();
            let coll_server = CollectorServer {
                server_idx,
                seed: seed.clone(),
                data_len: cfg.data_len,
                arc: arc.clone(),
            };

            let socket = tarpc::serde_transport::Transport::from((socket, Bincode::default()));
            let server = server::BaseChannel::with_defaults(socket);
            let (tx, rx) = futures::channel::oneshot::channel();
            tokio::spawn(async move {
                server.respond_with(coll_server.serve()).execute().await;
                //assert!(tx.send(()).is_ok());
                print!("Sending");
                tx.send(()).unwrap();
            });
            let a = rx.await;
            print!("Received");
            a
        })
        .buffer_unordered(100)
        .for_each(|_| async {})
        .await;

    Ok(())
}
