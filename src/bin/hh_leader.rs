use plasma::{
    collect,
    config,
    dpf,
    FieldElm,
    fastfield,
    hh_rpc::{
        HHAddKeysRequest,
        HHResetRequest, 
        HHTreeInitRequest,
        HHTreeCrawlRequest, 
        HHTreeCrawlLastRequest, 
        HHTreePruneRequest, 
        HHComputeHashesRequest,
        HHAddLeavesBetweenClientsRequest,
    },
    HHCollectorClient,
};

use futures::future::join_all;
// use futures::try_join;
use itertools::Itertools;
use num_traits::cast::ToPrimitive;
use rand::{Rng, distributions::Alphanumeric,};
use rayon::prelude::*;
use std::{io, time::{Duration, SystemTime, Instant},};
use tarpc::{client, context, tokio_serde::formats::Bincode, serde_transport::tcp,};

type Key = dpf::DPFKey<fastfield::FE,FieldElm>;
type Client = HHCollectorClient;

fn long_context() -> context::Context {
    let mut ctx = context::current();

    // Increase timeout to one hour
    ctx.deadline = SystemTime::now() + Duration::from_secs(1000000);
    ctx
}

fn sample_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric) as char)
        .take(len / 8)
        .collect()
}

// fn sample_location() -> (f64, f64) {
//     let mut rng = rand::thread_rng();
//     (rng.gen_range(-180.0..180.0) as f64, rng.gen_range(-90.0..90.0) as f64)
// }

fn generate_keys(cfg: &config::Config) -> Vec<(Vec<Key>, Vec<Key>)> {
    let ((keys20, keys02), ((keys01, keys10), (keys12, keys21))): 
        ((Vec<Key>, Vec<Key>), ((Vec<Key>, Vec<Key>), (Vec<Key>, Vec<Key>))) = 
    rayon::iter::repeat(0)
    .take(cfg.unique_buckets)
    .enumerate()
    .map(|(_i, _)| {
        let data_string = sample_string(cfg.data_bytes * 8);
        // let bit_str = plasma::bits_to_bitstring(
        //     plasma::string_to_bits(&data_string).as_slice()
        // );
        // println!("Client({}) \t input \"{}\" ({})", _i, data_string, bit_str);
        // let loc = sample_location();
        // let data_string = encode(Point::new(loc.0, loc.1), cfg.data_bytes * 8);
        (
            dpf::DPFKey::gen_from_str(&data_string),
            (dpf::DPFKey::gen_from_str(&data_string), 
            dpf::DPFKey::gen_from_str(&data_string))
        )
    })
    .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys01[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    vec![(keys01, keys10), (keys12, keys21), (keys20, keys02)]
}

async fn reset_servers(
    clients: &Vec<&Client>,
) -> io::Result<()> {
    let mut responses = vec![];

    responses.push(clients[0].reset(
        long_context(), HHResetRequest { client_idx: 0 }
    ));
    responses.push(clients[1].reset(
        long_context(), HHResetRequest { client_idx: 1 }
    ));

    responses.push(clients[1].reset(
        long_context(), HHResetRequest { client_idx: 0 }
    ));
    responses.push(clients[2].reset(
        long_context(), HHResetRequest { client_idx: 1 }
    ));

    responses.push(clients[2].reset(
        long_context(), HHResetRequest { client_idx: 0 }
    ));
    responses.push(clients[0].reset(
        long_context(), HHResetRequest { client_idx: 1 }
    ));

    responses.push(clients[0].reset(
        long_context(), HHResetRequest { client_idx: 2 }
    ));
    responses.push(clients[1].reset(
        long_context(), HHResetRequest { client_idx: 2 }
    ));

    join_all(responses).await;

    Ok(())
}

async fn tree_init(
    clients: &Vec<&Client>,
) -> io::Result<()> {
    let mut responses = vec![];

    // Session 0
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 0
        }).await
    }));
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 1
        }).await
    }));

    // Session 1
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 0
        }).await
    }));
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 1
        }).await
    }));
    
    // Session 2
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 0
        }).await
    }));
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 1
        }).await
    }));

    // extra
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 2
        }).await
    }));
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_init(long_context(), HHTreeInitRequest { 
            client_idx: 2
        }).await
    }));

    join_all(responses).await;

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    clients: &Vec<&Client>,
    keys: &Vec<(Vec<dpf::DPFKey<fastfield::FE,FieldElm>>, Vec<dpf::DPFKey<fastfield::FE,FieldElm>>)>,
    nreqs: usize,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkeys_0 = vec![Vec::with_capacity(nreqs); 3];
    let mut addkeys_1 = vec![Vec::with_capacity(nreqs); 3];
    for _ in 0..nreqs {
        let idx = zipf.sample(&mut rng) - 1;
        for i in 0..3 {
            addkeys_0[i].push(keys[i].0[idx].clone());
            addkeys_1[i].push(keys[i].1[idx].clone());
        }
    }

    let mut responses = vec![];
    // Session 0
    let keys = addkeys_0[0].clone();
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 0, keys: keys
        }).await
    }));
    let keys = addkeys_1[0].clone();
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 1, keys: keys
        }).await
    }));

    // Session 1
    let keys = addkeys_0[1].clone();
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 0, keys: keys
        }).await
    }));
    let cl = clients[2].clone();
    let keys = addkeys_1[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 1, keys: keys
        }).await
    }));

    // Session 2
    let cl = clients[2].clone();
    let keys = addkeys_0[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 0, keys: keys
        }).await
    }));
    let cl = clients[0].clone();
    let keys = addkeys_1[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 1, keys: keys
        }).await
    }));
    
    // extra
    let cl = clients[0].clone();
    let keys = addkeys_0[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 2, keys: keys
        }).await
    }));
    let cl = clients[1].clone();
    let keys = addkeys_1[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.add_keys(long_context(), HHAddKeysRequest { 
            client_idx: 2, keys: keys
        }).await
    }));

    join_all(responses).await;

    Ok(())
}

async fn run_level(
    cfg: &config::Config,
    clients: &Vec<&Client>,
    nreqs: usize,
) -> io::Result<()> {
    let threshold64 = core::cmp::max(1, (cfg.threshold * (nreqs as f64)) as u64);
    let threshold = fastfield::FE::new(threshold64 as u64);

    let mut responses = vec![];

    // Session 0
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 0,
        }).await
    }));
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 1,
        }).await
    }));

    // Session 1
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 0,
        }).await
    }));
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 1,
        }).await
    }));

    // Session 2
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 0,
        }).await
    }));
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 1,
        }).await
    }));

    // extra
    let cl = clients[0].clone();
    let response_00 = tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 2,
        }).await
    });
    let cl = clients[1].clone();
    let response_01 = tokio::spawn(async move { 
        cl.tree_crawl(long_context(), HHTreeCrawlRequest { 
            client_idx: 2,
        }).await
    });

    join_all(responses).await;

    let (vals0, vals1) = (response_00.await?.unwrap(), response_01.await?.unwrap());

    debug_assert_eq!(vals0.len(), vals1.len());
    let mut responses = vec![];
    let keep = collect::KeyCollection::<fastfield::FE,FieldElm>::keep_values_cmp(&threshold, &vals0, &vals1);

    // Tree prune
    // Session 0
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 0, keep: k,
        }).await
    }));
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 1, keep: k,
        }).await
    }));

    // Session 1
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 0, keep: k,
        }).await
    }));
    let cl = clients[2].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 1, keep: k,
        }).await
    }));

    // Session 2
    let cl = clients[2].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 0, keep: k,
        }).await
    }));
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 1, keep: k,
        }).await
    }));
    
    // Extra
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 2, keep: k,
        }).await
    }));
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move { 
        cl.tree_prune(long_context(), HHTreePruneRequest { 
            client_idx: 2, keep: k,
        }).await
    }));

    join_all(responses).await;

    Ok(())
}

async fn run_level_last(
    clients: &Vec<&Client>,
    num_clients: usize,
) -> io::Result<()> {
    // let threshold64 = core::cmp::max(1, (cfg.threshold * (num_clients as f64)) as u32);
    // let threshold = FieldElm::from(threshold64 as u32);
    // Session 0
    let cl = clients[0].clone();
    let response_00 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 0,
        }).await
    });
    let cl = clients[1].clone();
    let response_01 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 1,
        }).await
    });
    
    // Session 1
    let cl = clients[1].clone();
    let response_11 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 0,
        }).await
    });
    let cl = clients[2].clone();
    let response_12 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 1,
        }).await
    });
        
    // Session 2
    let cl = clients[2].clone();
    let response_22 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 0,
        }).await
    });
    let cl = clients[0].clone();
    let response_20 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 1,
        }).await
    });

    // extra
    let cl = clients[0].clone();
    let response_020 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 2,
        }).await
    });
    let cl = clients[1].clone();
    let response_021 = tokio::spawn(async move { 
        cl.tree_crawl_last(long_context(), HHTreeCrawlLastRequest { 
            client_idx: 2,
        }).await
    });

    let ((hashes_00, tau_vals_00), (hashes_01, tau_vals_01)) =
        (response_00.await?.unwrap(), response_01.await?.unwrap());
    let ((hashes_11, tau_vals_11), (hashes_12, tau_vals_12)) =
        (response_11.await?.unwrap(), response_12.await?.unwrap());
    let ((hashes_22, tau_vals_22), (hashes_20, tau_vals_20))= 
        (response_22.await?.unwrap(), response_20.await?.unwrap());
    let ((hashes_020, tau_vals_020), (hashes_021, tau_vals_021)) =
        (response_020.await?.unwrap(), response_021.await?.unwrap());

    debug_assert_eq!(hashes_00.len(), hashes_01.len());
    debug_assert_eq!(hashes_11.len(), hashes_12.len());
    debug_assert_eq!(hashes_11.len(), hashes_12.len());
    let mut ver_0 = vec![true; num_clients];
    let mut ver_1 = vec![true; num_clients];
    let mut ver_2 = vec![true; num_clients];

    // Check that \tau_2,0 and \pi_2,0 from S0 and S2 are the same
    plasma::check_hashes(&mut ver_0, &hashes_020, &hashes_22);
    plasma::check_taus(&mut ver_0, &tau_vals_020, &tau_vals_22);
    // Check that \tau_2,1 and \pi_2,1 from S0 and S2 are the same
    plasma::check_hashes(&mut ver_1, &hashes_021, &hashes_20);
    plasma::check_taus(&mut ver_1, &tau_vals_021, &tau_vals_20);

    let tau_vals_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_00, &tau_vals_01
    );
    let tau_vals_1 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_11, &tau_vals_12
    );
    let tau_vals_2 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_22, &tau_vals_20
    );

    // Check s0, s1 hashes and taus
    plasma::check_hashes_and_taus(&mut ver_0, &hashes_00, &hashes_01, &tau_vals_0, num_clients);
    // Check s1, s2 hashes and taus
    plasma::check_hashes_and_taus(&mut ver_1, &hashes_11, &hashes_12, &tau_vals_1, num_clients);
    // Check s2, s0 hashes and taus
    plasma::check_hashes_and_taus(&mut ver_2, &hashes_22, &hashes_20, &tau_vals_2, num_clients);
    debug_assert_eq!(
        ver_0.par_iter().zip_eq(&ver_1).zip_eq(&ver_2)
            .filter(|&((&v0, &v1), &v2)| v0 == true && v0 == v1 && v1 == v2).count(),
        ver_0.len()
    );

    let cl = clients[0].clone();
    let response_0 = tokio::spawn(async move { 
        cl.compute_hashes(
            long_context(), HHComputeHashesRequest { client_idx: 0, }
        ).await
    });
    let cl = clients[1].clone();
    let response_1 = tokio::spawn(async move { 
        cl.compute_hashes(
            long_context(), HHComputeHashesRequest { client_idx: 1, }
        ).await
    });

    let (hashes_0, hashes_1) =
        (response_0.await?.unwrap(), response_1.await?.unwrap());
    plasma::check_hashes(&mut ver_0, &hashes_0, &hashes_1);

    // Session 0
    let cl = clients[0].clone();
    let v0 = ver_0.clone();
    let response_00 = tokio::spawn(async move { 
        cl.add_leaves_between_clients(long_context(), 
            HHAddLeavesBetweenClientsRequest { 
                client_idx: 0, verified: v0,
        }).await
    });
    let cl = clients[1].clone();
    let v0 = ver_0.clone();
    let response_01 = tokio::spawn(async move { 
        cl.add_leaves_between_clients(long_context(), 
            HHAddLeavesBetweenClientsRequest { 
                client_idx: 1, verified: v0,
        }).await
    });

    // Session 1
    let cl = clients[1].clone();
    let v1 = ver_1.clone();
    let response_11 = tokio::spawn(async move { 
        cl.add_leaves_between_clients(long_context(), 
            HHAddLeavesBetweenClientsRequest { 
                client_idx: 0, verified: v1,
        }).await
    });
    let cl = clients[2].clone();
    let v1 = ver_1.clone();
    let response_12 = tokio::spawn(async move { 
        cl.add_leaves_between_clients(long_context(), 
            HHAddLeavesBetweenClientsRequest { 
                client_idx: 1, verified: v1,
        }).await
    });
    
    // Session 2
    let cl = clients[2].clone();
    let v2 = ver_2.clone();
    let response_22 = tokio::spawn(async move { 
        cl.add_leaves_between_clients(long_context(), 
            HHAddLeavesBetweenClientsRequest { 
                client_idx: 0, verified: v2,
        }).await
    });
    let cl = clients[0].clone();
    let v2 = ver_2.clone();
    let response_20 = tokio::spawn(async move { 
        cl.add_leaves_between_clients(long_context(), 
            HHAddLeavesBetweenClientsRequest { 
                client_idx: 1, verified: v2,
        }).await
    });

    let (shares_00, shares_01) =
        (response_00.await?.unwrap(), response_01.await?.unwrap());
    let (shares_11, shares_12) =
        (response_11.await?.unwrap(), response_12.await?.unwrap());
    let (shares_22, shares_20) = 
        (response_22.await?.unwrap(), response_20.await?.unwrap());

    // let keep = collect::KeyCollection::<fastfield::FE,FieldElm>::keep_values_last(num_clients, &threshold, &shares_00, &shares_01);
    // println!("KeepLast : {:?}", keep);
    // println!("KeepLen Last: {:?}", keep.len());

    let hist_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_00, &shares_01
    );
    let hist_1 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_11, &shares_12
    );
    let hist_2 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_22, &shares_20
    );

    // // Tree prune last
    // let mut responses = vec![];
    // // Session 0
    // let cl = clients[0].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 0, keep: k,
    //     }).await
    // }));
    // let cl = clients[1].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 1, keep: k,
    //     }).await
    // }));

    // // Session 1
    // let cl = clients[1].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 0, keep: k,
    //     }).await
    // }));
    // let cl = clients[2].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 1, keep: k,
    //     }).await
    // }));

    // // Session 2
    // let cl = clients[2].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 0, keep: k,
    //     }).await
    // }));
    // let cl = clients[0].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 1, keep: k,
    //     }).await
    // }));
    
    // // Session 2
    // let cl = clients[0].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 2, keep: k,
    //     }).await
    // }));
    // let cl = clients[1].clone();
    // let k = keep.clone();
    // responses.push(tokio::spawn(async move { 
    //     cl.tree_prune_last(long_context(), HHTreePruneLastRequest { 
    //         client_idx: 2, keep: k,
    //     }).await
    // }));
    // join_all(responses).await;

    for ((res_0, res_1), res_2) in hist_0.iter().zip_eq(hist_1).zip_eq(hist_2) {
        debug_assert_eq!(res_0.value.value(), res_1.value.value());
        debug_assert_eq!(res_0.value.value(), res_2.value.value());
        let bits = plasma::bits_to_bitstring(&res_0.path);
        if res_0.value.value().to_u32().unwrap() > 0 {
            println!("Value ({}) \t Count: {:?}", bits, res_0.value.value());
        }
    }

    Ok(())
}


#[tokio::main]
async fn main() -> io::Result<()> {
    //println!("Using only one thread!");
    //rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    env_logger::init();
    let (cfg, _, nreqs) = config::get_args("Leader", false, true);
    debug_assert_eq!(cfg.data_bytes % 8, 0);

    let client_0 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_0, Bincode::default).await?
    ).spawn();
    let client_1 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_1, Bincode::default).await?
    ).spawn();
    let client_2 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_2, Bincode::default).await?
    ).spawn();

    let start = Instant::now();
    let keys = generate_keys(&cfg);
    
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys[0].0.len(), delta, delta / (keys[0].0.len() as f64)
    );

    let clients = vec![&client_0, &client_1, &client_2];

    reset_servers(&clients).await?;

    let mut left_to_go = nreqs;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut resps = vec![];

        for _j in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.addkey_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                resps.push(add_keys(
                    &cfg,
                    &clients,
                    &keys,
                    this_batch,
                ));
            }
        }

        for r in resps {
            r.await?;
        }
    }

    tree_init(&clients).await?;

    let start = Instant::now();
    let bitlen = cfg.data_bytes * 8; // bits
    for _level in 0..bitlen-1 {
        let start_level = Instant::now();
        run_level(&cfg, &clients, nreqs).await?;
        println!("Time for level {} :{:?}", _level, start_level.elapsed().as_secs_f64());
    }
    println!("Time for {} levels: {:?}", bitlen, start.elapsed().as_secs_f64());

    let start_last = Instant::now();
    run_level_last(&clients, nreqs).await?;
    println!("Time for last level: {:?}", start_last.elapsed().as_secs_f64());
    println!("Total time {:?}", start.elapsed().as_secs_f64());

    Ok(())
}
