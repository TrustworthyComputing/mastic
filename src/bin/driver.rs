use std::{
    collections::HashSet,
    io::{self, Error},
    time::{Duration, Instant, SystemTime},
};

use futures::try_join;
use mastic::{
    collect,
    config::{self, Mode},
    rpc::{
        AddFLPsRequest, AddKeysRequest, AggregateByAttributesResultRequest,
        AggregateByAttributesValidateRequest, ApplyFLPResultsRequest, FinalSharesRequest,
        GetProofsRequest, ResetRequest, RunFlpQueriesRequest, TreeCrawlLastRequest,
        TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    vec_add,
    vidpf::VidpfKey,
    CollectorClient, Mastic, MasticHistogram,
};
use prio::{
    field::{random_vector, Field128},
    vdaf::xof::{IntoFieldVec, Xof, XofShake128},
};
use rand::{
    distributions::{Alphanumeric, Distribution},
    thread_rng, Rng,
};
use rand_core::RngCore;
use rayon::prelude::*;
use tarpc::{client, context, serde_transport::tcp, tokio_serde::formats::Bincode};

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

fn generate_keys(
    cfg: &config::Config,
    mastic: &MasticHistogram,
) -> Vec<(VidpfKey, VidpfKey, String, Vec<Field128>)> {
    let keys = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .map(|_| {
            // Generate a random number in the specified range
            let alpha = sample_string(cfg.data_bytes * 8);
            let beta = rand::thread_rng().gen_range(0..cfg.hist_buckets);
            let input_beta = mastic.encode_measurement(&beta).unwrap();
            let (key_0, key_1) = VidpfKey::gen_from_str(&alpha, &input_beta);
            (key_0, key_1, alpha, input_beta)
        })
        .collect::<Vec<_>>();

    let encoded: Vec<u8> = bincode::serialize(&keys[0].0).unwrap();
    println!("VIDPFKey size: {:?} bytes", encoded.len());

    keys
}

fn generate_randomness(
    keys: &[(VidpfKey, VidpfKey, String, Vec<Field128>)],
) -> (Vec<[u8; 16]>, Vec<[[u8; 16]; 2]>) {
    let (nonces, jr_parts): (Vec<[u8; 16]>, Vec<[[u8; 16]; 2]>) = keys
        .par_iter()
        .map(|(key_0, key_1, _, _)| {
            let nonce = rand::thread_rng().gen::<u128>().to_le_bytes();
            let vidpf_seeds = (key_0.get_root_seed().key, key_1.get_root_seed().key);

            let mut jr_parts = [[0u8; 16]; 2];
            let mut jr_part_0_xof = XofShake128::init(&vidpf_seeds.0, &[0u8; 16]);
            jr_part_0_xof.update(&[0]); // Aggregator ID
            jr_part_0_xof.update(&nonce);
            jr_part_0_xof
                .into_seed_stream()
                .fill_bytes(&mut jr_parts[0]);

            let mut jr_part_1_xof = XofShake128::init(&vidpf_seeds.1, &[0u8; 16]);
            jr_part_1_xof.update(&[1]); // Aggregator ID
            jr_part_1_xof.update(&nonce);
            jr_part_1_xof
                .into_seed_stream()
                .fill_bytes(&mut jr_parts[1]);

            (nonce, jr_parts)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&nonces[0]).unwrap();
    println!("Nonce size: {:?} bytes", encoded.len());
    let encoded: Vec<u8> = bincode::serialize(&jr_parts[0]).unwrap();
    println!("JR size: {:?} bytes", encoded.len());

    (nonces, jr_parts)
}

fn generate_proofs(
    mastic: &MasticHistogram,
    keys: &[(VidpfKey, VidpfKey, String, Vec<Field128>)],
    all_jr_parts: &Vec<[[u8; 16]; 2]>,
) -> (Vec<Vec<Field128>>, Vec<Vec<Field128>>) {
    let (proofs_0, proofs_1): (Vec<Vec<Field128>>, Vec<Vec<Field128>>) = all_jr_parts
        .par_iter()
        .zip_eq(
            keys.par_iter()
                .map(|(_key_0, _key_1, _alpha, input_beta)| input_beta),
        )
        .map(|(jr_parts, input_beta)| {
            let joint_rand_xof = XofShake128::init(&jr_parts[0], &jr_parts[1]);
            let joint_rand: Vec<Field128> = joint_rand_xof
                .into_seed_stream()
                .into_field_vec(mastic.joint_rand_len());

            let prove_rand = random_vector(mastic.prove_rand_len()).unwrap();
            let proof = mastic.prove(input_beta, &prove_rand, &joint_rand).unwrap();

            let proof_0 = proof
                .iter()
                .map(|_| Field128::from(rand::thread_rng().gen::<u128>()))
                .collect::<Vec<_>>();
            let proof_1 = proof
                .par_iter()
                .zip(proof_0.par_iter())
                .map(|(p_0, p_1)| p_0 - p_1)
                .collect::<Vec<_>>();

            (proof_0, proof_1)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&proofs_0[0]).unwrap();
    println!("FLP proof size: {:?} bytes", encoded.len());

    (proofs_0, proofs_1)
}

async fn reset_servers(
    cfg: &config::Config,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    verify_key: &[u8; 16],
) -> io::Result<()> {
    let req = ResetRequest {
        verify_key: *verify_key,
        hist_buckets: cfg.hist_buckets,
    };
    let resp_0 = client_0.reset(long_context(), req.clone());
    let resp_1 = client_1.reset(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn tree_init(client_0: &CollectorClient, client_1: &CollectorClient) -> io::Result<()> {
    let req = TreeInitRequest {};
    let resp_0 = client_0.tree_init(long_context(), req.clone());
    let resp_1 = client_1.tree_init(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    clients: (&CollectorClient, &CollectorClient),
    all_keys: &[(VidpfKey, VidpfKey, String, Vec<Field128>)],
    all_proofs: (&[Vec<Field128>], &[Vec<Field128>]),
    all_nonces: &[[u8; 16]],
    all_jr_parts: &[[[u8; 16]; 2]],
    num_clients: usize,
    malicious_percentage: f32,
) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut add_keys_0 = Vec::with_capacity(num_clients);
    let mut add_keys_1 = Vec::with_capacity(num_clients);
    let mut flp_proof_shares_0 = Vec::with_capacity(num_clients);
    let mut flp_proof_shares_1 = Vec::with_capacity(num_clients);
    let mut nonces = Vec::with_capacity(num_clients);
    let mut jr_parts = Vec::with_capacity(num_clients);
    for r in 0..num_clients {
        let idx_1 = zipf.sample(&mut rng) - 1;
        let mut idx_2 = idx_1;
        let mut idx_3 = idx_1;
        if rng.gen_range(0.0..1.0) < malicious_percentage {
            if rng.gen() {
                // Malicious key.
                idx_2 += 1;
            } else {
                // Malicious FLP.
                idx_3 += 1;
            }
            println!("Malicious {}", r);
        }
        add_keys_0.push(all_keys[idx_1].0.clone());
        add_keys_1.push(all_keys[idx_2 % cfg.unique_buckets].1.clone());

        flp_proof_shares_0.push(all_proofs.0[idx_1].clone());
        flp_proof_shares_1.push(all_proofs.1[idx_3 % cfg.unique_buckets].clone());

        nonces.push(all_nonces[idx_1]);
        jr_parts.push(all_jr_parts[idx_1]);
    }

    let resp_0 = clients
        .0
        .add_keys(long_context(), AddKeysRequest { keys: add_keys_0 });
    let resp_1 = clients
        .1
        .add_keys(long_context(), AddKeysRequest { keys: add_keys_1 });
    try_join!(resp_0, resp_1).unwrap();

    let resp_0 = clients.0.add_all_flp_proof_shares(
        long_context(),
        AddFLPsRequest {
            flp_proof_shares: flp_proof_shares_0,
            nonces: nonces.clone(),
            jr_parts: jr_parts.clone(),
        },
    );
    let resp_1 = clients.1.add_all_flp_proof_shares(
        long_context(),
        AddFLPsRequest {
            flp_proof_shares: flp_proof_shares_1,
            nonces: nonces.clone(),
            jr_parts: jr_parts.clone(),
        },
    );
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_flp_queries(
    cfg: &config::Config,
    mastic: &MasticHistogram,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    num_clients: usize,
) -> io::Result<()> {
    // Receive FLP query responses in chunks of cfg.flp_batch_size to avoid having huge RPC messages.
    let mut keep = vec![];
    let mut start = 0;
    while start < num_clients {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);

        let req = RunFlpQueriesRequest { start, end };
        let resp_0 = client_0.run_flp_queries(long_context(), req.clone());
        let resp_1 = client_1.run_flp_queries(long_context(), req);
        let (flp_verifier_shares_0, flp_verifier_shares_1) = try_join!(resp_0, resp_1).unwrap();
        debug_assert_eq!(flp_verifier_shares_0.len(), flp_verifier_shares_1.len());

        keep.extend(
            flp_verifier_shares_0
                .par_iter()
                .zip(flp_verifier_shares_1.par_iter())
                .map(|(flp_verifier_share_0, flp_verifier_share_1)| {
                    let flp_verifier = flp_verifier_share_0
                        .par_iter()
                        .zip(flp_verifier_share_1.par_iter())
                        .map(|(&v1, &v2)| v1 + v2)
                        .collect::<Vec<_>>();

                    mastic.decide(&flp_verifier).unwrap()
                })
                .collect::<Vec<_>>(),
        );

        start += cfg.flp_batch_size;
    }

    // Tree prune
    let req = ApplyFLPResultsRequest { keep };
    let resp_0 = client_0.apply_flp_results(long_context(), req.clone());
    let resp_1 = client_1.apply_flp_results(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_level(
    cfg: &config::Config,
    mastic: &MasticHistogram,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    num_clients: usize,
) -> io::Result<()> {
    let threshold = if let Mode::WeightedHeavyHitters { threshold } = cfg.mode {
        core::cmp::max(1, (threshold * (num_clients as f64)) as u64)
    } else {
        return Err(Error::other(
            "invoked server in an unexpected mode of operation",
        ));
    };
    let mut keep;
    let mut split = 1usize;
    let mut malicious = Vec::<usize>::new();
    let mut is_last = false;
    loop {
        let ml = malicious.clone();
        let req = TreeCrawlRequest {
            split_by: split,
            malicious: ml,
            is_last,
        };

        let resp_0 = client_0.tree_crawl(long_context(), req.clone());
        let resp_1 = client_1.tree_crawl(long_context(), req);
        let ((cnt_values_0, mt_root_0, indices_0), (cnt_values_1, mt_root_1, indices_1)) =
            try_join!(resp_0, resp_1).unwrap();

        assert_eq!(cnt_values_0.len(), cnt_values_1.len());
        keep = collect::KeyCollection::keep_values(
            mastic.input_len(),
            threshold,
            &cnt_values_0,
            &cnt_values_1,
        );
        if mt_root_0.is_empty() {
            break;
        }

        malicious = Vec::new();
        for i in 0..mt_root_0.len() {
            if mt_root_0[i] != mt_root_1[i] {
                assert_eq!(indices_0[i], indices_1[i]);
                malicious.push(indices_0[i]);
                // println!("{}) different {} vs {}", i, hl0, hl1);
            }
        }
        if malicious.is_empty() {
            break;
        } else {
            println!(
                "Detected malicious {:?} out of {} clients",
                malicious, num_clients
            );
            if split >= num_clients {
                if is_last {
                    break;
                } else {
                    is_last = true;
                }
            } else {
                split *= 2;
            }
        }
    }

    // Tree prune
    let req = TreePruneRequest { keep };
    let resp_0 = client_0.tree_prune(long_context(), req.clone());
    let resp_1 = client_1.tree_prune(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_level_last(
    cfg: &config::Config,
    mastic: &MasticHistogram,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    num_clients: usize,
) -> io::Result<()> {
    let threshold = if let Mode::WeightedHeavyHitters { threshold } = cfg.mode {
        core::cmp::max(1, (threshold * (num_clients as f64)) as u64)
    } else {
        return Err(Error::other(
            "invoked server in an unexpected mode of operation",
        ));
    };

    let req = TreeCrawlLastRequest {};
    let resp_0 = client_0.tree_crawl_last(long_context(), req.clone());
    let resp_1 = client_1.tree_crawl_last(long_context(), req);
    let (cnt_values_0, cnt_values_1) = try_join!(resp_0, resp_1).unwrap();
    assert_eq!(cnt_values_0.len(), cnt_values_1.len());
    let keep = collect::KeyCollection::keep_values(
        mastic.input_len(),
        threshold,
        &cnt_values_0,
        &cnt_values_1,
    );

    // Receive counters in chunks to avoid having huge RPC messages.
    let mut start = 0;
    while start < num_clients {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);

        let req = GetProofsRequest { start, end };
        let resp_0 = client_0.get_proofs(long_context(), req.clone());
        let resp_1 = client_1.get_proofs(long_context(), req);
        let (hashes_0, hashes_1) = try_join!(resp_0, resp_1).unwrap();

        assert_eq!(hashes_0.len(), hashes_1.len());

        let verified = hashes_0
            .par_iter()
            .zip(hashes_1.par_iter())
            .all(|(&h0, &h1)| h0 == h1);
        assert!(verified);

        start += cfg.flp_batch_size;
    }

    // Tree prune
    let req = TreePruneRequest { keep };
    let resp_0 = client_0.tree_prune(long_context(), req.clone());
    let resp_1 = client_1.tree_prune(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    let req = FinalSharesRequest {};
    let resp_0 = client_0.final_shares(long_context(), req.clone());
    let resp_1 = client_1.final_shares(long_context(), req);
    let (shares_0, shares_1) = try_join!(resp_0, resp_1).unwrap();
    for res in &collect::KeyCollection::final_values(mastic.input_len(), &shares_0, &shares_1) {
        let bits = mastic::bits_to_bitstring(&res.path);
        if res.value[mastic.input_len() - 1] > Field128::from(0) {
            println!("Value ({}) \t Count: {:?}", bits, res.value);
        }
    }

    Ok(())
}

async fn run_aggregate_by_attributes(
    cfg: &config::Config,
    mastic: &MasticHistogram,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    attributes: &[String],
    num_clients: usize,
) -> io::Result<()> {
    for start in (0..num_clients).step_by(cfg.flp_batch_size) {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);
        let req = AggregateByAttributesValidateRequest {
            attributes: attributes.to_vec(),
            start,
            end,
        };

        // For each report, each aggregator evaluates the VIDPF on each of the attributes and returns
        // the VIDPF proof and its FLP verifier share.
        let t = Instant::now();
        let resp_0 = client_0.aggregate_by_attributes_start(long_context(), req.clone());
        let resp_1 = client_1.aggregate_by_attributes_start(long_context(), req.clone());
        let (results_0, results_1) = try_join!(resp_0, resp_1).unwrap();
        assert_eq!(results_0.len(), req.end - req.start);
        assert_eq!(results_1.len(), req.end - req.start);

        let mut rejected = Vec::with_capacity(req.end - req.start);
        for (client_index, ((mut verifier, eval_proof_0), (verifier_share_1, eval_proof_1))) in
            (req.start..req.end).zip(results_0.into_iter().zip(results_1.into_iter()))
        {
            vec_add(&mut verifier, &verifier_share_1);
            if !mastic.decide(&verifier).unwrap() {
                println!("Report {client_index} rejected (weight check failed)");
                rejected.push(client_index);
            }

            if eval_proof_0 != eval_proof_1 {
                println!("Report {client_index} rejected (onehot or path check failed)");
                rejected.push(client_index);
            }
        }

        println!(
            "{start}..{end}: report validation completed in {:?}: rejected {} reports",
            t.elapsed(),
            rejected.len()
        );

        let t = Instant::now();
        let req = AggregateByAttributesResultRequest {
            rejected,
            num_attributes: attributes.len(),
            start,
            end,
        };

        let resp_0 = client_0.aggregate_by_attributes_finish(long_context(), req.clone());
        let resp_1 = client_1.aggregate_by_attributes_finish(long_context(), req.clone());
        let (mut results, results_share_1) = try_join!(resp_0, resp_1).unwrap();
        for (r, s1) in results.iter_mut().zip(results_share_1.iter()) {
            vec_add(r, s1);
        }

        println!(
            "{start}..{end}: report aggregation completed in {:?}",
            t.elapsed(),
        );

        for (attribute, result) in attributes.iter().zip(results.iter()) {
            println!("{attribute}: {result:?}");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let (cfg, _, num_clients, malicious) = config::get_args("Driver", false, true, true);
    assert!((0.0..0.8).contains(&malicious));
    println!("Running with {}% malicious clients", malicious * 100.0);
    let client_0 = CollectorClient::new(
        client::Config::default(),
        tcp::connect(cfg.server_0, Bincode::default).await?,
    )
    .spawn();
    let client_1 = CollectorClient::new(
        client::Config::default(),
        tcp::connect(cfg.server_1, Bincode::default).await?,
    )
    .spawn();

    let mastic = Mastic::new_histogram(cfg.hist_buckets, 2).unwrap();

    let start = Instant::now();
    println!("Generating keys...");
    let keys = generate_keys(&cfg, &mastic);
    let delta = start.elapsed().as_secs_f64();
    let (nonces, jr_parts) = generate_randomness(&keys);
    let (proofs_0, proofs_1) = generate_proofs(&mastic, &keys, &jr_parts);
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys.len(),
        delta,
        delta / (keys.len() as f64)
    );

    let mut verify_key = [0; 16];
    thread_rng().fill(&mut verify_key);

    reset_servers(&cfg, &client_0, &client_1, &verify_key).await?;

    let mut left_to_go = num_clients;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut responses = vec![];

        for _ in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.add_key_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                responses.push(add_keys(
                    &cfg,
                    (&client_0, &client_1),
                    &keys,
                    (&proofs_0, &proofs_1),
                    &nonces,
                    &jr_parts,
                    this_batch,
                    malicious,
                ));
            }
        }

        for r in responses {
            r.await?;
        }
    }

    let start = Instant::now();
    match cfg.mode {
        Mode::WeightedHeavyHitters { .. } => {
            tree_init(&client_0, &client_1).await?;

            let bit_len = cfg.data_bytes * 8; // bits
            for level in 0..bit_len - 1 {
                let start_level = Instant::now();
                if level == 0 {
                    run_flp_queries(&cfg, &mastic, &client_0, &client_1, num_clients).await?;
                }
                run_level(&cfg, &mastic, &client_0, &client_1, num_clients).await?;
                println!(
                    "Time for level {}: {:?}",
                    level,
                    start_level.elapsed().as_secs_f64()
                );
            }
            println!(
                "\nTime for {} levels: {:?}",
                bit_len,
                start.elapsed().as_secs_f64()
            );

            let start_last = Instant::now();
            run_level_last(&cfg, &mastic, &client_0, &client_1, num_clients).await?;
            println!(
                "Time for last level: {:?}",
                start_last.elapsed().as_secs_f64()
            );
        }

        Mode::AttributeBasedMetrics { num_attributes } => {
            // Synthesize a set of attributes.
            let attributes = {
                let mut rng = rand::thread_rng();
                let zipf =
                    zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();
                let mut unique_inputs = HashSet::with_capacity(num_attributes);
                for _ in 0..num_attributes {
                    let client_index = zipf.sample(&mut rng);
                    unique_inputs.insert(keys[client_index].2.clone());
                }
                unique_inputs.into_iter().collect::<Vec<_>>()
            };
            println!("Using {} attributes", attributes.len());

            run_aggregate_by_attributes(
                &cfg,
                &mastic,
                &client_0,
                &client_1,
                &attributes,
                num_clients,
            )
            .await?;
        }
    };
    println!("Total time {:?}", start.elapsed().as_secs_f64());

    Ok(())
}
