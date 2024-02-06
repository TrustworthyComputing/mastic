use std::{
    collections::HashSet,
    io::{self, Error},
    time::{Duration, Instant, SystemTime},
};

use futures::try_join;
use mastic::{
    bits_to_bitstring,
    collect::{self, ReportShare},
    config::{self, Mode},
    histogram_chunk_length,
    rpc::{
        AddReportSharesRequest, ApplyFLPResultsRequest, AttributeBasedMetricsResultRequest,
        AttributeBasedMetricsValidateRequest, FinalSharesRequest, GetProofsRequest,
        PlainMetricsResultRequest, PlainMetricsValidateRequest, ResetRequest, RunFlpQueriesRequest,
        TreeCrawlLastRequest, TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    vec_add,
    vidpf::VidpfKey,
    CollectorClient, Mastic, MasticHistogram,
};
use prio::{
    codec::Encode,
    field::{random_vector, Field128},
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PublicShare},
        xof::{IntoFieldVec, Xof, XofShake128},
        Client, Collector,
    },
};
use rand::{distributions::Distribution, thread_rng, Rng};
use rand_core::RngCore;
use rayon::prelude::*;
use tarpc::{client, context, serde_transport::tcp, tokio_serde::formats::Bincode};

fn long_context() -> context::Context {
    let mut ctx = context::current();

    // Increase timeout to one hour
    ctx.deadline = SystemTime::now() + Duration::from_secs(1000000);
    ctx
}

fn sample_bits(len: usize) -> Vec<bool> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<bool>()).collect()
}

enum PlaintextReport {
    /// A plaintext report for Mastic. This report type is used for weighted heavy hitters and
    /// attribute-based metrics.
    Mastic {
        nonce: [u8; 16],
        vidpf_keys: [VidpfKey; 2],
        flp_proof_shares: [Vec<Field128>; 2],
        flp_joint_rand_parts: [[u8; 16]; 2],
        alpha: Vec<bool>,
    },

    /// A plaintext report for Prio3. This report type is used for plain (non-attribute-based)
    /// metrics.
    Prio3 {
        nonce: [u8; 16],
        public_share: Prio3PublicShare<16>,
        input_shares: [Prio3InputShare<Field128, 16>; 2],
    },
}

impl PlaintextReport {
    /// Panics unless the type is `Mastic`.
    fn unwrap_alpha(&self) -> Vec<bool> {
        match self {
            Self::Mastic {
                nonce: _,
                vidpf_keys: _,
                flp_proof_shares: _,
                flp_joint_rand_parts: _,
                alpha,
            } => alpha.clone(),
            Self::Prio3 { .. } => panic!("Prio3 reports don't have an alpha"),
        }
    }

    fn to_shares(&self) -> [ReportShare; 2] {
        match self {
            Self::Mastic {
                nonce,
                vidpf_keys,
                flp_proof_shares,
                flp_joint_rand_parts,
                ..
            } => [
                ReportShare::Mastic {
                    nonce: *nonce,
                    vidpf_key: vidpf_keys[0].clone(),
                    flp_proof_share: flp_proof_shares[0].clone(),
                    flp_joint_rand_parts: *flp_joint_rand_parts,
                },
                ReportShare::Mastic {
                    nonce: *nonce,
                    vidpf_key: vidpf_keys[1].clone(),
                    flp_proof_share: flp_proof_shares[1].clone(),
                    flp_joint_rand_parts: *flp_joint_rand_parts,
                },
            ],
            Self::Prio3 {
                nonce,
                public_share,
                input_shares,
            } => [
                ReportShare::Prio3 {
                    nonce: *nonce,
                    public_share_bytes: public_share.get_encoded(),
                    input_share_bytes: input_shares[0].get_encoded(),
                },
                ReportShare::Prio3 {
                    nonce: *nonce,
                    public_share_bytes: public_share.get_encoded(),
                    input_share_bytes: input_shares[1].get_encoded(),
                },
            ],
        }
    }
}

fn generate_reports(cfg: &config::Config, mastic: &MasticHistogram) -> Vec<PlaintextReport> {
    assert!(cfg.unique_buckets > 0);

    let reports = (0..cfg.unique_buckets)
        .into_par_iter()
        .map(|_| {
            let mut rng = thread_rng();
            let nonce = rng.gen::<[u8; 16]>();

            // Synthesize a fake histogram contribution.
            let bucket = rng.gen_range(0..cfg.hist_buckets);

            match cfg.mode {
                Mode::WeightedHeavyHitters { .. } | Mode::AttributeBasedMetrics { .. } => {
                    // Synthesize a fake input and weight.
                    let alpha = sample_bits(cfg.data_bits);
                    let beta = mastic.encode_measurement(&bucket).unwrap();

                    let (key_0, key_1) = VidpfKey::gen(&alpha, &beta);

                    let jr_parts = {
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
                        jr_parts
                    };

                    let (proof_0, proof_1) = {
                        let joint_rand_xof = XofShake128::init(&jr_parts[0], &jr_parts[1]);
                        let joint_rand: Vec<Field128> = joint_rand_xof
                            .into_seed_stream()
                            .into_field_vec(mastic.joint_rand_len());

                        let prove_rand = random_vector(mastic.prove_rand_len()).unwrap();
                        let proof = mastic.prove(&beta, &prove_rand, &joint_rand).unwrap();

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
                    };

                    PlaintextReport::Mastic {
                        nonce,
                        vidpf_keys: [key_0, key_1],
                        flp_proof_shares: [proof_0, proof_1],
                        flp_joint_rand_parts: jr_parts,
                        alpha,
                    }
                }
                Mode::PlainMetrics => {
                    let chunk_length =
                        histogram_chunk_length(mastic.input_len(), Mode::PlainMetrics);
                    let prio3 = Prio3::new_histogram(2, mastic.input_len(), chunk_length).unwrap();
                    let (public_share, input_shares) = prio3.shard(&bucket, &nonce).unwrap();

                    PlaintextReport::Prio3 {
                        nonce,
                        public_share,
                        input_shares: input_shares.try_into().unwrap(),
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    match &reports[0] {
        PlaintextReport::Mastic {
            nonce,
            vidpf_keys,
            flp_proof_shares,
            flp_joint_rand_parts,
            ..
        } => {
            let encoded: Vec<u8> = bincode::serialize(nonce).unwrap();
            println!("\t- Nonce size: {:?} bytes", encoded.len());

            let encoded: Vec<u8> = bincode::serialize(&flp_joint_rand_parts[0]).unwrap();
            println!("\t- JR size: {:?} bytes", encoded.len());

            let encoded: Vec<u8> = bincode::serialize(&vidpf_keys[0]).unwrap();
            println!("\t- VIDPFKey size: {:?} bytes", encoded.len());

            let encoded: Vec<u8> = bincode::serialize(&flp_proof_shares[0]).unwrap();
            println!("\t- FLP proof size: {:?} bytes", encoded.len());
        }
        r @ PlaintextReport::Prio3 { .. } => {
            let [report_share_0, report_share_1] = r.to_shares();

            let encoded: Vec<u8> = bincode::serialize(&report_share_0).unwrap();
            println!("\t- leader report share size: {:?} bytes", encoded.len());

            let encoded: Vec<u8> = bincode::serialize(&report_share_1).unwrap();
            println!("\t- helper report share size: {:?} bytes", encoded.len());
        }
    }

    reports
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

async fn add_reports(
    cfg: &config::Config,
    clients: (&CollectorClient, &CollectorClient),
    all_reports: &[PlaintextReport],
    num_clients: usize,
    malicious_percentage: f32,
) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut report_shares_0 = Vec::with_capacity(num_clients);
    let mut report_shares_1 = Vec::with_capacity(num_clients);
    for r in 0..num_clients {
        let idx_1 = zipf.sample(&mut rng) - 1;
        let [report_share_0, mut report_share_1] = all_reports[idx_1].to_shares();

        if rng.gen_range(0.0..1.0) < malicious_percentage {
            match report_share_1 {
                ReportShare::Mastic {
                    nonce: _,
                    ref mut vidpf_key,
                    ref mut flp_proof_share,
                    flp_joint_rand_parts: _,
                } => {
                    if rng.gen() {
                        // Malicious key. Tweaking the root seed is sufficient to cause VIDPF
                        // verification to fail.
                        vidpf_key.get_root_seed().key[0] ^= 1;
                    } else {
                        // Malicious FLP. Tweaking the proof is sufficient to cause FLP verification to
                        // fail.
                        flp_proof_share[0] += Field128::from(1337);
                    }
                }
                ReportShare::Prio3 {
                    nonce: _,
                    public_share_bytes: _,
                    ref mut input_share_bytes,
                } => {
                    // Tweaking the input share is sufficient to cause FLP verification to fail.
                    input_share_bytes[0] ^= 1;
                }
            }
            println!("Malicious {}", r);
        }

        report_shares_0.push(report_share_0);
        report_shares_1.push(report_share_1);
    }

    let resp_0 = clients.0.add_report_shares(
        long_context(),
        AddReportSharesRequest {
            report_shares: report_shares_0,
        },
    );
    let resp_1 = clients.1.add_report_shares(
        long_context(),
        AddReportSharesRequest {
            report_shares: report_shares_1,
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
    let start_last = Instant::now();
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
    println!(
        "- Time for level {}: {:?}\n",
        cfg.data_bits,
        start_last.elapsed().as_secs_f64()
    );
    for res in &collect::KeyCollection::final_values(mastic.input_len(), &shares_0, &shares_1) {
        let bits = mastic::bits_to_bitstring(&res.path);
        if res.value[mastic.input_len() - 1] > Field128::from(0) {
            println!("Value ({}) \t Count: {:?}", bits, res.value);
        }
    }

    Ok(())
}

async fn run_attribute_based_metrics(
    cfg: &config::Config,
    mastic: &MasticHistogram,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    attributes: &[Vec<bool>],
    num_clients: usize,
) -> io::Result<()> {
    for start in (0..num_clients).step_by(cfg.flp_batch_size) {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);
        let req = AttributeBasedMetricsValidateRequest {
            attributes: attributes.to_vec(),
            start,
            end,
        };

        // For each report, each aggregator evaluates the VIDPF on each of the attributes and returns
        // the VIDPF proof and its FLP verifier share.
        let t = Instant::now();
        let resp_0 = client_0.attribute_based_metrics_validate(long_context(), req.clone());
        let resp_1 = client_1.attribute_based_metrics_validate(long_context(), req.clone());
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
        let req = AttributeBasedMetricsResultRequest {
            rejected,
            num_attributes: attributes.len(),
            start,
            end,
        };

        let resp_0 = client_0.attribute_based_metrics_result(long_context(), req.clone());
        let resp_1 = client_1.attribute_based_metrics_result(long_context(), req.clone());
        let (mut results, results_share_1) = try_join!(resp_0, resp_1).unwrap();
        for (r, s1) in results.iter_mut().zip(results_share_1.iter()) {
            vec_add(r, s1);
        }

        println!(
            "{start}..{end}: report aggregation completed in {:?}",
            t.elapsed(),
        );

        for (attribute, result) in attributes.iter().zip(results.iter()) {
            println!("{}: {result:?}", bits_to_bitstring(attribute));
        }
    }

    Ok(())
}

async fn run_plain_metrics(
    cfg: &config::Config,
    mastic: &MasticHistogram,
    client_0: &CollectorClient,
    client_1: &CollectorClient,
    num_clients: usize,
) -> io::Result<()> {
    let chunk_length = histogram_chunk_length(mastic.input_len(), Mode::PlainMetrics);
    let prio3 = Prio3::new_histogram(2, mastic.input_len(), chunk_length).unwrap();

    for start in (0..num_clients).step_by(cfg.flp_batch_size) {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);
        let req = PlainMetricsValidateRequest { start, end };

        // For each report, each aggregator evaluates the VIDPF on each of the attributes and returns
        // the VIDPF proof and its FLP verifier share.
        let t = Instant::now();
        let resp_0 = client_0.plain_metrics_validate(long_context(), req.clone());
        let resp_1 = client_1.plain_metrics_validate(long_context(), req.clone());
        let (results_0, results_1) = try_join!(resp_0, resp_1).unwrap();
        assert_eq!(results_0.len(), req.end - req.start);
        assert_eq!(results_1.len(), req.end - req.start);
        println!(
            "{start}..{end}: report validation initialized in {:?}",
            t.elapsed(),
        );

        // Relay each aggregator's prep shares to its peer.
        //
        // NOTE To validate the report, each aggregator combines the prep shares, then uses the
        // combined prep message and its state to compute its output share. Thus it is necessary to
        // relay each aggregator's prep share to its peer. We could save communication here by
        // having the driver compute the prep message at this point, however the libprio-rs API
        // currently doesn't allow this. See https://github.com/divviup/libprio-rs/issues/912.
        let t = Instant::now();
        let resp_0 = client_0.plain_metrics_result(
            long_context(),
            PlainMetricsResultRequest {
                peer_prep_shares: results_1,
                start,
                end,
            },
        );
        let resp_1 = client_1.plain_metrics_result(
            long_context(),
            PlainMetricsResultRequest {
                peer_prep_shares: results_0,
                start,
                end,
            },
        );
        let ((agg_share_0, rejected_count), (agg_share_1, rejected_count_1)) =
            try_join!(resp_0, resp_1).unwrap();
        assert_eq!(rejected_count, rejected_count_1);
        let result = prio3
            .unshard(
                &(),
                [agg_share_0, agg_share_1],
                end - start - rejected_count,
            )
            .unwrap();

        println!(
            "{start}..{end}: report validation and aggregation completed in {:?}: rejected {} reports",
            t.elapsed(),
            rejected_count,
        );

        println!("{result:?}");
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

    println!("- Mode: {:?}", cfg.mode);
    println!("- Using {:?} histogram buckets", cfg.hist_buckets);
    println!("- Using {:?} bits", cfg.data_bits);

    let mastic = Mastic::new_histogram(cfg.hist_buckets).unwrap();
    let start = Instant::now();
    println!("Generating reports...");
    let reports = generate_reports(&cfg, &mastic);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        reports.len(),
        delta,
        delta / (reports.len() as f64)
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
                responses.push(add_reports(
                    &cfg,
                    (&client_0, &client_1),
                    &reports,
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

            for level in 0..cfg.data_bits - 1 {
                let start_level = Instant::now();
                if level == 0 {
                    run_flp_queries(&cfg, &mastic, &client_0, &client_1, num_clients).await?;
                }
                run_level(&cfg, &mastic, &client_0, &client_1, num_clients).await?;
                println!(
                    "- Time for level {}: {:?}",
                    level + 1,
                    start_level.elapsed().as_secs_f64()
                );
            }
            run_level_last(&cfg, &mastic, &client_0, &client_1, num_clients).await?;
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
                    unique_inputs.insert(reports[client_index].unwrap_alpha());
                }
                unique_inputs.into_iter().collect::<Vec<_>>()
            };
            println!("Using {} attributes", attributes.len());

            run_attribute_based_metrics(
                &cfg,
                &mastic,
                &client_0,
                &client_1,
                &attributes,
                num_clients,
            )
            .await?;
        }
        Mode::PlainMetrics => {
            run_plain_metrics(&cfg, &mastic, &client_0, &client_1, num_clients).await?
        }
    };
    println!("Total time {:?}", start.elapsed().as_secs_f64());

    Ok(())
}
