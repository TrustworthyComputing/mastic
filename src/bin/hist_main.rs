use dpf_codes::{
    collect, 
    config,
    dpf,
    fastfield::FE, 
    FieldElm, 
    prg, 
};
use num_traits::cast::ToPrimitive;
use rand::Rng;
use rand::distributions::Alphanumeric;
use rayon::prelude::*;
use std::time::Instant;
use itertools::Itertools;
type Key = dpf::DPFKey<FE, FieldElm>;

fn sample_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric) as char)
        .take(len / 8)
        .collect()
}

fn generate_keys(cfg: &config::Config) -> (Vec<Key>, Vec<Key>) {
    println!("data_len = {}\n", cfg.data_len);

    let (keys0, keys1): (Vec<Key>, Vec<Key>) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .enumerate()
        .map(|(i, _)| {
            let data_string = sample_string(cfg.data_len * 8);
            let bit_str = dpf_codes::bits_to_bitstring(
                dpf_codes::string_to_bits(&data_string).as_slice()
            );
            println!("Client({}) \t input \"{}\" ({})", i, data_string, bit_str);
            
            dpf::DPFKey::gen_from_str(&data_string)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys0[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    (keys0, keys1)
}


pub fn verify_clients_histogram(
    hashes0: &Vec<Vec<u8>>, hashes1: &Vec<Vec<u8>>,
    tau_vals0: &Vec<FieldElm>, tau_vals1: &Vec<FieldElm>
) -> Vec<bool> {
    assert_eq!(hashes0.len(), hashes1.len());
    assert_eq!(tau_vals0.len(), tau_vals1.len());
    assert_eq!(hashes0.len(), tau_vals0.len());

    let mut verified = vec![true; hashes0.len()];

    let tau_vals = &collect::KeyCollection::<FE, FieldElm>::reconstruct_shares(
        tau_vals0, tau_vals1
    );

    for ((i, h0), h1) in hashes0.iter().enumerate().zip_eq(hashes1) {
        let matching = h0.iter().zip(h1.iter()).filter(|&(h0, h1)| h0 == h1).count();
        if h0.len() != matching || tau_vals[i].value().to_u32().unwrap() != 1 {
            println!("Client {}, {} != {}", i, hex::encode(h0), hex::encode(h1));
            verified[i] = false;
        }
    }

    verified
}

fn main() {
    let (cfg, _, nreqs) = config::get_args("histogram-main", false, true);

    let start = Instant::now();
    let (keys0, keys1) = generate_keys(&cfg);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} unique keys in {:?} seconds ({:?} sec/key)",
        keys0.len(),
        delta,
        delta / (keys0.len() as f64)
    );

    let seed = prg::PrgSeed::random();
    let bitlen = cfg.data_len * 8; // bits
    let mut col0 = collect::KeyCollection::<FE, FieldElm>::new(&seed, bitlen);
    let mut col1 = collect::KeyCollection::<FE, FieldElm>::new(&seed, bitlen);

    println!("Running with {} clients", nreqs);
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();
    for _ in 0..nreqs {
        let idx = zipf.sample(&mut rng) - 1;
        col0.add_key(keys0[idx].clone());
        col1.add_key(keys1[idx].clone());
    }

    col0.tree_init();
    col1.tree_init();

    for _ in 0..bitlen-1 {
        col0.histogram_tree_crawl();
        col1.histogram_tree_crawl();
    }

    let (hashes0, tau_vals0) = col0.histogram_tree_crawl_last();
    let (hashes1, tau_vals1) = col1.histogram_tree_crawl_last();

    let verified = verify_clients_histogram(&hashes0, &hashes1, &tau_vals0, &tau_vals1);

    let s0 = col0.histogram_add_leaves_between_clients(&verified);
    let s1 = col1.histogram_add_leaves_between_clients(&verified);

    for res in &collect::KeyCollection::<FE, FieldElm>::final_values(&s0, &s1) {
        let bits = dpf_codes::bits_to_bitstring(&res.path);
        println!("Value ({}) \t Count: {:?}", bits, res.value.value());
    }

}
