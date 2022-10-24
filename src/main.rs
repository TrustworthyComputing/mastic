use dpf_codes::{collect, FieldElm, fastfield::FE, prg, dpf, encode, config};
use geo::Point;
use rand::Rng;
use rayon::prelude::*;
use std::time::Instant;
type Key = dpf::DPFKey<FE, FieldElm>;


fn sample_location() -> (f64, f64) {
    let mut rng = rand::thread_rng();
    (rng.gen_range(-180.0..180.0) as f64, rng.gen_range(-90.0..90.0) as f64)
}

fn generate_keys(cfg: &config::Config) -> (Vec<Key>, Vec<Key>) {
    println!("data_len = {}\n", cfg.data_len);

    let (keys0, keys1): (Vec<Key>, Vec<Key>) = rayon::iter::repeat(0)
        .take(cfg.num_sites)
        .map(|_| {
            let loc = sample_location();
            let data_string = encode(Point::new(loc.0, loc.1), cfg.data_len);
            // let data_string = _sample_string(8 * 2);
        
            println!("data_string = {}", data_string);
            
            dpf::DPFKey::gen_from_str(&data_string)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys0[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    (keys0, keys1)
}

fn main() {
    let (cfg, _, n_reqs) = config::get_args("main", false, false);

    let start = Instant::now();
    let (keys0, keys1) = generate_keys(&cfg);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys0.len(),
        delta,
        delta / (keys0.len() as f64)
    );

    let seed = prg::PrgSeed::random();
    let bitlen = cfg.data_len * 8; // bits
    let mut col0 = collect::KeyCollection::<FE, FieldElm>::new(&seed, bitlen);
    let mut col1 = collect::KeyCollection::<FE, FieldElm>::new(&seed, bitlen);

    for i in 0..keys0.len() {
        col0.add_key(keys0[i].clone());
        col1.add_key(keys1[i].clone());
    }

    col0.tree_init();
    col1.tree_init();

    let threshold = 2u32;
    let threshold_fe = FE::from(threshold);
    let threshold_fieldelm = FieldElm::from(threshold);
    for _ in 0..bitlen-1 {
        let vals0 = col0.tree_crawl();
        let vals1 = col1.tree_crawl();

        assert_eq!(vals0.len(), vals1.len());

        let keep = collect::KeyCollection::<FE, FieldElm>::keep_values(n_reqs, &threshold_fe, &vals0, &vals1);

        col0.tree_prune(&keep);
        col1.tree_prune(&keep);
    }

    let vals0 = col0.tree_crawl_last();
    let vals1 = col1.tree_crawl_last();
    let keep = collect::KeyCollection::<FE, FieldElm>::keep_values_last(n_reqs, &threshold_fieldelm, &vals0, &vals1);
    col0.tree_prune_last(&keep);
    col1.tree_prune_last(&keep);

    let s0 = col0.final_shares();
    let s1 = col1.final_shares();
    for res in &collect::KeyCollection::<FE, FieldElm>::final_values(&s0, &s1) {
        let bits = dpf_codes::bits_to_bitstring(&res.path);
        let s = dpf_codes::bits_to_string(&res.path);
        println!("Value: {:?} ({}) \t Count: {:?}", s, bits, res.value.value());
    }

}
