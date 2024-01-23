use mastic::{collect::*, prg, *};
use prio::{
    field::Field64,
    flp::{types::Count, Type},
};
use rand::{thread_rng, Rng};
use rayon::prelude::*;

#[test]
fn collect_test_eval_groups() {
    let client_strings = [
        "abdef", "abdef", "abdef", "ghijk", "gZijk", "gZ???", "  ?*g", "abdef", "gZ???", "gZ???",
    ];

    let strlen = crate::string_to_bits(&client_strings[0]).len();

    let seed = prg::PrgSeed::random();
    let mut verify_key = [0; 16];
    thread_rng().fill(&mut verify_key);

    let typ = Count::<Field64>::new();
    let mut col_0 = KeyCollection::new(typ.clone(), 0, &seed, strlen, verify_key);
    let mut col_1 = KeyCollection::new(typ.clone(), 1, &seed, strlen, verify_key);

    for cstr in &client_strings {
        let input_beta = typ.encode_measurement(&1).unwrap();
        let (keys_0, keys_1) = vidpf::VidpfKey::gen_from_str(&cstr, &input_beta);
        col_0.add_key(keys_0);
        col_1.add_key(keys_1);
    }

    col_0.tree_init();
    col_1.tree_init();

    let threshold = 2;
    let malicious = Vec::<usize>::new();
    for level in 0..strlen - 1 {
        println!("At level {:?}", level);
        let (cnt_values_0, _, _) = col_0.tree_crawl(1usize, &malicious, false);
        let (cnt_values_1, _, _) = col_1.tree_crawl(1usize, &malicious, false);

        assert_eq!(cnt_values_0.len(), cnt_values_1.len());
        let keep =
            KeyCollection::keep_values(typ.input_len(), threshold, &cnt_values_0, &cnt_values_1);

        col_0.tree_prune(&keep);
        col_1.tree_prune(&keep);
    }

    let cnt_values_0 = col_0.tree_crawl_last();
    let cnt_values_1 = col_1.tree_crawl_last();

    let hashes_0 = col_0.get_proofs(0, client_strings.len());
    let hashes_1 = col_1.get_proofs(0, client_strings.len());

    assert_eq!(cnt_values_0.len(), cnt_values_1.len());
    assert_eq!(hashes_0.len(), hashes_1.len());

    let verified = hashes_0
        .par_iter()
        .zip(hashes_1.par_iter())
        .all(|(&h0, &h1)| h0 == h1);
    assert!(verified);

    let keep = KeyCollection::keep_values(typ.input_len(), threshold, &cnt_values_0, &cnt_values_1);

    col_0.tree_prune(&keep);
    col_1.tree_prune(&keep);

    let shares_0 = col_0.final_shares();
    let shares_1 = col_1.final_shares();

    for res in &KeyCollection::final_values(typ.input_len(), &shares_0, &shares_1) {
        println!("Path = {:?}", res.path);
        let s = crate::bits_to_string(&res.path);
        println!("fast: {:?} = {:?}", s, res.value);

        match &s[..] {
            "abdef" => assert_eq!(res.value, vec![4, 4]),
            "gZ???" => assert_eq!(res.value, vec![3, 3]),
            _ => {
                println!("Unexpected string: '{:?}' = {:?}", s, res.value);
                assert!(false);
            }
        }
    }
}

#[test]
fn collect_test_eval_full_groups() {
    let client_strings = [
        "01234567012345670123456701234567",
        "z12x45670y2345670123456701234567",
        "612x45670y2345670123456701234567",
        "912x45670y2345670123456701234567",
    ];

    let num_clients = 10;
    let strlen = crate::string_to_bits(&client_strings[0]).len();

    let seed = prg::PrgSeed::random();
    let mut verify_key = [0; 16];
    thread_rng().fill(&mut verify_key);
    let typ = Count::<Field64>::new();
    let mut col_0 = KeyCollection::new(typ.clone(), 0, &seed, strlen, verify_key);
    let mut col_1 = KeyCollection::new(typ.clone(), 1, &seed, strlen, verify_key);

    let mut keys = vec![];
    println!("Starting to generate keys");
    for s in &client_strings {
        let input_beta = typ.encode_measurement(&1u64).unwrap();
        keys.push(vidpf::VidpfKey::gen_from_str(&s, &input_beta));
    }
    println!("Done generating keys");

    for i in 0..num_clients {
        let copy_0 = keys[i % keys.len()].0.clone();
        let copy_1 = keys[i % keys.len()].1.clone();
        col_0.add_key(copy_0);
        col_1.add_key(copy_1);
        if i % 50 == 0 {
            println!("  VIDPFKey {:?}", i);
        }
    }

    col_0.tree_init();
    col_1.tree_init();

    let threshold = 2;
    let malicious = Vec::<usize>::new();
    for level in 0..strlen - 1 {
        println!("...start");
        let (cnt_values_0, _, _) = col_0.tree_crawl(1usize, &malicious, false);
        let (cnt_values_1, _, _) = col_1.tree_crawl(1usize, &malicious, false);
        println!("...done");
        println!("At level {:?} (size: {:?})", level, cnt_values_0.len());

        assert_eq!(cnt_values_0.len(), cnt_values_1.len());
        let keep =
            KeyCollection::keep_values(typ.input_len(), threshold, &cnt_values_0, &cnt_values_1);

        col_0.tree_prune(&keep);
        col_1.tree_prune(&keep);
    }

    let cnt_values_0 = col_0.tree_crawl_last();
    let cnt_values_1 = col_1.tree_crawl_last();

    let hashes_0 = col_0.get_proofs(0, client_strings.len());
    let hashes_1 = col_1.get_proofs(0, client_strings.len());

    assert_eq!(cnt_values_0.len(), cnt_values_1.len());
    assert_eq!(hashes_0.len(), hashes_1.len());

    let verified = hashes_0
        .par_iter()
        .zip(hashes_1.par_iter())
        .all(|(&h0, &h1)| h0 == h1);
    assert!(verified);

    let keep = KeyCollection::keep_values(typ.input_len(), threshold, &cnt_values_0, &cnt_values_1);

    col_0.tree_prune(&keep);
    col_1.tree_prune(&keep);

    let s0 = col_0.final_shares();
    let s1 = col_1.final_shares();

    for res in &KeyCollection::final_values(typ.input_len(), &s0, &s1) {
        println!("Path = {:?}", res.path);
        let s = crate::bits_to_string(&res.path);
        println!("Value: {:?} = {:?}", s, res.value);
    }
}
