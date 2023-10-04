use mastic::collect::*;
use mastic::prg;
use mastic::*;

#[test]
fn collect_test_eval() {
    let client_strings = [
        "abdef", "abdef", "abdef", "ghijk", "gZijk", "gZ???", "  ?*g", "abdef", "gZ???", "gZ???",
    ];

    let strlen = crate::string_to_bits(&client_strings[0]).len();

    let seed = prg::PrgSeed::random();
    let mut col_0 = KeyCollection::new(&seed, strlen);
    let mut col_1 = KeyCollection::new(&seed, strlen);

    for cstr in &client_strings {
        let (keys_0, keys_1) = dpf::DPFKey::<FieldElm, FieldElm>::gen_from_str(&cstr);
        col_0.add_key(keys_0);
        col_1.add_key(keys_1);
    }

    col_0.tree_init();
    col_1.tree_init();

    let num_clients = client_strings.len();
    let threshold = FieldElm::from(2);
    let malicious = Vec::<usize>::new();
    for level in 0..strlen - 1 {
        println!("At level {:?}", level);
        let (vals_0, _, _) = col_0.tree_crawl(1usize, &malicious, false);
        let (vals_1, _, _) = col_1.tree_crawl(1usize, &malicious, false);

        assert_eq!(vals_0.len(), vals_1.len());
        let keep = KeyCollection::<FieldElm, FieldElm>::keep_values(&threshold, &vals_0, &vals_1);

        col_0.tree_prune(&keep);
        col_1.tree_prune(&keep);
    }

    let mut verified = vec![true; num_clients];
    let (hashes_0, _) = col_0.tree_crawl_last();
    let (hashes_1, _) = col_1.tree_crawl_last();
    mastic::check_hashes(&mut verified, &hashes_0, &hashes_1);
    assert!(verified.iter().all(|&x| x));

    let vals_0 = col_0.add_leaves_between_clients(&verified);
    let vals_1 = col_1.add_leaves_between_clients(&verified);

    assert_eq!(vals_0.len(), vals_1.len());
    let keep = KeyCollection::<FieldElm, FieldElm>::keep_values_last(
        &threshold,
        &vals_0,
        &vals_1,
    );

    col_0.tree_prune_last(&keep);
    col_1.tree_prune_last(&keep);

    let shares_0 = col_0.final_shares();
    let shares_1 = col_1.final_shares();

    for res in &KeyCollection::<FieldElm, FieldElm>::final_values(&shares_0, &shares_1) {
        println!("Path = {:?}", res.path);
        let s = crate::bits_to_string(&res.path);
        println!("fast: {:?} = {:?}", s, res.value);

        match &s[..] {
            "abdef" => assert_eq!(res.value, FieldElm::from(4)),
            "gZ???" => assert_eq!(res.value, FieldElm::from(3)),
            _ => {
                println!("Unexpected string: '{:?}' = {:?}", s, res.value);
                assert!(false);
            }
        }
    }
}

#[test]
fn collect_test_eval_full() {
    let client_strings = [
        "01234567012345670123456701234567",
        "z12x45670y2345670123456701234567",
        "612x45670y2345670123456701234567",
        "912x45670y2345670123456701234567",
    ];

    let num_clients = 10;
    let strlen = crate::string_to_bits(&client_strings[0]).len();

    let seed = prg::PrgSeed::random();
    let mut col_0 = KeyCollection::new(&seed, strlen);
    let mut col_1 = KeyCollection::new(&seed, strlen);

    let mut keys = vec![];
    println!("Starting to generate keys");
    for s in &client_strings {
        keys.push(dpf::DPFKey::<FieldElm, fastfield::FE>::gen_from_str(&s));
    }
    println!("Done generating keys");

    for i in 0..num_clients {
        let copy_0 = keys[i % keys.len()].0.clone();
        let copy_1 = keys[i % keys.len()].1.clone();
        col_0.add_key(copy_0);
        col_1.add_key(copy_1);
        if i % 50 == 0 {
            println!("  Key {:?}", i);
        }
    }

    col_0.tree_init();
    col_1.tree_init();

    let threshold = FieldElm::from(2);
    let threshold_last = fastfield::FE::new(2);
    let malicious = Vec::<usize>::new();
    for level in 0..strlen-1 {
        println!("...start");
        let (vals_0, _, _) = col_0.tree_crawl(1usize, &malicious, false);
        let (vals_1, _, _) = col_1.tree_crawl(1usize, &malicious, false);
        println!("...done");
        println!("At level {:?} (size: {:?})", level, vals_0.len());

        assert_eq!(vals_0.len(), vals_1.len());
        let keep = KeyCollection::<FieldElm, fastfield::FE>::keep_values(&threshold, &vals_0, &vals_1);

        col_0.tree_prune(&keep);
        col_1.tree_prune(&keep);
    }

    let (hashes_0, _) = col_0.tree_crawl_last();
    let (hashes_1, _) = col_1.tree_crawl_last();
    let mut verified = vec![true; num_clients];
    mastic::check_hashes(&mut verified, &hashes_0, &hashes_1);
    assert!(verified.iter().all(|&x| x));

    let vals_0 = col_0.add_leaves_between_clients(&verified);
    let vals_1 = col_1.add_leaves_between_clients(&verified);

    assert_eq!(vals_0.len(), vals_1.len());
    let keep = KeyCollection::<FieldElm, fastfield::FE>::keep_values_last(&threshold_last, &vals_0, &vals_1);

    col_0.tree_prune_last(&keep);
    col_1.tree_prune_last(&keep);

    let s0 = col_0.final_shares();
    let s1 = col_1.final_shares();

    for res in &KeyCollection::<FieldElm,fastfield::FE>::final_values(&s0, &s1) {
        println!("Path = {:?}", res.path);
        let s = crate::bits_to_string(&res.path);
        println!("Value: {:?} = {:?}", s, res.value);
    }
}
