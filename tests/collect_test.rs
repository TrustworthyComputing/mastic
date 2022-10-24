use dpf_codes::collect::*;
use dpf_codes::prg;
use dpf_codes::dpf;
use dpf_codes::*;

#[test]
fn collect_test_eval() {
    let client_strings = [
        "abdef", "abdef", "abdef", "ghijk", "gZijk", "gZ???", "  ?*g", "abdef", "gZ???", "gZ???",
    ];

    let strlen = crate::string_to_bits(&client_strings[0]).len();

    let seed = prg::PrgSeed::random();
    let mut col0 = KeyCollection::new(&seed, strlen);
    let mut col1 = KeyCollection::new(&seed, strlen);

    for cstr in &client_strings {
        let keys = dpf::DPFKey::<FieldElm,FieldElm>::gen_from_str(&cstr);
        col0.add_key(keys.0.clone());
        col1.add_key(keys.1.clone());
    }

    col0.tree_init();
    col1.tree_init();

    let nclients = client_strings.len();
    let threshold = FieldElm::from(2);
    for level in 0..strlen-1 {
        println!("At level {:?}", level);
        let vals0 = col0.tree_crawl();
        let vals1 = col1.tree_crawl();

        assert_eq!(vals0.len(), vals1.len());
        let keep = KeyCollection::<FieldElm,FieldElm>::keep_values(nclients, &threshold, &vals0, &vals1);

        col0.tree_prune(&keep);
        col1.tree_prune(&keep);
    }

    let vals0 = col0.tree_crawl_last();
    let vals1 = col1.tree_crawl_last();

    assert_eq!(vals0.len(), vals1.len());
    let keep = KeyCollection::<FieldElm,FieldElm>::keep_values_last(nclients, &threshold, &vals0, &vals1);

    col0.tree_prune_last(&keep);
    col1.tree_prune_last(&keep);

    let s0 = col0.final_shares();
    let s1 = col1.final_shares();

    for res in &KeyCollection::<FieldElm,FieldElm>::final_values(&s0, &s1) {
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

    let nclients = 1;
    let strlen = crate::string_to_bits(&client_strings[0]).len();

    let seed = prg::PrgSeed::random();
    let mut col0 = KeyCollection::new(&seed, strlen);
    let mut col1 = KeyCollection::new(&seed, strlen);
    // use cpuprofiler::PROFILER;

    let mut keys = vec![];
    println!("Starting to generate keys");
    for s in &client_strings {
        keys.push(dpf::DPFKey::<FieldElm,fastfield::FE>::gen_from_str(&s));
    }
    println!("Done generating keys");

    for i in 0..nclients {
        let copy0 = keys[i % keys.len()].0.clone();
        let copy1 = keys[i % keys.len()].1.clone();
        col0.add_key(copy0);
        col1.add_key(copy1);
        if i % 50 == 0 {
            println!("  Key {:?}", i);
        }
    }

    col0.tree_init();
    col1.tree_init();

    // PROFILER.lock().unwrap().start("./sketch-2.profile").unwrap();
    let threshold = FieldElm::from(2);
    let threshold_last = fastfield::FE::new(2);
    for level in 0..strlen-1 {
        println!("...start");
        let vals0 = col0.tree_crawl();
        let vals1 = col1.tree_crawl();
        println!("...done");
        println!("At level {:?} (size: {:?})", level, vals0.len());

        assert_eq!(vals0.len(), vals1.len());
        let keep = KeyCollection::<FieldElm,fastfield::FE>::keep_values(nclients, &threshold, &vals0, &vals1);

        col0.tree_prune(&keep);
        col1.tree_prune(&keep);
    }
    // PROFILER.lock().unwrap().stop().unwrap();

    let vals0 = col0.tree_crawl_last();
    let vals1 = col1.tree_crawl_last();

    assert_eq!(vals0.len(), vals1.len());
    let keep = KeyCollection::<FieldElm,fastfield::FE>::keep_values_last(nclients, &threshold_last, &vals0, &vals1);

    col0.tree_prune_last(&keep);
    col1.tree_prune_last(&keep);

    let s0 = col0.final_shares();
    let s1 = col1.final_shares();

    for res in &KeyCollection::<FieldElm,fastfield::FE>::final_values(&s0, &s1) {
        println!("Path = {:?}", res.path);
        let s = crate::bits_to_string(&res.path);
        println!("Value: {:?} = {:?}", s, res.value);
    }
}

