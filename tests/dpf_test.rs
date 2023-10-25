use std::ops::Add;

use mastic::{dpf::*, *};
use prio::field::Field64;
use sha2::{Digest, Sha256};

#[test]
fn dpf_complete() {
    let num_bits = 5;
    let alpha = u32_to_bits(num_bits, 21);
    let betas = vec![
        Field64::from(7u64),
        Field64::from(17u64),
        Field64::from(2u64),
        Field64::from(0u64),
        Field64::from(32u64),
    ];
    let (key_0, key_1) = DPFKey::gen(&alpha, &betas);

    let (mut pi_0, mut pi_1) = {
        let mut hasher = Sha256::new();
        hasher.update("0");
        let tmp = hasher.finalize().to_vec();
        (tmp.clone(), tmp)
    };

    for i in 0..(1 << num_bits) {
        let alpha_eval = u32_to_bits(num_bits, i);

        println!("Alpha: {:?}", alpha);
        for j in 2..((num_bits - 1) as usize) {
            let eval_0 = key_0.eval(&alpha_eval[0..j].to_vec(), &mut pi_0);
            let eval_1 = key_1.eval(&alpha_eval[0..j].to_vec(), &mut pi_1);

            let tmp = eval_0.0[j - 2].add(eval_1.0[j - 2]);
            println!("[{:?}] Tmp {:?} = {:?}", alpha_eval, j, tmp);
            if alpha[0..j - 1] == alpha_eval[0..j - 1] {
                assert_eq!(
                    betas[j - 2],
                    tmp,
                    "[Level {:?}] Value incorrect at {:?}",
                    j,
                    alpha_eval
                );
            } else {
                assert_eq!(Field64::from(0), tmp);
            }
        }

        assert_eq!(pi_0, pi_1);
    }
}
