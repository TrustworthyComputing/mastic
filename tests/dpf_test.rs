use std::ops::Add;

use blake3::hash;
use mastic::{vidpf::*, *};
use prio::field::Field128;

#[test]
fn dpf_complete() {
    let num_bits = 5;
    let alpha = u32_to_bits(num_bits, 21);
    let beta = vec![Field128::from(7u128)];
    let (key_0, key_1) = VidpfKey::gen(&alpha, &beta);

    let mut pi_0: [u8; HASH_SIZE] = hash(b"0").as_bytes()[0..HASH_SIZE].try_into().unwrap();
    let mut pi_1: [u8; HASH_SIZE] = pi_0.clone();

    for i in 0..(1 << num_bits) {
        let alpha_eval = u32_to_bits(num_bits, i);

        println!("Alpha: {:?}", alpha);
        for j in 2..((num_bits - 1) as usize) {
            let eval_0 = key_0.eval(&alpha_eval[0..j].to_vec(), &mut pi_0, 1);
            let eval_1 = key_1.eval(&alpha_eval[0..j].to_vec(), &mut pi_1, 1);

            let tmp = eval_0.0[j - 2][0].add(eval_1.0[j - 2][0]);
            println!("[{:?}] Tmp {:?} = {:?}", alpha_eval, j, tmp);
            if alpha[0..j - 1] == alpha_eval[0..j - 1] {
                assert_eq!(
                    beta[0], tmp,
                    "[Level {:?}] Value incorrect at {:?}",
                    j, alpha_eval
                );
            } else {
                assert_eq!(Field128::from(0), tmp);
            }
        }

        assert_eq!(pi_0, pi_1);
    }
}
