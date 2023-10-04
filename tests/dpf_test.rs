use mastic::dpf::*;
use mastic::*;
use sha2::{Digest, Sha256};

#[test]
fn dpf_complete() {
    let num_bits = 5;
    let alpha = u32_to_bits(num_bits, 21);
    let betas = vec![
        FieldElm::from(7u32),
        FieldElm::from(17u32),
        FieldElm::from(2u32),
        FieldElm::from(0u32),
    ];
    let beta_last = fastfield::FE::from(32u32);
    let (key_0, key_1) = DPFKey::gen(&alpha, &betas, &beta_last);

    let (mut pi_0, mut pi_1) = {
        let mut hasher = Sha256::new();
        hasher.update("0");
        let tmp = hasher.finalize().to_vec();
        (tmp.clone(), tmp)
    };

    for i in 0..(1 << num_bits) {
        let alpha_eval = u32_to_bits(num_bits, i);

        println!("Alpha: {:?}", alpha);
        for j in 2..((num_bits-1) as usize) {
            let eval_0 = key_0.eval(&alpha_eval[0..j].to_vec(), &mut pi_0);
            let eval_1 = key_1.eval(&alpha_eval[0..j].to_vec(), &mut pi_1);

            let mut tmp = FieldElm::zero();

            tmp.add(&eval_0.0[j - 2]);
            tmp.add(&eval_1.0[j - 2]);
            println!("[{:?}] Tmp {:?} = {:?}", alpha_eval, j, tmp);
            if alpha[0..j-1] == alpha_eval[0..j-1] {
                assert_eq!(
                    betas[j - 2],
                    tmp,
                    "[Level {:?}] Value incorrect at {:?}",
                    j,
                    alpha_eval
                );
            } else {
                assert_eq!(FieldElm::zero(), tmp);
            }
        }

        assert_eq!(pi_0, pi_1);
    }
}
