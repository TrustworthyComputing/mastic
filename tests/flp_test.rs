use prio::{
    field::{random_vector, Field64},
    flp::{
        types::{Count, Sum},
        FlpError, Type,
    },
};
use rand::Rng;
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

#[test]
fn flp_bool_beta() {
    let count = Count::new();

    assert!(run_flp_with_input(&count, &vec![], 0).unwrap());
    assert!(run_flp_with_input(&count, &vec![], 1).unwrap());

    // The following two should panic with an FLP error as the input is not in range.
    assert!(run_flp_with_input(&count, &vec![], 2).is_err());
    assert!(run_flp_with_input(&count, &vec![], 100).is_err());
}

#[test]
fn flp_random_beta_in_range() {
    let bits = 2; // [0, 2^2)
    let sum = Sum::<Field64>::new(bits).unwrap();

    // TODO(@jimouris): Derive joint randomness correctly.
    let joint_rand = vec![Field64::from(0); sum.joint_rand_len()];

    assert!(run_flp_with_input(&sum, &joint_rand, 0).unwrap());
    assert!(run_flp_with_input(&sum, &joint_rand, 1).unwrap());
    assert!(run_flp_with_input(&sum, &joint_rand, 2).unwrap());
    assert!(run_flp_with_input(&sum, &joint_rand, 3).unwrap());

    // The following two should panic with an FLP error as the input is not in range.
    assert!(run_flp_with_input(&sum, &joint_rand, 4).is_err());
    assert!(run_flp_with_input(&sum, &joint_rand, 100).is_err());
}

fn run_flp_with_input<T>(sum: &T, joint_rand: &[Field64], input: u64) -> Result<bool, FlpError>
where
    T: prio::flp::Type<Field = Field64, Measurement = u64>,
{
    // 1. The prover chooses a measurement and secret shares the input.
    let input: Vec<Field64> = sum.encode_measurement(&input)?;
    let input_0 = input
        .iter()
        .map(|_| Field64::from(rand::thread_rng().gen::<u64>()))
        .collect::<Vec<_>>();
    let input_1 = input
        .par_iter()
        .zip(input_0.par_iter())
        .map(|(in_0, in_1)| in_0 - in_1)
        .collect::<Vec<_>>();

    // 2. The prover generates prove_rand and query_rand (should be unique per proof). The prover
    //    uses prover_rand to generate the proof. Finally, the prover secret shares the proof.
    let prove_rand = random_vector(sum.prove_rand_len()).unwrap();
    let query_rand = random_vector(sum.query_rand_len()).unwrap();

    let proof = sum.prove(&input, &prove_rand, &joint_rand).unwrap();
    let proof_0 = proof
        .iter()
        .map(|_| Field64::from(rand::thread_rng().gen::<u64>()))
        .collect::<Vec<_>>();
    let proof_1 = proof
        .par_iter()
        .zip(proof_0.par_iter())
        .map(|(p_0, p_1)| p_0 - p_1)
        .collect::<Vec<_>>();

    // 3. The verifiers are provided with query_rand (should be the same between the verifiers).
    //    Each verifier queries the input and proof shares and receives a verifier_share.
    let verifier_0 = sum
        .query(&input_0, &proof_0, &query_rand, &joint_rand, 2)
        .unwrap();
    let verifier_1 = sum
        .query(&input_1, &proof_1, &query_rand, &joint_rand, 2)
        .unwrap();

    // 4. The verifiers combined their verifier_shares to check the proof.
    let verifier = verifier_0
        .par_iter()
        .zip(verifier_1.par_iter())
        .map(|(v1, v2)| v1 + v2)
        .collect::<Vec<_>>();

    sum.decide(&verifier)
}
