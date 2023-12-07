use blake3::hash;
use prio::{
    flp::{types::Count, Type},
    vdaf::xof::{IntoFieldVec, Xof, XofShake128},
};
use rayon::prelude::*;
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::{dpf, prg, xor_in_place, xor_vec, HASH_SIZE};

#[derive(Clone)]
pub struct HashAlg {}

impl Hasher for HashAlg {
    type Hash = [u8; HASH_SIZE];

    fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
        hash(data).as_bytes()[0..HASH_SIZE].try_into().unwrap()
    }
}

#[derive(Clone)]
struct TreeNode<T> {
    path: Vec<bool>,
    value: T,
    key_states: Vec<dpf::EvalState>,
    key_values: Vec<T>,
}

unsafe impl<T> Send for TreeNode<T> {}
unsafe impl<T> Sync for TreeNode<T> {}

#[derive(Clone)]
pub struct KeyCollection<T> {
    server_id: i8,
    verify_key: [u8; 16],
    depth: usize,
    pub keys: Vec<(bool, dpf::DPFKey<T>)>,
    nonces: Vec<[u8; 16]>,
    all_flp_proof_shares: Vec<Vec<T>>,
    frontier: Vec<TreeNode<T>>,
    prev_frontier: Vec<TreeNode<T>>,
    count: Count<T>,
    final_proofs: Vec<[u8; HASH_SIZE]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result<T> {
    pub path: Vec<bool>,
    pub value: T,
}

impl<T> KeyCollection<T>
where
    T: prio::field::FieldElement
        + prio::field::FftFriendlyFieldElement
        + std::fmt::Debug
        + std::cmp::PartialOrd
        + Send
        + Sync
        + prg::FromRng
        + 'static,
    u64: From<T>,
{
    pub fn new(
        server_id: i8,
        _seed: &prg::PrgSeed,
        depth: usize,
        verify_key: [u8; 16],
    ) -> KeyCollection<T> {
        KeyCollection::<T> {
            server_id,
            verify_key,
            depth,
            keys: vec![],
            nonces: vec![],
            all_flp_proof_shares: vec![],
            frontier: vec![],
            prev_frontier: vec![],
            count: Count::new(),
            final_proofs: vec![],
        }
    }

    pub fn add_key(&mut self, key: dpf::DPFKey<T>) {
        self.keys.push((true, key));
    }

    pub fn add_flp_proof_share(&mut self, flp_proof_share: Vec<T>, nonce: [u8; 16]) {
        self.all_flp_proof_shares.push(flp_proof_share);
        self.nonces.push(nonce);
    }

    pub fn tree_init(&mut self) {
        let mut root = TreeNode::<T> {
            path: vec![],
            value: T::zero(),
            key_states: vec![],
            key_values: vec![],
        };

        for k in &self.keys {
            root.key_states.push(k.1.eval_init());
            root.key_values.push(T::zero());
        }

        self.frontier.clear();
        self.frontier.push(root);
    }

    fn make_tree_node(&self, parent: &TreeNode<T>, dir: bool) -> TreeNode<T> {
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir { '1' } else { '0' });

        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<T>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| key.1.eval_bit(&parent.key_states[i], dir, &bit_str))
            .unzip();

        let mut child_val = T::zero();
        key_values
            .iter()
            .zip(&self.keys)
            .filter(|&(_, key)| key.0)
            .for_each(|(&v, _)| child_val.add_assign(v));

        let mut child = TreeNode::<T> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
        };

        child.path.push(dir);

        child
    }

    pub fn run_flp_queries(&mut self, start: usize, end: usize) -> Vec<Vec<T>> {
        let level = self.frontier[0].path.len();
        assert_eq!(level, 0);

        // Should only have the root node.
        debug_assert_eq!(self.frontier.len(), 1);

        let node_left = self.make_tree_node(&self.frontier[0], false);
        let node_right = self.make_tree_node(&self.frontier[0], true);
        debug_assert_eq!(
            self.frontier[0].key_values.len(),
            node_left.key_values.len()
        );

        // Compute the FLP Proof Shares for all the clients.
        self.frontier[0]
            .key_values
            .par_iter()
            .enumerate()
            .filter(|(client_index, _)| *client_index >= start && *client_index < end)
            .map(|(client_index, _)| {
                let y_p0 = node_left.key_values[client_index];
                let y_p1 = node_right.key_values[client_index];

                let mut beta_share = T::zero();
                beta_share.add_assign(y_p0);
                beta_share.add_assign(y_p1);

                let flp_proof_share = &self.all_flp_proof_shares[client_index];

                let query_rand_xof =
                    XofShake128::init(&self.verify_key, &self.nonces[client_index]);
                let query_rand: Vec<T> = query_rand_xof
                    .clone()
                    .into_seed_stream()
                    .into_field_vec(self.count.query_rand_len());

                // Compute the flp_verifier_share.
                self.count
                    .query(&[beta_share], flp_proof_share, &query_rand, &[], 2)
                    .unwrap()
            })
            .collect::<Vec<_>>()
    }

    pub fn tree_crawl(
        &mut self,
        mut split_by: usize,
        malicious: &Vec<usize>,
        is_last: bool,
    ) -> (Vec<T>, Vec<Vec<u8>>, Vec<usize>) {
        if !malicious.is_empty() {
            println!("Malicious is not empty!!");

            if is_last {
                for &malicious_client in malicious {
                    self.keys[malicious_client].0 = false;
                    println!("Removing malicious client {}.", malicious_client);
                }
            }
            self.frontier = self.prev_frontier.clone();
        }

        let level = self.frontier[0].path.len();
        debug_assert!(level < self.depth);

        let next_frontier = self
            .frontier
            .par_iter()
            .flat_map(|node| {
                assert!(node.path.len() <= self.depth);
                let child_0 = self.make_tree_node(node, false);
                let child_1 = self.make_tree_node(node, true);

                vec![child_0, child_1]
            })
            .collect::<Vec<TreeNode<T>>>();

        // These are summed evaluations y for different prefixes.
        let cnt_values = next_frontier
            .par_iter()
            .map(|node| node.value)
            .collect::<Vec<T>>();

        // For all prefixes, compute the checks for each client.
        let all_y_checks = self
            .frontier
            .par_iter()
            .enumerate()
            .map(|(prefix_index, node)| {
                let node_left = &next_frontier[2 * prefix_index];
                let node_right = &next_frontier[2 * prefix_index + 1];

                debug_assert_eq!(node.key_values.len(), node_left.key_values.len());
                debug_assert_eq!(node.key_values.len(), node_right.key_values.len());

                // For one prefix for all the clients.
                node.key_values
                    .par_iter()
                    .enumerate()
                    .map(|(client_index, &y_p)| {
                        let y_p0 = node_left.key_values[client_index];
                        let y_p1 = node_right.key_values[client_index];

                        let mut value_check = T::zero();
                        if level == 0 {
                            // (1 - server_id) + (-1)^server_id * (- y^{p||0} - y^{p||1})
                            if self.server_id == 0 {
                                value_check.add_assign(T::one());
                                value_check.sub_assign(y_p0);
                                value_check.sub_assign(y_p1);
                            } else {
                                value_check.add_assign(y_p0);
                                value_check.add_assign(y_p1);
                            }
                        } else {
                            // (-1)^server_id * (y^{p} - y^{p||0} - y^{p||1})
                            if self.server_id == 0 {
                                value_check.add_assign(y_p);
                                value_check.sub_assign(y_p0);
                                value_check.sub_assign(y_p1);
                            } else {
                                value_check.add_assign(y_p0);
                                value_check.add_assign(y_p1);
                                value_check.sub_assign(y_p);
                            }
                        }

                        value_check
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let combined_hashes = self
            .keys
            .par_iter()
            .enumerate()
            .filter(|(_, key)| key.0)
            .map(|(client_index, _)| {
                // Combine the multiple proofs that each client has for each prefix into a single
                // proof for each client.
                let mut proof = [0u8; HASH_SIZE];
                next_frontier.iter().for_each(|node| {
                    xor_in_place(&mut proof, &node.key_states[client_index].proof);
                });

                // Combine all the checks that each client has for each prefix into a single check
                // for each client.
                let mut check = [0u8; 8];
                all_y_checks.iter().for_each(|checks_for_prefix| {
                    xor_in_place(&mut check, &checks_for_prefix[client_index].get_encoded());
                });

                xor_vec(
                    &proof,
                    hash(&check).as_bytes()[0..HASH_SIZE].try_into().unwrap(),
                )
                .try_into()
                .unwrap()
            })
            .collect::<Vec<[u8; HASH_SIZE]>>();
        debug_assert_eq!(
            self.keys.iter().filter(|&key| key.0).count(),
            combined_hashes.len()
        );

        // Compute the Merkle tree based on y_checks for each client and the proofs.
        // If we are at the last level, we only need to compute the root as the malicious clients
        // have already been removed.
        if is_last {
            split_by = 1
        };
        let num_leaves = 1 << (combined_hashes.len() as f32).log2().ceil() as usize;
        let chunk_sz = num_leaves / split_by;
        let chunks_list = combined_hashes.chunks(chunk_sz).collect::<Vec<_>>();

        let mut mtree_roots = vec![];
        let mut mtree_indices = vec![];
        if split_by == 1 {
            let mt = MerkleTree::<HashAlg>::from_leaves(chunks_list[0]);
            let root = mt.root().unwrap();
            mtree_roots.push(root.to_vec());
            mtree_indices.push(0);
        } else {
            for &i in malicious {
                let mt_left = MerkleTree::<HashAlg>::from_leaves(chunks_list[i * 2]);
                let root_left = mt_left.root().unwrap();
                mtree_roots.push(root_left.to_vec());
                mtree_indices.push(i * 2);

                if i * 2 + 1 >= chunks_list.len() {
                    continue;
                }
                let mt_right = MerkleTree::<HashAlg>::from_leaves(chunks_list[i * 2 + 1]);
                let root_right = mt_right.root().unwrap();
                mtree_roots.push(root_right.to_vec());
                mtree_indices.push(i * 2 + 1);
            }
        }

        self.prev_frontier = self.frontier.clone();
        self.frontier = next_frontier;

        (cnt_values, mtree_roots, mtree_indices)
    }

    pub fn tree_crawl_last(&mut self) -> Vec<T> {
        let next_frontier = self
            .frontier
            .par_iter()
            .flat_map(|node| {
                // assert!(node.path.len() <= self.depth);
                let child_0 = self.make_tree_node(node, false);
                let child_1 = self.make_tree_node(node, true);

                vec![child_0, child_1]
            })
            .collect::<Vec<TreeNode<T>>>();

        self.final_proofs = self
            .keys
            .par_iter()
            .enumerate()
            .filter(|(_, key)| key.0) // If the client is honest.
            .map(|(proof_index, _)| {
                let mut proof = [0u8; HASH_SIZE];
                next_frontier.iter().for_each(|node| {
                    xor_in_place(&mut proof, &node.key_states[proof_index].proof);
                });

                proof
            })
            .collect::<Vec<_>>();
        self.frontier = next_frontier;

        // These are summed evaluations y for different prefixes.
        self.frontier
            .par_iter()
            .map(|node| node.value)
            .collect::<Vec<T>>()
    }

    pub fn get_proofs(&self, start: usize, end: usize) -> Vec<[u8; HASH_SIZE]> {
        let mut proofs = Vec::new();
        if end > start && end <= self.final_proofs.len() {
            proofs.extend_from_slice(&self.final_proofs[start..end]);
        }

        proofs
    }

    pub fn tree_prune(&mut self, alive_vals: &[bool]) {
        assert_eq!(alive_vals.len(), self.frontier.len());

        // Remove from back to front to preserve indices
        for i in (0..alive_vals.len()).rev() {
            if !alive_vals[i] {
                self.frontier.remove(i);
            }
        }
    }

    pub fn apply_flp_results(&mut self, keep: &[bool]) {
        assert_eq!(keep.len(), self.keys.len());

        // Remove keys for which the FLP did not verify successfully.
        for (i, alive) in keep.iter().enumerate() {
            if !alive {
                self.keys[i].0 = false;
                println!("Removing malicious client {}.", i);
            }
        }
    }

    pub fn keep_values(threshold: u64, cnt_values_0: &[T], cnt_values_1: &[T]) -> Vec<bool> {
        cnt_values_0
            .par_iter()
            .zip(cnt_values_1.par_iter())
            .map(|(&value_0, &value_1)| {
                let v = value_0 + value_1;

                u64::from(v) >= threshold
            })
            .collect::<Vec<_>>()
    }

    pub fn final_shares(&self) -> Vec<Result<T>> {
        self.frontier
            .par_iter()
            .map(|n| Result::<T> {
                path: n.path.clone(),
                value: n.value,
            })
            .collect::<Vec<_>>()
    }

    // Reconstruct counters based on shares
    pub fn reconstruct_shares(results_0: &[T], results_1: &[T]) -> Vec<T> {
        assert_eq!(results_0.len(), results_1.len());

        results_0
            .par_iter()
            .zip_eq(results_1)
            .map(|(&v1, &v2)| {
                let mut v = T::zero();
                v.add_assign(v1);
                v.add_assign(v2);
                v
            })
            .collect()
    }

    // Reconstruct counters based on shares
    pub fn final_values(results_0: &[Result<T>], results_1: &[Result<T>]) -> Vec<Result<T>> {
        assert_eq!(results_0.len(), results_1.len());

        results_0
            .par_iter()
            .zip(results_1.par_iter())
            .map(|(r0, r1)| {
                assert_eq!(r0.path, r1.path);

                let mut v = T::zero();
                v.add_assign(r0.value);
                v.add_assign(r1.value);

                Result {
                    path: r0.path.clone(),
                    value: v,
                }
            })
            .filter(|result| result.value > T::zero())
            .collect::<Vec<_>>()
    }
}
