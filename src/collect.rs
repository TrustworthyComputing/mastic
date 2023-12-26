use blake3::hash;
use prio::{
    codec::Encode,
    field::Field128,
    vdaf::xof::{IntoFieldVec, Xof, XofShake128},
};
use rand_core::RngCore;
use rayon::prelude::*;
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::{prg, vec_add, vec_sub, vidpf, xor_in_place, xor_vec, MasticHistogram, HASH_SIZE};

#[derive(Clone)]
pub struct HashAlg {}

impl Hasher for HashAlg {
    type Hash = [u8; HASH_SIZE];

    fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
        hash(data).as_bytes()[0..HASH_SIZE].try_into().unwrap()
    }
}

#[derive(Clone)]
struct TreeNode<Field128> {
    /// The binary path for this node of the tree.
    path: Vec<bool>,

    /// The value of the node.
    value: Vec<Field128>,

    /// The state of each client.
    key_states: Vec<vidpf::EvalState>,

    /// The value of each client.
    key_values: Vec<Vec<Field128>>,
}

unsafe impl<Field128> Send for TreeNode<Field128> {}
unsafe impl<Field128> Sync for TreeNode<Field128> {}

#[derive(Clone)]
pub struct KeyCollection {
    /// The type of the FLP.
    mastic: MasticHistogram,

    /// The ID of the server (0 or 1).
    server_id: i8,

    ///
    verify_key: [u8; 16],

    /// The depth of the tree.
    depth: usize,

    /// The keys of the clients. The first element of the tuple is whether the client is honest or
    /// not.
    pub keys: Vec<(bool, vidpf::VidpfKey)>,

    /// The nonces of the clients.
    nonces: Vec<[u8; 16]>,

    /// The joint randomness parts of the clients.
    jr_parts: Vec<[[u8; 16]; 2]>,

    // The FLP proof shares of the clients.
    all_flp_proof_shares: Vec<Vec<Field128>>,

    /// The current evaluations of the tree.
    frontier: Vec<TreeNode<Field128>>,

    /// The previous evaluations of the tree. This is used when we detect malicious activity.
    prev_frontier: Vec<TreeNode<Field128>>,

    /// The final VIDPF proofs of the clients.
    final_proofs: Vec<[u8; HASH_SIZE]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    /// The heavy-hitter path.
    pub path: Vec<bool>,

    /// The heavy-hitter value.
    pub value: Vec<Field128>,
}

impl KeyCollection {
    pub fn new(
        mastic: MasticHistogram,
        server_id: i8,
        _seed: &prg::PrgSeed,
        depth: usize,
        verify_key: [u8; 16],
    ) -> KeyCollection {
        KeyCollection {
            mastic,
            server_id,
            verify_key,
            depth,
            keys: vec![],
            nonces: vec![],
            jr_parts: vec![],
            all_flp_proof_shares: vec![],
            frontier: vec![],
            prev_frontier: vec![],
            final_proofs: vec![],
        }
    }

    pub fn add_key(&mut self, key: vidpf::VidpfKey) {
        self.keys.push((true, key));
    }

    pub fn add_flp_proof_share(
        &mut self,
        flp_proof_share: Vec<Field128>,
        nonce: [u8; 16],
        jr_parts: [[u8; 16]; 2],
    ) {
        self.all_flp_proof_shares.push(flp_proof_share);
        self.nonces.push(nonce);
        self.jr_parts.push(jr_parts);
    }

    pub fn tree_init(&mut self) {
        let mut root = TreeNode::<Field128> {
            path: vec![],
            value: vec![Field128::from(0)],
            key_states: vec![],
            key_values: vec![],
        };

        for k in &self.keys {
            root.key_states.push(k.1.eval_init());
            root.key_values.push(vec![Field128::from(0)]);
        }

        self.frontier.clear();
        self.frontier.push(root);
    }

    fn make_tree_node(&self, parent: &TreeNode<Field128>, dir: bool) -> TreeNode<Field128> {
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir { '1' } else { '0' });

        let (key_states, key_values): (Vec<vidpf::EvalState>, Vec<Vec<Field128>>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                key.1.eval_bit(
                    &parent.key_states[i],
                    dir,
                    &bit_str,
                    self.mastic.input_len(),
                )
            })
            .unzip();

        let mut child_val = vec![Field128::from(0); &self.mastic.input_len() + 1];
        key_values
            .iter()
            .zip(&self.keys)
            .filter(|&(_, key)| key.0)
            .for_each(|(v, _)| vec_add(&mut child_val, v));

        let mut child = TreeNode::<Field128> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
        };

        child.path.push(dir);

        child
    }

    pub fn run_flp_queries(&mut self, start: usize, end: usize) -> Vec<Vec<Field128>> {
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
                let y_p0 = &node_left.key_values[client_index];
                let y_p1 = &node_right.key_values[client_index];

                let mut beta_share = vec![Field128::from(0); self.mastic.input_len()];
                vec_add(&mut beta_share, y_p0);
                vec_add(&mut beta_share, y_p1);

                let flp_proof_share = &self.all_flp_proof_shares[client_index];

                let query_rand_xof =
                    XofShake128::init(&self.verify_key, &self.nonces[client_index]);
                let query_rand: Vec<Field128> = query_rand_xof
                    .clone()
                    .into_seed_stream()
                    .into_field_vec(self.mastic.query_rand_len());

                let mut jr_parts = self.jr_parts[client_index];
                if self.server_id == 0 {
                    let mut jr_part_xof = XofShake128::init(
                        &self.keys[client_index].1.get_root_seed().key,
                        &[0u8; 16],
                    );
                    jr_part_xof.update(&[0]); // Aggregator ID
                    jr_part_xof.update(&self.nonces[client_index]);
                    jr_part_xof.into_seed_stream().fill_bytes(&mut jr_parts[0]);
                } else {
                    let mut jr_part_xof = XofShake128::init(
                        &self.keys[client_index].1.get_root_seed().key,
                        &[0u8; 16],
                    );
                    jr_part_xof.update(&[1]); // Aggregator ID
                    jr_part_xof.update(&self.nonces[client_index]);
                    jr_part_xof.into_seed_stream().fill_bytes(&mut jr_parts[1]);
                }

                let joint_rand_xof = XofShake128::init(&jr_parts[0], &jr_parts[1]);
                let joint_rand: Vec<Field128> = joint_rand_xof
                    .into_seed_stream()
                    .into_field_vec(self.mastic.joint_rand_len());

                // Compute the flp_verifier_share.
                self.mastic
                    .query(&beta_share, flp_proof_share, &query_rand, &joint_rand, 2)
                    .unwrap()
            })
            .collect::<Vec<_>>()
    }

    pub fn tree_crawl(
        &mut self,
        mut split_by: usize,
        malicious: &Vec<usize>,
        is_last: bool,
    ) -> (Vec<Vec<Field128>>, Vec<Vec<u8>>, Vec<usize>) {
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
            .collect::<Vec<TreeNode<Field128>>>();

        // These are summed evaluations y for different prefixes.
        let cnt_values = next_frontier
            .par_iter()
            .map(|node| node.value.clone())
            .collect::<Vec<Vec<Field128>>>();

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
                    .map(|(client_index, y_p)| {
                        let y_p0 = &node_left.key_values[client_index];
                        let y_p1 = &node_right.key_values[client_index];

                        let mut value_check = vec![Field128::from(0); &self.mastic.input_len() + 1];
                        if level == 0 {
                            // (1 - server_id) + (-1)^server_id * (- y^{p||0} - y^{p||1})
                            if self.server_id == 0 {
                                vec_add(
                                    &mut value_check,
                                    &vec![Field128::from(1); &self.mastic.input_len() + 1],
                                );
                                vec_sub(&mut value_check, y_p0);
                                vec_sub(&mut value_check, y_p1);
                            } else {
                                vec_add(&mut value_check, y_p0);
                                vec_add(&mut value_check, y_p1);
                            }
                        } else {
                            // (-1)^server_id * (y^{p} - y^{p||0} - y^{p||1})
                            if self.server_id == 0 {
                                vec_add(&mut value_check, y_p);
                                vec_sub(&mut value_check, y_p0);
                                vec_sub(&mut value_check, y_p1);
                            } else {
                                vec_add(&mut value_check, y_p0);
                                vec_add(&mut value_check, y_p1);
                                vec_sub(&mut value_check, y_p);
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
                    if level == 0 {
                        xor_in_place(
                            &mut check,
                            &checks_for_prefix[client_index][self.mastic.input_len()].get_encoded(),
                        );
                    } else {
                        for i in 0..self.mastic.input_len() {
                            xor_in_place(
                                &mut check,
                                &checks_for_prefix[client_index][i].get_encoded(),
                            );
                        }
                    }
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

    pub fn tree_crawl_last(&mut self) -> Vec<Vec<Field128>> {
        let next_frontier = self
            .frontier
            .par_iter()
            .flat_map(|node| {
                // assert!(node.path.len() <= self.depth);
                let child_0 = self.make_tree_node(node, false);
                let child_1 = self.make_tree_node(node, true);

                vec![child_0, child_1]
            })
            .collect::<Vec<TreeNode<Field128>>>();

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
            .map(|node| node.value.clone())
            .collect::<Vec<Vec<Field128>>>()
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

    /// Remove the malicious clients (i.e., the clients whose the FLP was not successful) from the
    /// key collection.
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

    /// Keep only heavy-hitter values. Note that we perform the pruning based on the last element
    /// (i.e., the counter) as the previous elements are parts of \beta.
    pub fn keep_values(
        input_len: usize,
        threshold: u64,
        cnt_values_0: &[Vec<Field128>],
        cnt_values_1: &[Vec<Field128>],
    ) -> Vec<bool> {
        cnt_values_0
            .par_iter()
            .zip(cnt_values_1.par_iter())
            .map(|(value_0, value_1)| {
                let v = value_0[input_len] + value_1[input_len];

                u128::from(v) as u64 >= threshold
            })
            .collect::<Vec<_>>()
    }

    pub fn final_shares(&self) -> Vec<Result> {
        self.frontier
            .par_iter()
            .map(|n| Result {
                path: n.path.clone(),
                value: n.value.clone(),
            })
            .collect::<Vec<_>>()
    }

    // Reconstruct counters based on shares
    pub fn final_values(
        input_len: usize,
        results_0: &[Result],
        results_1: &[Result],
    ) -> Vec<Result> {
        assert_eq!(results_0.len(), results_1.len());

        results_0
            .par_iter()
            .zip(results_1.par_iter())
            .map(|(r0, r1)| {
                assert_eq!(r0.path, r1.path);

                let mut v = vec![Field128::from(0); input_len + 1];
                vec_add(&mut v, &r0.value);
                vec_add(&mut v, &r1.value);

                Result {
                    path: r0.path.clone(),
                    value: v,
                }
            })
            .filter(|result| result.value[input_len] > Field128::from(0))
            .collect::<Vec<_>>()
    }
}
