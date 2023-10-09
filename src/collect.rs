use crate::dpf;
use crate::prg;
use crate::{xor_in_place, xor_vec};

use rayon::prelude::*;
use rs_merkle::Hasher;
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
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
pub struct KeyCollection<T, U> {
    server_id: i8,
    depth: usize,
    pub keys: Vec<(bool, dpf::DPFKey<T, U>)>,
    honest_clients: Vec<bool>,
    frontier: Vec<TreeNode<T>>,
    prev_frontier: Vec<TreeNode<T>>,
    frontier_last: Vec<TreeNode<U>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result<T> {
    pub path: Vec<bool>,
    pub value: T,
}

impl<T, U> KeyCollection<T, U>
where
    T: crate::Share
        + std::fmt::Debug
        + std::cmp::PartialOrd
        + std::convert::From<u32>
        + Send
        + Sync
        + 'static,
    U: crate::Share
        + std::fmt::Debug
        + std::cmp::PartialOrd
        + std::convert::From<u32>
        + Send
        + Sync,
{
    pub fn new(server_id: i8, _seed: &prg::PrgSeed, depth: usize) -> KeyCollection<T, U> {
        KeyCollection::<T, U> {
            server_id,
            depth,
            keys: vec![],
            honest_clients: vec![],
            frontier: vec![],
            prev_frontier: vec![],
            frontier_last: vec![],
        }
    }

    pub fn add_key(&mut self, key: dpf::DPFKey<T, U>) {
        self.keys.push((true, key));
        self.honest_clients.push(true);
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
        self.frontier_last.clear();
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
        for ((i, v), &honest_client) in key_values.iter().enumerate().zip(&self.honest_clients) {
            // Add in only live values
            if self.keys[i].0 && honest_client {
                child_val.add_lazy(v);
            }
        }
        child_val.reduce();

        let mut child = TreeNode::<T> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
        };

        child.path.push(dir);

        child
    }

    fn make_tree_node_last(&self, parent: &TreeNode<T>, dir: bool) -> TreeNode<U> {
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir { '1' } else { '0' });

        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<U>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| key.1.eval_bit_last(&parent.key_states[i], dir, &bit_str))
            .unzip();

        let mut child_val = U::zero();
        for ((i, v), &honest_client) in key_values.iter().enumerate().zip(&self.honest_clients) {
            // Add in only live values
            if self.keys[i].0 && honest_client {
                child_val.add_lazy(v);
            }
        }
        child_val.reduce();

        let mut child = TreeNode::<U> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
        };

        child.path.push(dir);

        child
    }

    pub fn tree_crawl(
        &mut self,
        mut split_by: usize,
        malicious: &Vec<usize>,
        is_last: bool,
    ) -> (Vec<T>, Vec<Vec<u8>>, Vec<usize>) {
        if !malicious.is_empty() {
            if is_last {
                for &malicious_client in malicious {
                    self.honest_clients[malicious_client] = false;
                    println!("removing malicious client {}", malicious_client);
                }
            }
            self.frontier = self.prev_frontier.clone();
        }

        let level = self.frontier[0].path.len();
        debug_assert!(level < self.depth);
        // println!("Level {}", level);

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
            .map(|node| node.value.clone())
            .collect::<Vec<T>>();

        // Combine the multiple proofs for each client into a single proof for each client.
        let num_clients = next_frontier.get(0).map_or(0, |node| node.key_states.len());
        let mut key_proofs: Vec<_> = vec![[0u8; 32]; num_clients];
        key_proofs
            .par_iter_mut()
            .enumerate()
            .zip_eq(&self.honest_clients)
            .for_each(|((proof_index, proof), &honest_client)| {
                if honest_client {
                    for node in next_frontier.iter() {
                        xor_in_place(proof, &node.key_states[proof_index].proof);
                    }
                }
            });

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

                // For one prefix for all the clients
                node.key_values
                    .par_iter()
                    .enumerate()
                    .map(|(client_index, y_p)| {
                        let y_p0 = &node_left.key_values[client_index];
                        let y_p1 = &node_right.key_values[client_index];

                        let mut value_check = T::zero();

                        if level == 0 {
                            // TODO(@jimouris): Replace level 0 with FLP
                            // (1 - server_id) + (-1)^server_id * (- y^{p||0} - y^{p||1})
                            if self.server_id == 0 {
                                value_check.add(&T::one());
                                value_check.sub(y_p0);
                                value_check.sub(y_p1);
                            } else {
                                value_check.add(y_p0);
                                value_check.add(y_p1);
                            }
                        } else {
                            // (-1)^server_id * (y^{p} - y^{p||0} - y^{p||1})
                            if self.server_id == 0 {
                                value_check.add(y_p);
                                value_check.sub(y_p0);
                                value_check.sub(y_p1);
                            } else {
                                value_check.add(y_p0);
                                value_check.add(y_p1);
                                value_check.sub(y_p);
                            }
                        }

                        value_check
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Now, we combine all the checks for each client into a single check for each client.
        let key_checks = all_y_checks[0] // parallelize the clients
            .par_iter()
            .enumerate()
            .zip_eq(&self.honest_clients)
            .map(|((client_index, _), &honest_client)| {
                let mut hasher = Sha256::new();
                if honest_client {
                    all_y_checks.iter().for_each(|checks_for_prefix| {
                        hasher.update(
                            checks_for_prefix[client_index]
                                .clone()
                                .value()
                                .to_le_bytes(),
                        );
                    });
                }
                hasher.finalize().to_vec()
            })
            .collect::<Vec<_>>();

        debug_assert_eq!(key_proofs.len(), key_checks.len());

        let combined_hashes = key_proofs
            .par_iter()
            .zip(key_checks.par_iter())
            .map(|(proof, check)| xor_vec(proof, check).try_into().unwrap())
            .collect::<Vec<[u8; 32]>>();

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
            let mt = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[0]);
            let root = mt.root().unwrap();
            mtree_roots.push(root.to_vec());
            mtree_indices.push(0);
        } else {
            for &i in malicious {
                let mt_left = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[i * 2]);
                let root_left = mt_left.root().unwrap();
                mtree_roots.push(root_left.to_vec());
                mtree_indices.push(i * 2);

                if i * 2 + 1 >= chunks_list.len() {
                    continue;
                }
                let mt_right = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[i * 2 + 1]);
                let root_right = mt_right.root().unwrap();
                mtree_roots.push(root_right.to_vec());
                mtree_indices.push(i * 2 + 1);
            }
        }

        self.prev_frontier = self.frontier.clone();
        self.frontier = next_frontier;

        (cnt_values, mtree_roots, mtree_indices)
    }

    pub fn tree_crawl_last(&mut self) -> (Vec<U>, Vec<[u8; 32]>) {
        let next_frontier = self
            .frontier
            .par_iter()
            .flat_map(|node| {
                // assert!(node.path.len() <= self.depth);
                let child_0 = self.make_tree_node_last(node, false);
                let child_1 = self.make_tree_node_last(node, true);

                vec![child_0, child_1]
            })
            .collect::<Vec<TreeNode<U>>>();

        // These are summed evaluations y for different prefixes.
        let cnt_values = next_frontier
            .par_iter()
            .map(|node| node.value.clone())
            .collect::<Vec<U>>();

        let num_clients = next_frontier.get(0).map_or(0, |node| node.key_states.len());
        let mut key_proofs: Vec<_> = vec![[0u8; 32]; num_clients];
        key_proofs
            .par_iter_mut()
            .enumerate()
            .zip_eq(&self.honest_clients)
            .for_each(|((proof_index, proof), &honest_client)| {
                if honest_client {
                    for node in next_frontier.iter() {
                        xor_in_place(proof, &node.key_states[proof_index].proof);
                    }
                }
            });

        self.frontier_last = next_frontier;

        (cnt_values, key_proofs)
    }

    pub fn tree_prune(&mut self, alive_vals: &[bool], is_last: bool) {
        if is_last {
            assert_eq!(alive_vals.len(), self.frontier_last.len());
        } else {
            assert_eq!(alive_vals.len(), self.frontier.len());
        }

        // Remove from back to front to preserve indices
        for i in (0..alive_vals.len()).rev() {
            if !alive_vals[i] {
                if is_last {
                    self.frontier_last.remove(i);
                } else {
                    self.frontier.remove(i);
                }
            }
        }
    }

    pub fn keep_values(threshold: &T, cnt_values_0: &[T], cnt_values_1: &[T]) -> Vec<bool> {
        cnt_values_0
            .par_iter()
            .zip(cnt_values_1.par_iter())
            .map(|(value_0, value_1)| {
                let mut v = T::zero();
                v.add(value_0);
                v.add(value_1);

                v >= *threshold
            })
            .collect::<Vec<_>>()
    }

    pub fn keep_values_last(threshold: &U, cnt_values_0: &[U], cnt_values_1: &[U]) -> Vec<bool> {
        assert_eq!(cnt_values_0.len(), cnt_values_1.len());

        cnt_values_0
            .par_iter()
            .zip(cnt_values_1.par_iter())
            .map(|(value_0, value_1)| {
                let mut v = U::zero();
                v.add(value_0);
                v.add(value_1);

                v >= *threshold
            })
            .collect::<Vec<_>>()
    }

    pub fn final_shares(&self) -> Vec<Result<U>> {
        self.frontier_last
            .par_iter()
            .map(|n| Result::<U> {
                path: n.path.clone(),
                value: n.value.clone(),
            })
            .collect::<Vec<_>>()
    }

    // Reconstruct counters based on shares
    pub fn reconstruct_shares(results_0: &[U], results_1: &[U]) -> Vec<U> {
        assert_eq!(results_0.len(), results_1.len());

        results_0
            .par_iter()
            .zip_eq(results_1)
            .map(|(v1, v2)| {
                let mut v = U::zero();
                v.add(v1);
                v.add(v2);
                v
            })
            .collect()
    }

    // Reconstruct counters based on shares
    pub fn final_values(results_0: &[Result<U>], results_1: &[Result<U>]) -> Vec<Result<U>> {
        assert_eq!(results_0.len(), results_1.len());

        results_0
            .par_iter()
            .zip(results_1.par_iter())
            .map(|(r0, r1)| {
                assert_eq!(r0.path, r1.path);

                let mut v = U::zero();
                v.add(&r0.value);
                v.add(&r1.value);

                Result {
                    path: r0.path.clone(),
                    value: v,
                }
            })
            .filter(|result| result.value > U::zero())
            .collect::<Vec<_>>()
    }
}
