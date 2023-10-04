use crate::dpf;
use crate::prg;
use crate::{xor_three_vecs, xor_vec};

use bitvec::prelude::*;
use rand::Rng;
use rayon::prelude::*;
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use rs_merkle::Hasher;
use sha2::digest::FixedOutput;

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
    hashes: Vec<Vec<u8>>,
    indices: Vec<usize>,
}

unsafe impl<T> Send for TreeNode<T> {}
unsafe impl<T> Sync for TreeNode<T> {}

#[derive(Clone)]
pub struct KeyCollection<T, U> {
    depth: usize,
    pub keys: Vec<(bool, dpf::DPFKey<T, U>)>,
    pub pis: Vec<Vec<Vec<u8>>>,
    honest_clients: Vec<bool>,
    frontier: Vec<TreeNode<T>>,
    prev_frontier: Vec<TreeNode<T>>,
    frontier_last: Vec<TreeNode<U>>,
    frontier_intermediate: Vec<(TreeNode<U>, TreeNode<U>)>,
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
    pub fn new(_seed: &prg::PrgSeed, depth: usize) -> KeyCollection<T, U> {
        KeyCollection::<T, U> {
            depth,
            keys: vec![],
            pis: vec![],
            honest_clients: vec![],
            frontier: vec![],
            prev_frontier: vec![],
            frontier_last: vec![],
            frontier_intermediate: vec![],
        }
    }

    pub fn add_key(&mut self, key: dpf::DPFKey<T, U>) {
        self.pis.push(key.cs.clone());
        self.keys.push((true, key));
        self.honest_clients.push(true);
    }

    pub fn tree_init(&mut self) {
        let mut root = TreeNode::<T> {
            path: vec![],
            value: T::zero(),
            key_states: vec![],
            key_values: vec![],
            hashes: vec![],
            indices: vec![],
        };

        for k in &self.keys {
            root.key_states.push(k.1.eval_init());
            root.key_values.push(T::zero());
        }

        self.frontier.clear();
        self.frontier_last.clear();
        self.frontier_intermediate.clear();
        self.frontier.push(root);
    }

    fn make_tree_node(
        &self,
        parent: &TreeNode<T>,
        dir: bool,
        split_by: usize,
        malicious_indices: &Vec<usize>,
        is_last: bool,
    ) -> TreeNode<T> {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<T>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| key.1.eval_bit(&parent.key_states[i], dir))
            .unzip();
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir { '1' } else { '0' });
        let mut child_val = T::zero();
        for ((i, v), &honest_client) in key_values.iter().enumerate().zip(&self.honest_clients) {
            // Add in only live values
            if self.keys[i].0 && honest_client {
                child_val.add_lazy(v);
            }
        }
        child_val.reduce();

        let hashes: Vec<[u8; 32]> = key_states
            .par_iter()
            .zip(&self.honest_clients)
            .enumerate()
            .map(|(i, (ks, honest_client))| {
                if !honest_client {
                    [0u8; 32]
                } else {
                    let mut hasher = Sha256::new();
                    hasher.update(&bit_str);
                    hasher.update(ks.seed.key);
                    let pi_prime = hasher.finalize_reset().to_vec();
                    // Correction operation
                    let h: [u8; 32] = if !ks.bit {
                        // H(pi ^ correct(pi_prime, cs, t0)) = H(pi ^ pi_prime)
                        xor_vec(&self.pis[i][0], &pi_prime).try_into().unwrap()
                    } else {
                        // H(pi ^ correct(pi_prime, cs, t0)) = H(pi ^ pi_prime)
                        let cs_t = &self.keys[i].1.cs[0];
                        xor_three_vecs(&self.pis[i][0], &pi_prime, cs_t)
                            .try_into()
                            .unwrap()
                    };
                    hasher.update(h);
                    xor_vec(&hasher.finalize(), &self.pis[i][0])
                        .try_into()
                        .unwrap()
                }
            })
            .collect::<Vec<_>>();
        let mut roots = Vec::new();
        let mut root_indices = Vec::new();
        if bit_str.len() < 2 && !is_last {
            let tree_size = 1 << (hashes.len() as f32).log2().ceil() as usize;
            let chunk_sz = tree_size / split_by;
            let chunks_list: Vec<&[[u8; 32]]> = hashes.chunks(chunk_sz).collect();

            if split_by == 1 {
                let mt = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[0]);
                let root = mt.root().unwrap();
                roots.push(root.to_vec());
                root_indices.push(0);
            } else {
                for &i in malicious_indices {
                    let mt_left = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[i * 2]);
                    let root_left = mt_left.root().unwrap();
                    roots.push(root_left.to_vec());
                    root_indices.push(i * 2);

                    if i * 2 + 1 >= chunks_list.len() {
                        continue;
                    }
                    let mt_right =
                        MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[i * 2 + 1]);
                    let root_right = mt_right.root().unwrap();
                    roots.push(root_right.to_vec());
                    root_indices.push(i * 2 + 1);
                }
            }
        }

        let mut child = TreeNode::<T> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
            hashes: roots,
            indices: root_indices,
        };

        child.path.push(dir);

        //println!("{:?} - Child value: {:?}", child.path, child.value);
        child
    }

    fn make_tree_node_last(
        &self,
        parent: &TreeNode<T>,
        dir: bool,
    ) -> (Vec<U>, Vec<Vec<u8>>, Vec<bool>) {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<U>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| key.1.eval_bit_last(&parent.key_states[i], dir))
            .unzip();

        let bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        // bit_str.push(if dir {'1'} else {'0'});
        let depth = bit_str.len();
        let mut hashes = vec![];
        if !dir {
            hashes = key_states
                .par_iter()
                .zip(&self.honest_clients)
                .enumerate()
                .map(|(i, (ks, honest_client))| {
                    if !honest_client {
                        vec![0u8; 32]
                    } else {
                        let mut hasher = Sha256::new();
                        hasher.update(&bit_str);
                        hasher.update(parent.key_states[i].seed.key);
                        let pi_prime = hasher.finalize().to_vec();
                        // Correction operation
                        let h: Vec<u8> = if !ks.bit {
                            // H(pi ^ correct(pi_prime, cs, t0)) = H(pi ^ pi_prime)
                            xor_vec(&self.pis[i][depth - 1], &pi_prime)
                        } else {
                            // H(pi ^ correct(pi_prime, cs, t0)) = H(pi ^ pi_prime)
                            xor_three_vecs(
                                &self.pis[i][depth - 1],
                                &pi_prime,
                                &self.keys[i].1.cs[depth - 1],
                            )
                        };

                        h
                    }
                })
                .collect::<Vec<_>>();
        }
        let mut path = parent.path.clone();
        path.push(dir);

        (key_values, hashes, path)
    }

    // Adds values for "path" across multiple clients.
    fn add_leaf_values(
        &self,
        key_values: &[U],
        path: &[bool],
        verified: &Vec<bool>,
    ) -> TreeNode<U> {
        let mut child_val = U::zero();
        for ((kv, ver), honest_client) in key_values.iter().zip(verified).zip(&self.honest_clients)
        {
            // Add in only live values
            if *ver && *honest_client {
                child_val.add_lazy(kv);
            }
        }
        child_val.reduce();

        TreeNode::<U> {
            path: path.to_owned(),
            value: child_val,
            key_states: vec![],
            key_values: vec![],
            hashes: vec![],
            indices: vec![],
        }
    }

    pub fn tree_crawl(
        &mut self,
        split_by: usize,
        malicious: &Vec<usize>,
        is_last: bool,
    ) -> (Vec<T>, Vec<Vec<Vec<u8>>>, Vec<Vec<usize>>) {
        if !malicious.is_empty() {
            if is_last {
                for &malicious_client in malicious {
                    self.honest_clients[malicious_client] = false;
                    println!("removing malicious client {}", malicious_client);
                }
            }
            self.frontier = self.prev_frontier.clone();
        }
        // println!("Number of honest clients: {}", self.honest_clients.iter().filter(|&n| *n).count());

        let next_frontier = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node(node, false, split_by, malicious, is_last);
                let child1 = self.make_tree_node(node, true, split_by, malicious, is_last);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<T>>>();

        let values = next_frontier
            .par_iter()
            .map(|node| node.value.clone())
            .collect::<Vec<T>>();

        let (hashes, indices) = next_frontier
            .par_iter()
            .map(|node| (node.hashes.clone(), node.indices.clone()))
            .collect::<(Vec<_>, Vec<_>)>();

        self.prev_frontier = self.frontier.clone();
        self.frontier = next_frontier;

        (values, hashes, indices)
    }

    pub fn tree_crawl_last(&mut self) -> (Vec<Vec<u8>>, Vec<U>) {
        self.frontier_intermediate = self
            .frontier
            .par_iter()
            .map(|node| {
                // assert!(node.path.len() <= self.depth);
                let (key_values_l, hashes_l, path_l) = self.make_tree_node_last(node, false);
                let (key_values_r, hashes_r, path_r) = self.make_tree_node_last(node, true);

                (
                    TreeNode::<U> {
                        path: path_l,
                        value: U::zero(),
                        key_states: vec![],
                        key_values: key_values_l,
                        hashes: hashes_l,
                        indices: vec![],
                    },
                    TreeNode::<U> {
                        path: path_r,
                        value: U::zero(),
                        key_states: vec![],
                        key_values: key_values_r,
                        hashes: hashes_r,
                        indices: vec![],
                    },
                )
            })
            .collect::<Vec<(TreeNode<U>, TreeNode<U>)>>();

        // XOR all the leaves for each client. Note: between all the leaves of
        // each client, not between clients.
        let num_clients = self.frontier_intermediate[0].0.hashes.len();
        let mut final_hashes = vec![vec![0u8; 32]; num_clients];
        let mut tau_vals = vec![U::zero(); num_clients];
        for node in self.frontier_intermediate.iter() {
            final_hashes = final_hashes
                .par_iter_mut()
                .zip_eq(&node.0.hashes)
                .zip_eq(&self.honest_clients)
                .map(|((v1, v2), honest_client)| {
                    if *honest_client {
                        xor_vec(v1, v2)
                    } else {
                        vec![0u8; 32]
                    }
                })
                .collect();

            tau_vals = tau_vals
                .par_iter_mut()
                .zip_eq(&node.0.key_values)
                .zip_eq(&node.1.key_values)
                .zip_eq(&self.honest_clients)
                .map(|(((t, v0), v1), honest_client)| {
                    if *honest_client {
                        t.add(v0);
                        t.add(v1);
                    }
                    t.clone()
                })
                .collect();
        }

        if crate::consts::BATCH {
            let mut batched_hash = vec![0u8; 32];
            let mut batched_tau = U::zero();
            for (hash, tau) in final_hashes.iter().zip(tau_vals) {
                batched_hash = xor_vec(&batched_hash, hash);
                batched_tau.add(&tau);
                println!("batched_tau {:?}", batched_tau);
            }
            (vec![batched_hash], vec![batched_tau])
        } else {
            (final_hashes, tau_vals)
        }
    }

    pub fn get_ys(&self) -> Vec<&Vec<U>> {
        self.frontier_intermediate
            .par_iter()
            .map(|node| vec![&node.0.key_values, &node.1.key_values])
            .flatten()
            .collect::<Vec<_>>()
    }

    pub fn add_leaves_between_clients(&mut self, verified: &Vec<bool>) -> Vec<Result<U>> {
        let next_frontier = self
            .frontier_intermediate
            .par_iter()
            .map(|node| {
                let child_l = self.add_leaf_values(&node.0.key_values, &node.0.path, verified);
                let child_r = self.add_leaf_values(&node.1.key_values, &node.1.path, verified);

                vec![child_l, child_r]
            })
            .flatten()
            .collect::<Vec<TreeNode<U>>>();
        let values = next_frontier
            .par_iter()
            .map(|node| Result::<U> {
                path: node.path.clone(),
                value: node.value.clone(),
            })
            .collect::<Vec<Result<U>>>();
        self.frontier_last = next_frontier;

        values
    }

    pub fn tree_prune(&mut self, alive_vals: &[bool]) {
        assert_eq!(alive_vals.len(), self.frontier.len());

        // Remove from back to front to preserve indices
        for i in (0..alive_vals.len()).rev() {
            if !alive_vals[i] {
                self.frontier.remove(i);
            }
        }

        //println!("Size of frontier: {:?}", self.frontier.len());
    }

    pub fn tree_prune_last(&mut self, alive_vals: &[bool]) {
        assert_eq!(alive_vals.len(), self.frontier_last.len());

        // Remove from back to front to preserve indices
        for i in (0..alive_vals.len()).rev() {
            if !alive_vals[i] {
                self.frontier_last.remove(i);
            }
        }

        //println!("Size of frontier: {:?}", self.frontier.len());
    }

    pub fn keep_values(threshold: &T, vals0: &[T], vals1: &[T]) -> Vec<bool> {
        let mut keep = vec![];
        for i in 0..vals0.len() {
            let mut v = T::zero();
            v.add(&vals0[i]);
            v.add(&vals1[i]);

            // Keep nodes that are above threshold
            keep.push(v >= *threshold);
        }

        // println!("Keep: {}", keep.len());
        keep
    }

    pub fn secret_share_bool<B>(bit_array: &BitVec<B>, num_bits: usize) -> (BitVec<B>, BitVec<B>)
    where
        B: BitStore,
    {
        let mut rng = rand::thread_rng();
        let mut sh_1 = BitVec::<B>::new();
        let mut sh_2 = BitVec::<B>::new();
        for i in 0..num_bits {
            sh_1.push(rng.gen::<bool>());
            sh_2.push(sh_1[i] ^ bit_array[i]);
        }
        (sh_1, sh_2)
    }

    pub fn reconstruct_shares_bool<B>(ss0: &BitVec<B>, ss1: &BitVec<B>) -> BitVec<B>
    where
        B: BitStore,
    {
        assert_eq!(ss0.len(), ss1.len());
        let mut reconstructed = BitVec::<B>::new();
        for (b0, b1) in ss0.iter().zip(ss1.iter()) {
            reconstructed.push(*b0 ^ *b1);
        }
        reconstructed
    }

    pub fn keep_values_last(threshold: &U, vals0: &[Result<U>], vals1: &[Result<U>]) -> Vec<bool> {
        assert_eq!(vals0.len(), vals1.len());

        let mut keep = vec![];
        for i in 0..vals0.len() {
            let mut v = U::zero();
            v.add(&vals0[i].value);
            v.add(&vals1[i].value);

            // Keep nodes that are above threshold
            keep.push(v >= *threshold);
        }

        // println!("Keep-last: {}", keep.len());
        keep
    }

    pub fn final_shares(&self) -> Vec<Result<U>> {
        let mut alive = vec![];
        for n in &self.frontier_last {
            alive.push(Result::<U> {
                path: n.path.clone(),
                value: n.value.clone(),
            });
            // println!("Final {:?}, value={:?}", n.path, n.value);
        }

        alive
    }

    // Reconstruct counters based on shares
    pub fn reconstruct_shares(res0: &[U], res1: &[U]) -> Vec<U> {
        assert_eq!(res0.len(), res1.len());

        res0.par_iter()
            .zip_eq(res1)
            .map(|(v1, v2)| {
                let mut v = U::zero();
                v.add(v1);
                v.add(v2);
                v
            })
            .collect()
    }

    // Reconstruct counters based on shares
    pub fn final_values(res0: &[Result<U>], res1: &[Result<U>]) -> Vec<Result<U>> {
        assert_eq!(res0.len(), res1.len());

        let mut out = vec![];
        for i in 0..res0.len() {
            assert_eq!(res0[i].path, res1[i].path);

            let mut v = U::zero();
            v.add(&res0[i].value);
            v.add(&res1[i].value);

            if v > U::zero() {
                out.push(Result {
                    path: res0[i].path.clone(),
                    value: v,
                });
            }
        }

        out
    }
}
