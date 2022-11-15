use crate::dpf;
use crate::prg;
use crate::xor_vec;
use itertools::Itertools;
// use crate::fastfield::FE;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
// use std::any::Any;
use sha2::{Sha256, Digest};

#[derive(Clone)]
struct TreeNode<T> {
    path: Vec<bool>,
    value: T,
    key_states: Vec<dpf::EvalState>,
    key_values: Vec<T>,
    hashes: Vec<Vec<u8>>,
}

unsafe impl<T> Send for TreeNode<T> {}
unsafe impl<T> Sync for TreeNode<T> {}

#[derive(Clone)]
pub struct KeyCollection<T,U> {
    depth: usize,
    pub keys: Vec<(bool, dpf::DPFKey<T,U>)>,
    frontier: Vec<TreeNode<T>>,
    frontier_last: Vec<TreeNode<U>>,
    frontier_intermediate: Vec<(TreeNode<U>, TreeNode<U>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result<T> {
    pub path: Vec<bool>,
    pub value: T,
}

impl<T,U> KeyCollection<T,U>
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
    pub fn new(_seed: &prg::PrgSeed, depth: usize) -> KeyCollection<T,U> {
        KeyCollection::<T,U> {
            depth,
            keys: vec![],
            frontier: vec![],
            frontier_last: vec![],
            frontier_intermediate: vec![],
        }
    }

    pub fn add_key(&mut self, key: dpf::DPFKey<T,U>) {
        self.keys.push((true, key));
    }

    pub fn tree_init(&mut self) {
        let mut root = TreeNode::<T> {
            path: vec![],
            value: T::zero(),
            key_states: vec![],
            key_values: vec![],
            hashes: vec![],
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

    fn make_tree_node(&self, parent: &TreeNode<T>, dir: bool) -> TreeNode<T> {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<T>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                // let (st, out0, out1) = key.1.eval_bit(&parent.key_states[i], dir);
                let (st, out0) = key.1.eval_bit(&parent.key_states[i], dir);
                (st, out0)
            })
            .unzip();

        let mut child_val = T::zero();
        for (i, v) in key_values.iter().enumerate() {
            // Add in only live values
            if self.keys[i].0 {
                child_val.add_lazy(&v);
            }
        }
        child_val.reduce();

        let mut child = TreeNode::<T> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
            hashes: vec![],
        };

        child.path.push(dir);

        //println!("{:?} - Child value: {:?}", child.path, child.value);
        child
    }

    fn make_tree_node_last(&self, parent: &TreeNode<T>, dir: bool) -> TreeNode<U> {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<U>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                let (st, out) = key.1.eval_bit_last(&parent.key_states[i], dir);
                (st, out)
            })
            .unzip();

        let mut child_val = U::zero();
        for (i, v) in key_values.iter().enumerate() {
            // Add in only live values
            if self.keys[i].0 {
                child_val.add_lazy(&v);
            }
        }
        child_val.reduce();

        let mut child = TreeNode::<U> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
            hashes: vec![],
        };
        child.path.push(dir);

        child
    }

    fn histogram_make_tree_node_last(&self, parent: &TreeNode<T>, dir: bool) -> (Vec<U>, Vec<Vec<u8>>, Vec<bool>) {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<U>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                let (st, out) = key.1.eval_bit_last(&parent.key_states[i], dir);
                (st, out)
            })
            .unzip();

        // Construct path: parent.path | bit
        // pi_b = H(x | seed_b)
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir {'1'} else {'0'});

        let mut hashes = vec![];
        let mut hasher = Sha256::new();
        for (i, ks) in key_states.iter().enumerate() {
            // pre_image = x | seed_b
            let mut pre_image = bit_str.clone();
            pre_image.push_str(&String::from_utf8_lossy(&ks.seed.key));

            hasher.update(pre_image);
            let mut pi_prime = hasher.finalize_reset().to_vec();
    
            // Correction operation
            if ks.bit {
                pi_prime = xor_vec(&pi_prime, &self.keys[i].1.cs);
            }
            hashes.push(pi_prime);    
        }

        let mut path = parent.path.clone();
        path.push(dir);

        (key_values, hashes, path)
    }

    // Adds values for "path" accross multiple clients.
    fn histogram_add_leaf_values(&self,
        key_values: Vec<U>,
        path: Vec<bool>,
        verified: &Vec<bool>
    ) -> TreeNode<U> {
        let mut child_val = U::zero();

        for (i, v) in key_values.iter().enumerate() {
            // Add in only live values
            if verified[i] {
                child_val.add_lazy(&v);
            }
        }
        child_val.reduce();

        let child = TreeNode::<U> {
            path: path.clone(),
            value: child_val,
            key_states: vec![],
            key_values: vec![],
            hashes: vec![],
        };

        child
    }

    pub fn tree_crawl(&mut self) -> Vec<T> {
        let next_frontier = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node(node, false);
                let child1 = self.make_tree_node(node, true);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<T>>>();

        let values = next_frontier
            .iter()
            .map(|node| node.value.clone())
            .collect::<Vec<T>>();

        self.frontier = next_frontier;
        values
    }

    pub fn histogram_tree_crawl(&mut self) {
        self.frontier = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node(node, false);
                let child1 = self.make_tree_node(node, true);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<T>>>();
    }

    pub fn tree_crawl_last(&mut self) -> Vec<U> {
        let next_frontier = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node_last(node, false);
                let child1 = self.make_tree_node_last(node, true);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<U>>>();

        let values = next_frontier
            .iter()
            .map(|node| node.value.clone())
            .collect::<Vec<U>>();
            
        self.frontier_last = next_frontier;
        values
    }

    pub fn histogram_tree_crawl_last(&mut self) -> (Vec<Vec<u8>>, Vec<U>) {
        self.frontier_intermediate = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let (key_values_l, hashes_l, path_l) = self.
                    histogram_make_tree_node_last(node, false);
                let (key_values_r, hashes_r, path_r) = self.
                    histogram_make_tree_node_last(node, true);

                (TreeNode::<U> {
                    path: path_l,
                    value: U::zero(),
                    key_states: vec![],
                    key_values: key_values_l,
                    hashes: hashes_l,
                },
                TreeNode::<U> {
                    path: path_r,
                    value: U::zero(),
                    key_states: vec![],
                    key_values: key_values_r,
                    hashes: hashes_r,
                })
            })
            .collect::<Vec<(TreeNode<U>, TreeNode<U>)>>();

        // XOR all the leaves for each client. Note: between all the leaves of 
        // each client, not between clients.
        let mut final_hashes = vec![vec![0u8; 32]; self.frontier_intermediate[0].0.hashes.len()];
        let mut tau_vals = vec![U::zero(); self.frontier_intermediate[0].0.key_values.len()];
        for node in self.frontier_intermediate.iter() {
            final_hashes = final_hashes
                .iter_mut()
                .zip_eq(node.0.hashes.clone())
                .zip_eq(node.1.hashes.clone())
                .map(|((v1, v2), v3)| {
                    let t = xor_vec(&v1, &v2);
                    xor_vec(&t, &v3)
                })
                .collect();

            tau_vals = tau_vals
                .iter_mut()
                .zip_eq(node.0.key_values.clone())
                .zip_eq(node.1.key_values.clone())
                .map(|((t, v0), v1)| {
                    t.add(&v0);
                    t.add(&v1);
                    t.clone()
                })
                .collect();
        }

        (final_hashes, tau_vals)
    }

    pub fn histogram_get_ys(&self) -> Vec<Vec<U>> {
        // let next_frontier = 
        self.frontier_intermediate
            .par_iter()
            .map(|node| {

            // node.0.key_values.clone()
            // node.1.key_values.clone()

                vec![node.0.key_values.clone(), node.1.key_values.clone()]
            })
            .flatten()
            .collect::<Vec<Vec<U>>>()
        
        // next_frontier
        //     .iter()
        //     .map(|node| node.value.clone())
        //     .collect::<Vec<U>>()
    }

    pub fn histogram_add_leaves_between_clients(&mut self, verified: &Vec<bool>) -> Vec<Result<U>> {
        let next_frontier = self.frontier_intermediate
            .par_iter()
            .map(|node| {
                let child_l = self.histogram_add_leaf_values(
                    node.0.key_values.clone(), node.0.path.clone(), verified);
                let child_r = self.histogram_add_leaf_values(
                    node.1.key_values.clone(), node.1.path.clone(), verified);

                vec![child_l, child_r]
            })
            .flatten()
            .collect::<Vec<TreeNode<U>>>();

        let result = next_frontier
            .iter()
            .map(|node| Result::<U> {
                path: node.path.clone(),
                value: node.value.clone(),
            })
            .collect::<Vec<Result<U>>>();

        result
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

    pub fn keep_values(nclients: usize, threshold: &T, vals0: &[T], vals1: &[T]) -> Vec<bool> {
        assert_eq!(vals0.len(), vals1.len());

        let nclients = T::from(nclients as u32);
        let mut keep = vec![];
        for i in 0..vals0.len() {
            let mut v = T::zero();
            v.add(&vals0[i]);
            v.add(&vals1[i]);

            // let v_any = &v as &dyn Any;
            // if let Some(v_fe) = v_any.downcast_ref::<FE>() {
            //     println!("-> Sum: {:?} {:?} {:?}", v_fe.value(), *threshold, nclients);
            // } else {
            //     // Generic path, pretend this is expensive
            //     println!("-> {:?} {:?} {:?}", v, *threshold, nclients);
            // }

            debug_assert!(v <= nclients);

            // Keep nodes that are above threshold
            keep.push(v >= *threshold);
        }

        keep
    }

    pub fn keep_values_last(_nclients: usize, threshold: &U, vals0: &[U], vals1: &[U]) -> Vec<bool> {
        assert_eq!(vals0.len(), vals1.len());

        // let nclients = U::from(_nclients as u32);
        let mut keep = vec![];
        for i in 0..vals0.len() {
            let mut v = U::zero();
            v.add(&vals0[i]);
            v.add(&vals1[i]);
            //println!("-> {:?} {:?} {:?}", v, *threshold, nclients);

            // debug_assert!(v <= nclients);

            // Keep nodes that are above threshold
            keep.push(v >= *threshold);
        }

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
                v.add(&v1);
                v.add(&v2);
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

            out.push(Result {
                path: res0[i].path.clone(),
                value: v,
            });
        }

        out
    }
}
