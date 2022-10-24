use crate::dpf;
use crate::prg;
// use crate::fastfield::FE;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
// use std::any::Any;

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
pub struct KeyCollection<T,U> {
    depth: usize,
    pub keys: Vec<(bool, dpf::DPFKey<T,U>)>,
    frontier: Vec<TreeNode<T>>,
    frontier_last: Vec<TreeNode<U>>,
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
        };

        child.path.push(dir);

        //println!("{:?} - Child value: {:?}", child.path, child.value);
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

    pub fn keep_values(_nclients: usize, threshold: &T, vals0: &[T], vals1: &[T]) -> Vec<bool> {
        assert_eq!(vals0.len(), vals1.len());

        // let nclients = T::from(_nclients as u32);
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

            // debug_assert!(v <= nclients);

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
