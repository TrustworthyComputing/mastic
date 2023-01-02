use crate::dpf;
use crate::prg;
use crate::xor_vec;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use bitvec::prelude::*;
use rand::Rng;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use fast_math::log2_raw;
use core::convert::TryFrom;

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

pub struct Dealer {
    k: Vec<u8>,
    c: u8,
    kc: u8,
}

impl Dealer {
    pub fn new() -> Dealer {
        let mut rng = rand::thread_rng();
        let k = vec![rng.gen::<u8>() % 2, rng.gen::<u8>() % 2];
        let c = rng.gen::<u8>() % 2;
        Dealer { kc: k[c as usize], k: k, c: c, }
    }
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

    fn make_tree_node(&self, parent: &TreeNode<T>, dir: bool, _hh: bool) -> TreeNode<T> {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<T>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                key.1.eval_bit(&parent.key_states[i], dir)
            })
            .unzip();

        // let mut hashes = vec![];
        // let mut hasher = Sha256::new();
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir {'1'} else {'0'});

        let mut child_val = T::zero();
        // for (i, (v, ks)) in key_values.iter().zip(key_states.iter()).enumerate() {
        for (i, v) in key_values.iter().enumerate() {
            // Add in only live values
            if self.keys[i].0 {
                child_val.add_lazy(&v);

                // if _hh {
                //     // pre_image = x | seed_b
                //     let mut pre_image = bit_str.clone();
                //     pre_image.push_str(&String::from_utf8_lossy(&ks.seed.key));
    
                //     hasher.update(pre_image);
                //     let mut pi_prime = hasher.finalize_reset().to_vec();
            
                //     // Correction operation
                //     if ks.bit {
                //         pi_prime = xor_vec(&pi_prime, &self.keys[i].1.cs);
                //     }
                //     hashes.push(pi_prime);
                // }
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

    fn make_tree_node_last(&self, parent: &TreeNode<T>, dir: bool) -> (Vec<U>, Vec<Vec<u8>>, Vec<bool>) {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<U>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                key.1.eval_bit_last(&parent.key_states[i], dir)
            })
            .unzip();

        // Construct path: parent.path | bit
        // pi_b = H(x | seed_b)
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir {'1'} else {'0'});

        let mut hashes = vec![];
        if !dir {
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
        }
        let mut path = parent.path.clone();
        path.push(dir);

        (key_values, hashes, path)
    }

    // Adds values for "path" accross multiple clients.
    fn add_leaf_values(&self,
        key_values: &Vec<U>,
        path: &Vec<bool>,
        verified: &Vec<bool>
    ) -> TreeNode<U> {
        let mut child_val = U::zero();
        for (kv, ver) in key_values.iter().zip(verified) {
            // Add in only live values
            if *ver {
                child_val.add_lazy(&kv);
            }
        }
        child_val.reduce();

        TreeNode::<U> {
            path: path.clone(),
            value: child_val,
            key_states: vec![],
            key_values: vec![],
            hashes: vec![],
        }
    }

    pub fn hh_tree_crawl(&mut self) -> Vec<T> {
        let next_frontier = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node(node, false, true);
                let child1 = self.make_tree_node(node, true, true);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<T>>>();

        let values = next_frontier
            .par_iter()
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
                // assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node(node, false, false);
                let child1 = self.make_tree_node(node, true, false);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<T>>>();
    }

    pub fn tree_crawl_last(&mut self) -> (Vec<Vec<u8>>, Vec<U>) {
        self.frontier_intermediate = self
            .frontier
            .par_iter()
            .map(|node| {
                // assert!(node.path.len() <= self.depth);
                let (key_values_l, hashes_l, path_l) = self.
                    make_tree_node_last(node, false);
                let (key_values_r, hashes_r, path_r) = self.
                    make_tree_node_last(node, true);

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
        let num_clients = self.frontier_intermediate[0].0.hashes.len();
        let mut final_hashes = vec![vec![0u8; 32]; num_clients];
        let mut tau_vals = vec![U::zero(); num_clients];
        for node in self.frontier_intermediate.iter() {
            final_hashes = final_hashes
                .par_iter_mut()
                .zip_eq(&node.0.hashes)
                .map(|(v1, v2)| xor_vec(&v1, &v2))
                .collect();

            tau_vals = tau_vals
                .par_iter_mut()
                .zip_eq(&node.0.key_values)
                .zip_eq(&node.1.key_values)
                .map(|((t, v0), v1)| {
                    t.add(&v0);
                    t.add(&v1);
                    t.clone()
                })
                .collect();
        }

        if crate::consts::BATCH {
            let mut batched_hash = vec![0u8; 32];
            let mut batched_tau = U::zero();
            for (hash, tau) in final_hashes.iter().zip(tau_vals) {
                batched_hash = xor_vec(&batched_hash, &hash);
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
            .map(|node| {
                vec![&node.0.key_values, &node.1.key_values]
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    pub fn add_leaves_between_clients(&mut self, verified: &Vec<bool>) -> Vec<Result<U>> {
        let next_frontier = self.frontier_intermediate
            .par_iter()
            .map(|node| {
                let child_l = self.add_leaf_values(
                    &node.0.key_values, &node.0.path, verified);
                let child_r = self.add_leaf_values(
                    &node.1.key_values, &node.1.path, verified);

                vec![child_l, child_r]
            })
            .flatten()
            .collect::<Vec<TreeNode<U>>>();

        // self.frontier_last = next_frontier; //.clone();

        next_frontier
            .par_iter()
            .map(|node| Result::<U> {
                path: node.path.clone(),
                value: node.value.clone(),
            })
            .collect::<Vec<Result<U>>>()
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

            debug_assert!(v <= nclients);

            // Keep nodes that are above threshold
            keep.push(v >= *threshold);
        }

        // println!("Keep: {}", keep.len());
        keep
    }

    pub fn keep_values_cmp(threshold: &T, vals0: &[T], vals1: &[T]) -> Vec<bool> {
        let mut keep = vec![];
        let thresh = (*threshold).clone().value() as u32;
        for i in 0..vals0.len() {
            let mut vals_0_one = T::one();
            vals_0_one.add(&vals0[i]);
            let lt = Self::lt_const(thresh, &vals_0_one, &vals1[i]);

            if cfg!(debug_assertions) {
                let mut v = T::zero();
                v.add(&vals0[i]);
                v.add(&vals1[i]);
                assert_eq!(v >= *threshold, lt, "lt_const: v >= *threshold, lt");
            }            

            // Keep nodes that are above threshold
            keep.push(lt);
        }

        // println!("Keep: {}", keep.len());
        keep
    }

    pub fn secret_share_bool<B>(
        bit_array: &BitVec<B>, num_bits: usize
    ) -> (BitVec<B>, BitVec<B>) 
    where B: BitStore, {
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
    where B: BitStore, {
        assert_eq!(ss0.len(), ss1.len());
        let mut reconstructed = BitVec::<B>::new();
        for (b0, b1) in ss0.iter().zip(ss1.iter()) {
            reconstructed.push(*b0 ^ *b1);
        }
        reconstructed
    }
    
    // P0 is the Sender with inputs (m0, m1)
    // P1 is the Receiver with inputs (b, mb)
    pub fn one_out_of_two_ot(
        dealer: &Dealer,
        receiver_b: u8,
        sender_m: &Vec<u8>) -> u8
    {
        let z = receiver_b ^ dealer.c;
        let y = {
            if z == 0 {
                vec![sender_m[0] ^ dealer.k[0], sender_m[1] ^ dealer.k[1]]
            } else {
                vec![sender_m[0] ^ dealer.k[1], sender_m[1] ^ dealer.k[0]]
            }
        };

        y[receiver_b as usize] ^ dealer.kc
    }

    // OR: z = x | y = ~(~x & ~y)
    //   ~(~x & ~y) = ~(~x * ~y) = ~( ~(p0.x + p1.x) * ~(p0.y + p1.y) ) =
    //  ~( (~p0.x + p1.x) * (~p0.y + p1.y) ) =
    //  ~( (~p0.x * ~p0.y) + (~p0.x * p1.y) + (p1.x * ~p0.y) + (p1.x * p1.y) ) =
    //  P0 computes locally ~p0.x * ~p0.y
    //  P1 computes locally p1.x * p1.y
    //  Both parties compute via OT: ~p0.x * p1.y and p1.x * ~p0.y
    pub fn or_gate(x0: bool, y0: bool, x1: bool, y1: bool) -> (bool, bool) {
        let mut rng = rand::thread_rng();

        // Online Phase - P1 receives r0 + p0.x * p1.y
        let r0 = rng.gen::<bool>();
        let dealer = Dealer::new();
        let r0_x0y1 = Self::one_out_of_two_ot(
            &dealer,
            y1 as u8,
            &vec![r0 as u8, (!x0 as u8) ^ (r0 as u8)]
        ) != 0;

        // Online Phase - P0 receives r1 + p1.x * p0.y
        let r1 = rng.gen::<bool>();
        let dealer = Dealer::new();
        let r1_x1y0 = Self::one_out_of_two_ot(
            &dealer,
            !y0 as u8,
            &vec![r1 as u8, (x1 as u8) ^ (r1 as u8)]
        ) != 0;

        // P0
        let share_0 = !( (!x0 & !y0) ^ (r0 ^ r1_x1y0) );

        // P1
        let share_1 = (x1 & y1) ^ (r1 ^ r0_x0y1);

        (share_0, share_1)
    }

    pub fn get_rand_edabit<B>(num_bits: usize) -> ((T, BitVec<B>), (T, BitVec<B>)) 
    where 
        B: BitStore + bitvec::store::BitStore<Unalias = B> + Eq + Copy + std::ops::Rem<Output=B> + TryFrom<u32>, 
        Standard: Distribution<B>,
        u32: From<B>,
    {
        let mut rng = rand::thread_rng();
        let r = rng.gen::<B>() % B::try_from(64).ok().unwrap();
        let r_bits = r.view_bits::<Lsb0>().to_bitvec();
        let (r_0_bits, r_1_bits) = Self::secret_share_bool(&r_bits, num_bits);
        let (r_0, r_1) = T::from(u32::from(r)).share();
        ((r_0, r_0_bits), (r_1, r_1_bits))
    }
    
    // Returns c = x < R
    fn lt_bits<B>(
        const_r: u32, sh_0: &BitVec<B>, sh_1: &BitVec<B>
    ) -> (u8, u8) 
    where B: BitStore {
        let r_bits = const_r.view_bits::<Lsb0>().to_bitvec();
        let num_bits = sh_0.len();

        // Step 1
        let mut y_bits_0 = bitvec![B, Lsb0; 0; num_bits];
        let mut y_bits_1 = bitvec![B, Lsb0; 0; num_bits];
        for i in 0..num_bits {
            y_bits_0.set(i, sh_0[i] ^ r_bits[i]);
            y_bits_1.set(i, sh_1[i]);
        }
        // Step 2 - PreOpL
        let log_m = log2_raw(num_bits as f32).ceil() as usize;
        for i in 0..log_m {
            for j in 0..(num_bits / (1 << (i + 1))) {
                let y = ((1 << i) + j * (1 << (i + 1))) - 1;
                for z in 1..(1 << (i + 1)) {
                    if y + z < num_bits {
                        let idx_y = num_bits - 1 - y;
                        let (or_0, or_1) = Self::or_gate(
                            y_bits_0[idx_y], y_bits_0[idx_y - z],
                            y_bits_1[idx_y], y_bits_1[idx_y - z]
                        );
                        y_bits_0.set(idx_y - z, or_0);
                        y_bits_1.set(idx_y - z, or_1);
                    }
                }
            }
        }
        y_bits_0.push(false);
        y_bits_1.push(false);
        let z_bits_0 = y_bits_0;
        let z_bits_1 = y_bits_1;

        // Step 3
        let mut w_bits_0 = bitvec![B, Lsb0; 0; num_bits];
        let mut w_bits_1 = bitvec![B, Lsb0; 0; num_bits];
        for i in 0..num_bits {
            w_bits_0.set(i, z_bits_0[i] ^ z_bits_0[i+1]); // -
            w_bits_1.set(i, z_bits_1[i] ^ z_bits_1[i+1]); // -
        }

        // Step 4
        let mut sum_0 = 0u8;
        let mut sum_1 = 0u8;
        for i in 0..num_bits {
            sum_0 += if r_bits[i] & w_bits_0[i] { 1 } else { 0 };
            sum_1 += if r_bits[i] & w_bits_1[i] { 1 } else { 0 };
        }

        (sum_0.view_bits::<Lsb0>().to_bitvec()[0] as u8,
        sum_1.view_bits::<Lsb0>().to_bitvec()[0] as u8)
    }

    fn lt_const(const_r: u32, x_0: &T, x_1: &T) -> bool {
        let num_bits = 16;
        let ((r_0, r_0_bits), (r_1, r_1_bits)) = Self::get_rand_edabit::<u16>(num_bits);
        let const_m = (1 << num_bits) - 1;
    
        // Step 1
        let mut a_0 = T::zero();
        a_0.add(x_0);
        a_0.add(&r_0);
    
        let mut a_1 = T::zero();
        a_1.add(x_1);
        a_1.add(&r_1);
        
        let b_0 = a_0.clone();
        let mut b_1 = a_1.clone();
        let const_r_fe = T::from(const_m - const_r);
        b_1.add(&const_r_fe);
    
        // Step 2
        let mut a = T::zero();
        a.add(&a_0);
        a.add(&a_1);
    
        let mut b = T::zero();
        b.add(&b_0);
        b.add(&b_1);
    
        // Step 3
        let (w1_0, w1_1) = Self::lt_bits(a.clone().value() as u32, &r_0_bits, &r_1_bits);
        let (w2_0, w2_1) = Self::lt_bits(b.clone().value() as u32, &r_0_bits, &r_1_bits);
        let w1 = w1_0 ^ w1_1;
        let w2 = w2_0 ^ w2_1;
        let w3 = (b.clone().value() as u16) < (const_m - const_r) as u16;
    
        let w1_val = w1 as i8;
        let w2_val = w2 as i8;
        let w3_val = w3 as i8;
        let c = 1 - (w1_val - w2_val + w3_val);

        // if cfg!(debug_assertions) {
        //     println!("\tR: {}", const_r);
        //     println!("\tM: {}", const_m);
        //     println!("\tb.value() {} < M - R: {}", b.clone().value() as u8, const_m - const_r as u32);
        //     println!("\ta u8: {}", a.clone().value() as u8);
        //     println!("\tb u8: {}", b.clone().value() as u8);
        //     println!("\tw1_val: {}", w1_val);
        //     println!("\tw2_val: {}", w2_val);
        //     println!("\tw3_val: {}", w3_val);
        //     println!("\tw: x < {} : {}", const_r, c % 2);
        // }
        
        c % 2 == 0
    }

    pub fn keep_values_last(_nclients: usize, threshold: &U, vals0: &[Result::<U>], vals1: &[Result::<U> ]) -> Vec<bool> {
        assert_eq!(vals0.len(), vals1.len());

        // let nclients = U::from(_nclients as u32);
        let mut keep = vec![];
        for i in 0..vals0.len() {
            let mut v = U::zero();
            v.add(&vals0[i].value);
            v.add(&vals1[i].value);
            //println!("-> {:?} {:?} {:?}", v, *threshold, nclients);

            // debug_assert!(v <= nclients);

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
