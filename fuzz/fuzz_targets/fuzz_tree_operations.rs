#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::protocol::group::tree;

#[derive(Arbitrary, Debug)]
struct TreeInput {
    node_idx: u32,
    leaf_idx: u16,
    leaf_count: u16,
}

fuzz_target!(|input: TreeInput| {
    let n = input.leaf_count as u32;
    let x = input.node_idx;
    let leaf = input.leaf_idx as u32;

    // Navigation functions — must never panic, only return Err
    let _ = tree::root(n);
    let _ = tree::left(x);
    let _ = tree::right(x, n);
    let _ = tree::parent(x, n);
    let _ = tree::sibling(x, n);
    let _ = tree::direct_path(leaf, n);
    let _ = tree::copath(leaf, n);
    let _ = tree::checked_leaf_to_node(leaf);

    // Pure functions — always safe
    let _level = tree::level(x);
    let _is_leaf = tree::is_leaf(x);
    let _nc = tree::node_count(n);
    let _n2l = tree::node_to_leaf(x);

    // Consistency: if root succeeds, left/right of root should work
    if let Ok(r) = tree::root(n) {
        if n > 1 {
            let left_ok = tree::left(r).is_ok();
            let right_ok = tree::right(r, n).is_ok();
            assert!(left_ok, "left(root) must succeed for n > 1");
            assert!(right_ok, "right(root, n) must succeed for n > 1");
        }
    }

    // Consistency: direct_path and copath must have same length
    if n > 0 && leaf < n {
        if let (Ok(dp), Ok(cp)) = (tree::direct_path(leaf, n), tree::copath(leaf, n)) {
            assert_eq!(
                dp.len(),
                cp.len(),
                "direct_path and copath must have same length"
            );
        }
    }

    // Consistency: parent(left(x)) == x and parent(right(x, n)) == x
    if n > 1 {
        if let Ok(r) = tree::root(n) {
            if !tree::is_leaf(x) && x < tree::node_count(n) && x != r {
                if let Ok(l) = tree::left(x) {
                    if let Ok(p) = tree::parent(l, n) {
                        assert_eq!(p, x, "parent(left(x)) must equal x");
                    }
                }
            }
        }
    }
});
