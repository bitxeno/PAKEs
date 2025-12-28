use digest::{Digest, Output};
use num_bigint::BigUint;

use crate::types::SrpGroup;

// u = H(PAD(A) | PAD(B))
pub fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BigUint::from_bytes_be(&u.finalize())
}

// k = H(N | PAD(g))
pub fn compute_k<D: Digest>(params: &SrpGroup) -> BigUint {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BigUint::from_bytes_be(d.finalize().as_slice())
}

// M1 = H(A, B, K) this doesn't follow the spec but apparently no one does for M1
// M1 should equal =  H(H(N) XOR H(g) | H(U) | s | A | B | K) according to the spec
pub fn compute_m1<D: Digest>(
    a_pub: &[u8],
    b_pub: &[u8],
    key: &[u8],
    username: &[u8],
    salt: &[u8],
    params: &SrpGroup,
    ex_data: Option<&[u8]>,
) -> Output<D> {
    // X = H(N) xor H(g) where H(...) = SHA512(raw bytes)
    let n_bytes = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();

    let n_hash = D::digest(&n_bytes);
    let g_hash = D::digest(&g_bytes);

    let mut x = n_hash.clone();
    for i in 0..x.len() {
        x[i] ^= g_hash[i];
    }

    // Y = H(U)
    let y = D::digest(username);

    // K = H(BigIntegerToCstr(srp->key)) -> hash the provided key bytes
    let key_hash = D::digest(key);

    let mut d = D::new();
    d.update(&x); // 64 bytes
    d.update(&y); // 64 bytes
    d.update(salt);
    d.update(a_pub);
    d.update(b_pub);
    d.update(&key_hash); // 64 bytes
    if let Some(ed) = ex_data {
        d.update(ed);
    }

    d.finalize()
}

// M2 = H(A, M1, K)
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &Output<D>, key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(&a_pub);
    d.update(&m1);
    d.update(&key);
    d.finalize()
}
