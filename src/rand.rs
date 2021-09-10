use anyhow::Result;
use rand::thread_rng;
use rug::integer::Order;
use rug::rand::MutRandState;
use rug::Complete;
use rug::Integer;
use openssl::bn::BigNum;

pub(crate) fn generate_safe_prime(bits: usize) -> Result<Integer> {
    let mut sp = BigNum::new()?;
    sp.generate_prime(bits as i32, true, None, None);
    Ok(Integer::from_digits(&sp.to_vec(), Order::MsfBe))
}

/// Generate a random value that is in Z_(op)^*. This simply random chooses
/// values until we get one with gcd(rop, op) of n. If one has knowledge about
/// the value of rop, then calling this function may not be neccessary. i.e.
/// if rop is prime, we can just call urandomm directly.
pub(crate) fn random_in_mult_group(op: &Integer, rand: &mut dyn MutRandState) -> Integer {
    loop {
        let res = Integer::from(op.random_below_ref(rand));
        if res.gcd_ref(&op).complete() == 1 {
            break res;
        }
    }
}
