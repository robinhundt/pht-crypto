use anyhow::Result;
use rug::Complete;
use rug::Integer;
use rug::ops::Pow;
use rug::rand::MutRandState;

use crate::rand::{generate_safe_prime, random_in_mult_group};

pub mod paillier;
mod rand;
mod util;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
