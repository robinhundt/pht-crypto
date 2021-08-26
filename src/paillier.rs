use anyhow::{anyhow, Result};
use rug::rand::MutRandState;
use rug::{Assign, Complete, Integer};
use serde::{Deserialize, Serialize};

use crate::rand::{generate_safe_prime, random_in_mult_group};
use crate::util;

use rug::ops::{NegAssign};
use std::convert::TryInto;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Server index of this instance
    i: u32,
    /// Polynomial evaluation at i
    si: Integer,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PublicKey {
    /// The number of servers req to successfully decrypt
    w: u32,
    /// The number of decryption servers in total
    l: u32,
    /// Modulus of the key. n = p * q
    n: Integer,
    /// Precomputation: n + 1
    g: Integer,
    /// Precomputation: n^2
    n2: Integer,
    /// Precomputation: l!
    delta: Integer,
}

pub struct PrivateKey {
    /// The number of servers req to decrypt
    w: u32,
    /// The number of decryption servers in total
    l: u32,
    /// d = 0 mod m and d = 1 mod n^2
    d: Integer,
    /// Modulus of the key: p * q
    n: Integer,
    /// Precomputation: n^2
    n2: Integer,
    /// Precomputation: n * m
    nm: Integer,
}

#[derive(Debug)]
pub struct Polynomial {
    coefficients: Vec<Integer>,
}

pub fn generate_key_pair(
    bits: usize,
    decryption_servers: u32,
    threshold: u32,
) -> Result<(PublicKey, PrivateKey)> {
    let (mut t1, mut t2, mut t3, t4): (Integer, Integer, Integer, Integer) = loop {
        let t1 = generate_safe_prime(bits)?;
        let t3 = generate_safe_prime(bits)?;
        if t1 != t3 {
            let t2 = (t1.clone() - 1) / 2;
            let t4 = (t3.clone() - 1) / 2;
            break (t1, t2, t3, t4);
        }
    };
    let n = t1.clone() * &t3;
    let n2 = n.clone().square();
    let g = n.clone() + 1;
    t3 = t2.clone() * t4;
    let nm = n.clone() * &t3;
    t1.assign(1);
    t2.assign(0);
    let d = util::crt2(&t1, &n, &t2, &t3);
    let delta = Integer::factorial(decryption_servers).complete();

    let pk = PublicKey {
        w: threshold,
        l: decryption_servers,
        n: n.clone(),
        g,
        n2: n2.clone(),
        delta,
    };

    let sk = PrivateKey {
        w: threshold,
        l: decryption_servers,
        d,
        n,
        n2,
        nm,
    };

    Ok((pk, sk))
}

impl KeyShare {
    pub fn new(si: Integer, i: u32) -> Self {
        Self {
            // TODO i is not used
            i: i + 1, // Input is assumed to be 0-indexed (from array)
            si,
        }
    }
}

impl PublicKey {
    pub fn encrypt(&self, m: Integer, rand: &mut dyn MutRandState) -> Integer {
        let mut r = random_in_mult_group(&self.n, rand);
        let mut rop = self.g.clone().pow_mod(&m, &self.n2).unwrap();
        r.pow_mod_mut(&self.n, &self.n2).unwrap();
        rop *= r;
        rop %= &self.n2;
        rop
    }

    pub fn reencrypt(&self, cipher: &mut Integer, rand: &mut dyn MutRandState) {
        let mut tmp = random_in_mult_group(&self.n, rand);
        tmp.pow_mod_mut(&self.n, &self.n2).unwrap();
        *cipher *= tmp;
        *cipher %= &self.n2;
    }

    pub fn add_plain(&self, cipher: &mut Integer, plain: &Integer) {
        let tmp = self.g.clone().pow_mod(plain, &self.n2).unwrap();
        *cipher *= tmp;
        *cipher %= &self.n2;
    }

    pub fn add_encrypted(&self, cipher1: &mut Integer, cipher2: &Integer) {
        *cipher1 *= cipher2;
        *cipher1 %= &self.n2;
    }

    pub fn mul_plain(&self, cipher: &mut Integer, plain: &Integer) {
        cipher.pow_mod_mut(plain, &self.n2).unwrap();
    }

    pub fn share_decrypt(&self, auth_server: &KeyShare, cipher: Integer) -> Integer {
        let exponent = auth_server.si.clone() * &self.delta * 2;
        cipher.pow_mod(&exponent, &self.n2).unwrap()
    }

    pub fn share_combine(&self, shares: &[Integer]) -> Result<Integer> {
        assert_eq!(
            shares.len(),
            self.l as usize,
            "shares must have same length as decryption servers. Zero entries are ignored"
        );
        let mut rop = Integer::from(1);
        let mut t1;
        let mut t2;
        for i in 0..self.l as usize {
            if shares[i] == 0 {
                continue;
            }
            t1 = self.delta.clone();
            for j in 0..(self.l as i64) {
                if i == j as usize || shares[j as usize] == 0 {
                    continue;
                }
                let v = j - i as i64;
                t1 = if v < 0 { t1 / (v * -1) } else { t1 / v };
                if v < 0 {
                    t1.neg_assign()
                }
                t1 *= j + 1;
            }
            t2 = t1.abs_ref().complete();
            t2 *= 2;
            t2 = Integer::from(shares[i].pow_mod_ref(&t2, &self.n2).unwrap());
            if t1.signum() < 0 && t2.invert_mut(&self.n2).is_err() {
                return Err(anyhow!("No inverse"));
            }
            rop *= t2;
            rop %= &self.n2;
        }
        rop = dlog_s(rop, &self.n);
        t1 = self.delta.clone().square();
        t1 *= 4;
        if t1.invert_mut(&self.n).is_err() {
            return Err(anyhow!("No inverse"));
        }
        rop *= t1;
        rop %= &self.n;
        Ok(rop)
    }
}

impl Polynomial {
    pub fn new(sk: &PrivateKey, rand: &mut dyn MutRandState) -> Self {
        let mut coefficients = vec![sk.nm.clone(); sk.w as usize];
        coefficients[0] = sk.d.clone();
        for coeff in coefficients.iter_mut().skip(1) {
            coeff.random_below_mut(rand);
        }
        Self { coefficients }
    }

    pub fn compute(&self, sk: &PrivateKey, x: u32) -> Integer {
        let mut rop = self.coefficients[0].clone();
        for (i, coeff) in self.coefficients.iter().enumerate().skip(1) {
            let mut tmp = Integer::u_pow_u(x + 1, i.try_into().unwrap()).complete();
            tmp *= coeff;
            rop += tmp;
            rop %= &sk.nm;
        }
        rop
    }
}

fn dlog_s(mut op: Integer, n: &Integer) -> Integer {
    op -= 1;
    op.div_exact_mut(n);
    op % n
}

#[cfg(test)]
mod tests {
    use crate::paillier::{generate_key_pair, KeyShare, Polynomial};
    
    use rug::rand::RandState;
    use rug::Integer;

    #[test]
    fn test_single_server() {
        let (pk, sk) = generate_key_pair(128, 1, 1).unwrap();
        let mut rand = RandState::new();
        let c = pk.encrypt(5.into(), &mut rand);
        let poly_eval = Polynomial::new(&sk, &mut rand).compute(&sk, 0);
        let auth_server = KeyShare::new(poly_eval, 0);
        let share_decrypt = pk.share_decrypt(&auth_server, c);
        let combined = pk.share_combine(&[share_decrypt]).unwrap();
        assert_eq!(combined, 5);
    }

    #[test]
    fn test_multiple_server() {
        let (pk, sk) = generate_key_pair(128, 3, 3).unwrap();
        let mut rand = RandState::new();
        let c = pk.encrypt(10.into(), &mut rand);
        let poly = Polynomial::new(&sk, &mut rand);
        let auth_servers: Vec<_> = (0..3)
            .map(|idx| {
                let poly_eval = poly.compute(&sk, idx);
                KeyShare::new(poly_eval, idx)
            })
            .collect();

        let shares: Vec<_> = auth_servers
            .iter()
            .map(|au| pk.share_decrypt(au, c.clone()))
            .collect();
        let combined = pk.share_combine(&shares).unwrap();
        assert_eq!(combined, 10);
    }

    #[test]
    fn test_multiple_server_lower_threshold() {
        let (pk, sk) = generate_key_pair(128, 3, 2).unwrap();
        let mut rand = RandState::new();
        let c = pk.encrypt(10.into(), &mut rand);
        let poly = Polynomial::new(&sk, &mut rand);
        let auth_servers: Vec<_> = (0..2)
            .map(|idx| {
                let poly_eval = poly.compute(&sk, idx);
                KeyShare::new(poly_eval, idx)
            })
            .collect();

        let mut shares: Vec<_> = auth_servers
            .iter()
            .map(|au| pk.share_decrypt(au, c.clone()))
            .collect();
        shares.push(Integer::new());
        let combined = pk.share_combine(&shares).unwrap();
        assert_eq!(combined, 10);
    }
}
