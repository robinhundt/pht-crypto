#![doc = include_str!("../README.md")]

use rug::Integer;
use serde::{Deserialize, Serialize};

pub mod paillier;
mod rand;
mod util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    #[serde(with = "crate::util::serde_integer")]
    val: Integer,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Plaintext {
    #[serde(with = "crate::util::serde_integer")]
    val: Integer,
}

macro_rules! impl_from {
    ($target:ty; $($from:ty)+) => {
        $(
            impl From<$from> for $target {
                fn from(v: $from) -> Self {
                    Self {
                        val: v.into()
                    }
                }
            }
        )+
    };
}

macro_rules! impl_partial_eq_plaintext {
    ($($eq:ty)+) => {
        $(
            impl PartialEq<$eq> for Plaintext {
                fn eq(&self, other: &$eq) -> bool {
                    self.val.eq(other)
                }
            }
        )+
    }
}

// Damn coherence and lack of specialisation...
impl_from!(Ciphertext; bool i128 i16 i32 i64 i8 isize u128 u16 u32 u64 u8 usize Integer &Integer);
impl_from!(Plaintext; bool i128 i16 i32 i64 i8 isize u128 u16 u32 u64 u8 usize Integer &Integer);
impl_partial_eq_plaintext!(f32 f64 i128 i16 i32 i64 i8 isize u128 u16 u32 u64 u8 usize Integer);

impl From<Ciphertext> for Integer {
    fn from(c: Ciphertext) -> Self {
        c.val
    }
}

impl From<Plaintext> for Integer {
    fn from(c: Plaintext) -> Self {
        c.val
    }
}

impl AsRef<Integer> for Ciphertext {
    fn as_ref(&self) -> &Integer {
        &self.val
    }
}

impl AsRef<Integer> for Plaintext {
    fn as_ref(&self) -> &Integer {
        &self.val
    }
}

impl AsMut<Integer> for Ciphertext {
    fn as_mut(&mut self) -> &mut Integer {
        &mut self.val
    }
}

impl AsMut<Integer> for Plaintext {
    fn as_mut(&mut self) -> &mut Integer {
        &mut self.val
    }
}
