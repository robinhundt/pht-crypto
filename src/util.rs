use rug::{Assign, Complete, Integer};

/// Chinese remainder theorem case where k = 2 using Bezout's identity. Unlike
/// other mpz functions rop must not be an aliased with any of the other
/// arguments! This is done to save excessive copying in this function, plus
/// it is usually not beneficial as conX_a and conX_m cannot be the same value
/// anyway
/// Source: https://github.com/tiehuis/libhcs/blob/0e1deeaca38617b7908b462747dbb80ae9f29d44/src/com/util.c#L294-L298
pub(crate) fn crt2(
    con1_a: &Integer,
    con1_m: &Integer,
    con2_a: &Integer,
    con2_m: &Integer,
) -> Integer {
    let mut t = con1_m.gcd_ref(&con2_m).complete();
    assert_eq!(t, 1);
    let mut res = con2_m.clone().invert(&con1_m).unwrap();
    res *= (con2_m * con1_a).complete();
    t.assign(con1_m.clone().invert(&con2_m).unwrap() * con1_m * con2_a);
    res += t;
    t = (con1_m * con2_m).complete();
    res %= t;
    res
}

/// This implements more efficient ser/de for rug::Integer. The standard implementation simply
/// [uses to_string_radix](https://docs.rs/rug/1.12.0/src/rug/integer/serde.rs.html#26-38) while
/// this uses the more efficient to/from_digits
pub(crate) mod serde_integer {
    use rug::integer::Order;
    use rug::Integer;
    use serde::de::Visitor;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    struct IVisitor;
    impl<'de> Visitor<'de> for IVisitor {
        type Value = Integer;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of bytes in least significant first, big-endian format")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Integer::from_digits(v, Order::LsfBe))
        }
    }

    pub(crate) fn serialize<S>(i: &Integer, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = i.to_digits(Order::LsfBe);
        s.serialize_bytes(&bytes)
    }

    pub(crate) fn deserialize<'de, D>(d: D) -> Result<Integer, D::Error>
    where
        D: Deserializer<'de>,
    {
        d.deserialize_bytes(IVisitor)
    }

    #[cfg(test)]
    mod tests {
        use rug::Integer;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
        struct Wrapper {
            #[serde(with = "super")]
            i: Integer,
        }

        #[test]
        fn test_serde() {
            let i = Wrapper {
                i: Integer::from(42),
            };
            let ser = bincode::serialize(&i).unwrap();
            let deser: Wrapper = bincode::deserialize(&ser).unwrap();
            assert_eq!(i, deser)
        }
    }
}
