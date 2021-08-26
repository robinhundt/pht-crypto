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
