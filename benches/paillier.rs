use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pht_crypto::paillier::generate_key_pair;
use rug::rand::RandState;

pub fn key_gen(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_gen");
    group.sample_size(10);
    group.bench_function("512 bits", |b| b.iter(|| generate_key_pair(512, 1, 1)));
    group.bench_function("1024 bits", |b| b.iter(|| generate_key_pair(1024, 1, 1)));
    group.bench_function("2048 bits", |b| b.iter(|| generate_key_pair(2048, 1, 1)));
    group.bench_function("3072 bits", |b| b.iter(|| generate_key_pair(3072, 1, 1)));
    group.finish();
}

pub fn encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");
    let (pk, _sk) = generate_key_pair(2048, 10, 10).unwrap();
    let mut rand_state = RandState::new();
    group.bench_function("2048 bits", |b| {
        b.iter(|| pk.encrypt(42.into(), &mut rand_state))
    });
    let (pk, _sk) = generate_key_pair(3072, 10, 10).unwrap();
    group.bench_function("3072 bits", |b| {
        b.iter(|| pk.encrypt(42.into(), &mut rand_state))
    });
}

pub fn add_ciphertexts(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_ciphertexts");
    let (pk, _sk) = generate_key_pair(2048, 10, 10).unwrap();
    let mut ciphertext1 = pk.encrypt(42.into(), &mut RandState::new());
    let ciphertext2 = pk.encrypt(999.into(), &mut RandState::new());
    group.bench_function("2048 bits", |b| {
        b.iter(|| pk.add_encrypted(black_box(&mut ciphertext1), black_box(&ciphertext2)))
    });
    let (pk, _sk) = generate_key_pair(3072, 10, 10).unwrap();
    let mut ciphertext1 = pk.encrypt(42.into(), &mut RandState::new());
    let ciphertext2 = pk.encrypt(999.into(), &mut RandState::new());
    group.bench_function("3072 bits", |b| {
        b.iter(|| pk.add_encrypted(black_box(&mut ciphertext1), black_box(&ciphertext2)))
    });
}

pub fn share_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("share_decrypt");
    let (pk, sk) = generate_key_pair(2048, 200, 200).unwrap();
    let mut rand = RandState::new();
    let sk_shares = sk.share(&(0..200).collect::<Vec<_>>(), &mut rand);
    let cipher = pk.encrypt(0.into(), &mut rand);
    group.bench_function("2048 bits", |b| {
        b.iter(|| {
            sk_shares[0].share_decrypt(&pk, cipher.clone());
        })
    });

    let (pk, sk) = generate_key_pair(3072, 200, 200).unwrap();
    let mut rand = RandState::new();
    let sk_shares = sk.share(&(0..200).collect::<Vec<_>>(), &mut rand);
    let cipher = pk.encrypt(0.into(), &mut rand);
    group.bench_function("3072 bits", |b| {
        b.iter(|| {
            sk_shares[0].share_decrypt(&pk, cipher.clone());
        })
    });
}

pub fn combine_shares(c: &mut Criterion) {
    let mut group = c.benchmark_group("combine_shares");
    let mut rand = RandState::new();

    let (pk, sk) = generate_key_pair(2048, 200, 200).unwrap();
    let sk_shares = sk.share(&(0..200).collect::<Vec<_>>(), &mut rand);
    let cipher = pk.encrypt(42.into(), &mut rand);
    let partial_decs: Vec<_> = sk_shares
        .iter()
        .map(|share| share.share_decrypt(&pk, cipher.clone()))
        .collect();
    group.bench_function("2048 bits", |b| {
        b.iter(|| {
            pk.share_combine(&partial_decs);
        })
    });

    let (pk, sk) = generate_key_pair(3072, 200, 200).unwrap();
    let sk_shares = sk.share(&(0..200).collect::<Vec<_>>(), &mut rand);
    let cipher = pk.encrypt(42.into(), &mut rand);
    let partial_decs: Vec<_> = sk_shares
        .iter()
        .map(|share| share.share_decrypt(&pk, cipher.clone()))
        .collect();
    group.bench_function("3072 bits", |b| {
        b.iter(|| {
            pk.share_combine(&partial_decs);
        })
    });
}

criterion_group!(
    benches,
    key_gen,
    encrypt,
    add_ciphertexts,
    share_decrypt,
    combine_shares
);
criterion_main!(benches);
