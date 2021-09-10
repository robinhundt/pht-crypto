use criterion::{Criterion, criterion_group, criterion_main};
use pht_crypto::paillier::generate_key_pair;



pub fn key_gen(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_gen");
    group.sample_size(10);
    group.bench_function("512 bits", |b| b.iter(|| generate_key_pair(512, 1, 1)));
    group.bench_function("1024 bits", |b| b.iter(|| generate_key_pair(1024, 1, 1)));
    group.bench_function("2048 bits", |b| b.iter(|| generate_key_pair(2048, 1, 1)));
    group.finish()
}

criterion_group!(benches, key_gen);
criterion_main!(benches);