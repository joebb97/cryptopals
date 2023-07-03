use criterion::{black_box, criterion_group, criterion_main, Criterion};
use set1::detect_single_character_xor;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("detect single character xor", |b| {
        b.iter(|| black_box(detect_single_character_xor()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
