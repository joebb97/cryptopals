use criterion::{black_box, criterion_group, criterion_main, Criterion};
use set1::{challenge6_data, break_repeating_key_xor};

pub fn break_repeating_key_xor_bench(c: &mut Criterion) {
    let data = challenge6_data();
    c.bench_function("break_repeating_key_xor", |b| {
        b.iter(|| black_box(break_repeating_key_xor(&data)))
    });
}

criterion_group!(benches, break_repeating_key_xor_bench);
criterion_main!(benches);
