#[macro_use]
extern crate criterion;

use union_only::UOSignature;
use union_only::signature;
use union_only::signature::Schnorr;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use std::fmt::{Display, Formatter};

use criterion::*;

struct Benchparams {
    size: i32,
    hashes: u32
}
impl Display for Benchparams {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "s{}-h{}", self.size, self.hashes)
    }
}

fn bench_sign(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("signing");
    for size in 1..19 {
        for hashes in [1,10,100,478].iter() {
            let bp = Benchparams{size: size, hashes: *hashes};
            group.bench_with_input(BenchmarkId::from_parameter(&bp), &bp, |b, bp| {
                b.iter_batched(|| {
                    let sk = Scalar::random(&mut csprng);
                    let msg: Vec<u64> = (0..).take(bp.size as usize).map(|_| rand::random::<u64>()).collect();
                    (sk, msg)
                }, |(sk, msg)| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg, bp.hashes), BatchSize::SmallInput)
            });
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("verifying");
    for size in 1..19 {
        for hashes in [1,10,100,478].iter() {
            let bp = Benchparams { size: size, hashes: *hashes };
            group.bench_with_input(BenchmarkId::from_parameter(&bp), &bp, |b, bp| {
                b.iter_batched(|| {
                    let sk = Scalar::random(&mut csprng);
                    let pk = sk * RISTRETTO_BASEPOINT_POINT;
                    let msg: Vec<u64> = (0..).take(bp.size as usize).map(|_| rand::random::<u64>()).collect();
                    let sig = UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg, bp.hashes).expect("signing error");
                    (pk, msg, sig)
                }, |(pk, msg, sig)| sig.verify(&pk, &msg, bp.hashes), BatchSize::SmallInput)
            });
        }
    }
    group.finish();
}

fn bench_merge(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("merging");
    for size in [2,10,100,1000,10000,100000,1000000].iter() { //
        if size > &10000 {
            group.sample_size(10);
        }
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(|| {
                let sk = Scalar::random(&mut csprng);
                let pk = sk*RISTRETTO_BASEPOINT_POINT;
                let msg: Vec<u64> = (0..).take(1).map(|_| rand::random::<u64>()).collect();
                
                let sigs: Vec<UOSignature::<signature::Schnorr, u64>> = match size <= 100 {
                     true => { (0..size).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect() }
                     false => {
                     let tmp: Vec<UOSignature::<signature::Schnorr, u64>> = (0..100).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect();
                     let mut sigs = Vec::new();
                     for _ in (0..(size/100)) {
                        sigs.extend(tmp.clone())
                     }
                     sigs
                     }
                };
                
                //(pk,msg,sig)
                sigs
                
            //}, |sigs| sigs.iter().fold(UOSignature::<signature::Schnorr, u64>::default(), |sum,x| sum+(x.clone())) , BatchSize::SmallInput)
            }, |sigs| UOSignature::<signature::Schnorr, u64>::merge(&sigs) , BatchSize::SmallInput)
        });
    }
    group.finish();
}

fn bench_merge10(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("merging10");
    for size in [2,10,100,1000,10000,100000,1000000].iter() { //
        if size > &100 {
            group.sample_size(10);
        }
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(|| {
                let sk = Scalar::random(&mut csprng);
                let pk = sk*RISTRETTO_BASEPOINT_POINT;
                let msg: Vec<u64> = (0..).take(10).map(|_| rand::random::<u64>()).collect();
                
                let sigs: Vec<UOSignature::<signature::Schnorr, u64>> = match size <= 100 {
                     true => { (0..size).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect() }
                     false => {
                     let tmp: Vec<UOSignature::<signature::Schnorr, u64>> = (0..100).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect();
                     let mut sigs = Vec::new();
                     for _ in (0..(size/100)) {
                        sigs.extend(tmp.clone())
                     }
                     sigs
                     }
                };
                
                //(pk,msg,sig)
                sigs
                
            //}, |sigs| sigs.iter().fold(UOSignature::<signature::Schnorr, u64>::default(), |sum,x| sum+(x.clone())) , BatchSize::SmallInput)
            }, |sigs| UOSignature::<signature::Schnorr, u64>::merge(&sigs) , BatchSize::SmallInput)
        });
    }
    group.finish();
}

fn bench_merge100(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("merging100");
    for size in [2,10,100,1000,10000,100000].iter() { //
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(|| {
                let sk = Scalar::random(&mut csprng);
                let pk = sk*RISTRETTO_BASEPOINT_POINT;
                let msg: Vec<u64> = (0..).take(100).map(|_| rand::random::<u64>()).collect();
                
                let sigs: Vec<UOSignature::<signature::Schnorr, u64>> = match size <= 100 {
                     true => { (0..size).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect() }
                     false => {
                     let tmp: Vec<UOSignature::<signature::Schnorr, u64>> = (0..100).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect();
                     let mut sigs = Vec::new();
                     for _ in (0..(size/100)) {
                        sigs.extend(tmp.clone())
                     }
                     sigs
                     }
                };
                
                //(pk,msg,sig)
                sigs
                
            //}, |sigs| sigs.iter().fold(UOSignature::<signature::Schnorr, u64>::default(), |sum,x| sum+(x.clone())) , BatchSize::SmallInput)
            }, |sigs| UOSignature::<signature::Schnorr, u64>::merge(&sigs) , BatchSize::SmallInput)
        });
    }
    group.finish();
}

fn bench_merge1000(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("merging1000");
    for size in [2,10,100,1000,10000].iter() { //
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(|| {
                let sk = Scalar::random(&mut csprng);
                let pk = sk*RISTRETTO_BASEPOINT_POINT;
                let msg: Vec<u64> = (0..).take(1000).map(|_| rand::random::<u64>()).collect();
                
                let sigs: Vec<UOSignature::<signature::Schnorr, u64>> = match size <= 100 {
                     true => { (0..size).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect() }
                     false => {
                     let tmp: Vec<UOSignature::<signature::Schnorr, u64>> = (0..100).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect();
                     let mut sigs = Vec::new();
                     for _ in (0..(size/100)) {
                        sigs.extend(tmp.clone())
                     }
                     sigs
                     }
                };
                
                //(pk,msg,sig)
                sigs
                
            //}, |sigs| sigs.iter().fold(UOSignature::<signature::Schnorr, u64>::default(), |sum,x| sum+(x.clone())) , BatchSize::SmallInput)
            }, |sigs| UOSignature::<signature::Schnorr, u64>::merge(&sigs) , BatchSize::SmallInput)
        });
    }
    group.finish();
}

fn bench_unsorted1000(c: &mut Criterion) {

    let mut csprng = thread_rng();
    
    let mut group = c.benchmark_group("unsorted1000");
    for size in [2,10,100,1000,10000].iter() { //
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(|| {
                let sk = Scalar::random(&mut csprng);
                let pk = sk*RISTRETTO_BASEPOINT_POINT;
                let msg: Vec<u64> = (0..).take(1000).map(|_| rand::random::<u64>()).collect();
                
                let sigs: Vec<UOSignature::<signature::Schnorr, u64>> = match size <= 100 {
                     true => { (0..size).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect() }
                     false => {
                     let tmp: Vec<UOSignature::<signature::Schnorr, u64>> = (0..100).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg,478).expect("signing error")).collect();
                     let mut sigs = Vec::new();
                     for _ in (0..(size/100)) {
                        sigs.extend(tmp.clone())
                     }
                     sigs
                     }
                };
                
                //(pk,msg,sig)
                sigs
                
            //}, |sigs| sigs.iter().fold(UOSignature::<signature::Schnorr, u64>::default(), |sum,x| sum+(x.clone())) , BatchSize::SmallInput)
            }, |sigs| UOSignature::<signature::Schnorr, u64>::unsorted_merge(&sigs) , BatchSize::SmallInput)
        });
    }
    group.finish();
}


criterion_group!(benches, bench_sign,bench_verify, bench_merge);
//criterion_group!(benches, bench_sign,bench_verify, bench_merge,bench_merge10,bench_merge100, bench_merge1000 ,bench_unsorted1000);
//criterion_group!(benches, bench_merge10);
criterion_main!(benches);
