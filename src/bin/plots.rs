use std::collections::HashMap;
use union_only::UOSignature;
use union_only::signature;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::thread_rng;
use std::time::Instant;
use structopt::StructOpt;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;


#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "union-only-sig", about = "Runs the performance tests for Union Only Sigs")]
struct Opt {
    #[structopt(
    short = "s",
    long = "statistics",
    help = "How many repetitions",
    default_value = "20"
    )]
    statistics: u64,

    #[structopt(
    short = "m",
    long = "messages",
    help = "Messages per part",
    default_value = "2"
    )]
    messages: usize,

    #[structopt(
    short = "a",
    long = "merging",
    help = "Number of signatures to merge",
    default_value = "10"
    )]
    merging: usize,
}

fn main() -> Result<(),std::io::Error> {
    let opt = Opt::from_args();

    let mut csprng = thread_rng();
    let numhashes = 100;
    let start = Instant::now();
    for _ in 0..100 {
    let sk = Scalar::random(&mut csprng);
    let pk = sk*RISTRETTO_BASEPOINT_POINT;
    let msg: Vec<u64> = (0..).take(5).map(|_| rand::random::<u64>()).collect();
    let sig = UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg, numhashes);
    }
    let time = start.elapsed().as_micros();
    println!("sign time {:?}", time);

    
    
    let mut sigs: Vec<(UOSignature::<signature::Schnorr, u64>, Vec<u64>, RistrettoPoint)> = Vec::new();
    for _ in 0..100 {
    let sk = Scalar::random(&mut csprng);
    let pk = sk*RISTRETTO_BASEPOINT_POINT;
    let msg: Vec<u64> = (0..).take(5).map(|_| rand::random::<u64>()).collect();
    let sig = UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg, numhashes).expect("sign");
    sigs.push((sig,msg,pk));
    }
    let start = Instant::now();
    let v: Vec<bool> = sigs.iter().map(|(sig,msg,pk)| {
        let res = sig.verify(pk,msg, numhashes);
        res.is_ok()
    }).collect();
    let time = start.elapsed().as_micros();
    println!("verify time {:?}", time);


    let sk = Scalar::random(&mut csprng);
    let pk = sk*RISTRETTO_BASEPOINT_POINT;
    let msg: Vec<u64> = (0..).take(10).map(|_| rand::random::<u64>()).collect();
    let sigs: Vec<UOSignature::<signature::Schnorr, u64>> = (0..10).map(|_| UOSignature::<signature::Schnorr, u64>::sign(&sk, &msg, numhashes).expect("signing error")).collect();
    //(pk,msg,sig)

    let res = sigs.iter().fold(UOSignature::<signature::Schnorr, u64>::default(), |sum,x| sum+ (x.clone()));
    println!("{:?}", res);
    Ok(())
}