mod vsigma;
mod external;
mod consts;
pub mod signature;

use bytes::Bytes;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
//use sha3::{Sha3_512};
use sha2::{Sha512,Digest,Sha256};
use crate::signature::Signature;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use crate::vsigma::VSigmaProof;
use merlin::Transcript;
//use curve25519_dalek::digest::Digest;
use rayon::prelude::*;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul};
use std::ops::Add;
use std::iter;
use crate::consts::static_gens;
use std::convert::TryInto;

#[allow(non_snake_case)]
pub fn HashGens(num: u32) -> Vec<RistrettoPoint> {
    (0..num).map(|i|{
        let mut hasher = Sha512::new();
        hasher.update(&i.to_be_bytes());
        let result = hasher.finalize();
        RistrettoPoint::from_uniform_bytes(&result.as_slice().try_into().expect("Wrong length"))
        }).collect()
}

#[allow(non_snake_case)]
pub fn PEDERSEN_H() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let result = hasher.finalize();
    println!("{:?}",result);
    RistrettoPoint::from_uniform_bytes(&result.as_slice().try_into().expect("Wrong length"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum UOError{
    ArgumentNumberError,
    VerificationSigRemaining,
    VerificationOutputProof,
    VerificationMsgNotFound,
    VerificationMsgRemaining,
    VerificationError,
    VerificationInputProof,
    VerificationInputMatching,
    VerificationInputSignature,
}

pub trait UOMsg: Eq + Default + Clone {
    fn to_byte_vec(&self) -> Vec<u8>;
}

impl UOMsg for Bytes {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_vec()
    }
}
impl UOMsg for u64 {
    fn to_byte_vec(&self) -> Vec<u8> {
        Vec::from(self.to_ne_bytes())
    }
}

#[derive(Default, Hash, Debug, Clone)]
pub struct UOSignature<Algo: Signature, Msg: UOMsg> {
    pub signatures: Vec<(CompressedRistretto, Algo)>,
    messages: Vec<(vsigma::VSigmaProof, CompressedRistretto, Msg)>,
    randomness: Scalar,
}


impl<Algo: Signature + Default + Send + Sync + Clone, Msg: UOMsg + Send + Sync> UOSignature<Algo, Msg> {
    pub fn sign(secret_key: &Scalar, msgs: &Vec<Msg>, numhashes: u32) -> Result<UOSignature<Algo, Msg>, UOError> {
        let mut sig = UOSignature::<Algo, Msg>::default();

        if msgs.len() < 1 {
            return Err(UOError::ArgumentNumberError)
        }
        let gens = static_gens();
        let mut csprng = thread_rng();
        let sr_exp:Vec<(Scalar,Scalar)> = msgs.iter().map(|_|(Scalar::random(&mut csprng),Scalar::random(&mut csprng))).collect();
        //s = Scalar::random(&mut csprng);
        //let rs_exp:Vec<Vec<Scalar>> = msgs.iter().map(|_| iter::once(Scalar::random(&mut csprng)).chain(iter::repeat(s).take(numhashes as usize)).collect() ).collect();
        let outside: Vec<(Vec<Scalar>, Scalar, (VSigmaProof, CompressedRistretto, Msg))> = msgs.par_iter().zip(sr_exp).map(|(msg,(s_exp,r_exp))|{
            let mut transcript = Transcript::new(b"output knowledge");
            transcript.append_message(b"output message",&msg.to_byte_vec());
            let (proof, tmpcom) = vsigma::VSigmaProof::prove(&mut transcript,
                                                             &iter::once(r_exp).chain(iter::repeat(s_exp).take(numhashes as usize)).collect::<Vec<Scalar>>(),
                                                             &iter::once(RISTRETTO_BASEPOINT_POINT).chain(gens.iter().take(numhashes as usize).map(|p|p.clone())).collect::<Vec<RistrettoPoint>>()
            ).expect("something went very wrong");

            let ses: Vec<Scalar> = (0..numhashes as usize).into_par_iter().map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(i.to_be_bytes());
                //hasher.update(proof.as_bytes());
                hasher.update(&tmpcom.compress().as_bytes());
                hasher.update(&msg.to_byte_vec());
                let result = hasher.finalize();
                let output_hash = Scalar::from_bytes_mod_order(result.as_slice().try_into().expect("Wrong length"));
                s_exp + output_hash
            }).collect();
            (ses, r_exp, (proof, tmpcom.compress(), (*msg).clone()) )
        }).collect();

        let cum_ses: Vec<Scalar> = (0..numhashes as usize).map(|pos|{
            outside.iter().map(|(ses,_,_)| ses[pos] ).sum()
        }).collect();
        sig.randomness = outside.iter().map(|(_,r,_)|r).sum();
        sig.messages = outside.iter().map(|(_,_,p)|p.clone()).collect();

        let tmpcom = RistrettoPoint::multiscalar_mul(&cum_ses, gens.iter().take(numhashes as usize).map(|p|p.clone()).collect::<Vec<RistrettoPoint>>());

        let realsig = match Algo::sign( &secret_key,  &tmpcom){
            Ok(x) => x,
            Err(_e) => return Err(UOError::ArgumentNumberError)
        };
        sig.signatures = vec![(tmpcom.compress(),realsig)];

        sig.normalize();
        Ok(sig)
    }

    pub fn verify(&self, public_key: &RistrettoPoint, msgs: &Vec<Msg>, numhashes: u32) -> Result<(), UOError> {

        let mut cum_elem = (-self.randomness) * RISTRETTO_BASEPOINT_POINT;
        let gens = static_gens();
        let vers: Vec<Result<(usize,Vec<Scalar>, RistrettoPoint),UOError>> = self.messages.par_iter().map(|(proof, com, msg)| {
            // check that msg is in in cmp msgs
            let idx = match msgs.iter().position(|x| x == msg) {
                Some(idx) =>idx,
                None => return Err(UOError::VerificationMsgNotFound)
            };

            let mut transcript = Transcript::new(b"output knowledge");
            transcript.append_message(b"output message",&msg.to_byte_vec());
            if proof.verify(&mut transcript,
                            &iter::once(RISTRETTO_BASEPOINT_POINT).chain(gens.iter().take(numhashes as usize).map(|p|p.clone())).collect::<Vec<RistrettoPoint>>()
                            , &com.decompress().unwrap()).is_err() {
                return Err(UOError::VerificationOutputProof)
            }

            let output_hashes: Vec<Scalar> = (0..numhashes as usize).into_par_iter().map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(i.to_be_bytes());
                hasher.update(&com.as_bytes());
                //hasher.update(&proof.as_bytes());
                hasher.update(&msg.to_byte_vec());
                let result = hasher.finalize();
                Scalar::from_bytes_mod_order(result.as_slice().try_into().expect("Wrong length"))
            }).collect();
            Ok((idx,output_hashes, com.decompress().unwrap()))
        }).collect();

        match vers.iter().find(|res| res.is_err()) {
            Some(e) => return Err(e.clone().unwrap_err()),
            _ => {}
        }

        let mut idices = vers.iter().map(|r| r.clone().unwrap().0).collect::<Vec<usize>>();
        idices.sort();
        idices.dedup();
        if idices.len() != msgs.len() {
            return Err(UOError::VerificationMsgRemaining)
        }
        cum_elem += vers.iter().map(|r| r.clone().unwrap().2).sum::<RistrettoPoint>();
        let cum_h: Vec<Scalar> = (0..numhashes as usize).map(|pos|{
            vers.iter().map(|r| r.clone().unwrap().1[pos] ).sum()
        }).collect();
        cum_elem += RistrettoPoint::multiscalar_mul(cum_h,
                                                    gens.iter().take(numhashes as usize).map(|p|p.clone()).collect::<Vec<RistrettoPoint>>());

        let versigs: Vec<Result<RistrettoPoint,UOError>> = self.signatures.par_iter().map( |(com, signature)| {
            if signature.verify(public_key, &com.decompress().unwrap()).is_err() {
                return Err(UOError::VerificationInputSignature)
            }
            Ok(com.decompress().unwrap())
        }).collect();

        match versigs.iter().find(|res| res.is_err()) {
            Some(e) => return Err(e.clone().unwrap_err()),
            _ => {}
        }

        cum_elem = cum_elem - versigs.iter().map(|r| r.clone().unwrap()).sum::<RistrettoPoint>();

        if cum_elem.is_identity() {
            Ok(())
        } else {
            Err(UOError::VerificationError)
        }

    }

    pub fn merge(sigs: &Vec<UOSignature<Algo, Msg>>) -> UOSignature<Algo, Msg> {
        let mut ips = Vec::new();
        let mut ops = Vec::new();
        let mut randomness = Scalar::zero();
        for sig in sigs.iter() {
            ips.extend(sig.signatures.clone());
            ops.extend(sig.messages.clone());
            randomness += sig.randomness;
        }
        
        let mut a = UOSignature::<Algo, Msg>{
            signatures: ips,
            messages: ops,
            randomness
        };
        a.normalize();
        a
    }
    
    pub fn unsorted_merge(sigs: &Vec<UOSignature<Algo, Msg>>) -> UOSignature<Algo, Msg> {
        let mut ips = Vec::new();
        let mut ops = Vec::new();
        let mut randomness = Scalar::zero();
        for sig in sigs.iter() {
            ips.extend(sig.signatures.clone());
            ops.extend(sig.messages.clone());
            randomness += sig.randomness;
        }
        
        let a = UOSignature::<Algo, Msg>{
            signatures: ips,
            messages: ops,
            randomness
        };
        a
    }

    pub fn normalize(&mut self) {
        self.signatures.sort_unstable_by(|a,b|a.0.as_bytes().cmp(b.0.as_bytes()));
        self.messages.sort_unstable_by(|a,b|a.1.as_bytes().cmp(b.1.as_bytes()));
    }
}

impl<Algo: Signature + Default + Send + Sync + Clone, Msg: UOMsg + Send + Sync> Add for UOSignature<Algo, Msg> {
    type Output = UOSignature<Algo, Msg>;
    fn add(self, other: UOSignature<Algo, Msg>) -> UOSignature<Algo, Msg> {
        let mut ips = Vec::from(self.signatures);
        ips.extend(other.signatures);
        let mut ops = Vec::from(self.messages);
        ops.extend(other.messages);
        let mut a = UOSignature::<Algo, Msg>{
            signatures: ips,
            messages: ops,
            randomness: self.randomness+other.randomness
        };
        a.normalize();
        a
    }
}

#[cfg(test)]
mod tests {
    use super::HashGens;
    use crate::consts::static_gens;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use bytes::Bytes;
    use crate::{UOSignature, signature, PEDERSEN_H};
    use rand::thread_rng;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_pedersen() {
        //const COMPRESSED_PEDERSEN_H: CompressedRistretto = CompressedRistretto([140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160, 140, 219, 127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52]);
        let a = HashGens(478);
        let b = static_gens();
        let k = PEDERSEN_H();
        //println!("{:?}",b);
        //println!("{:?}",k);
        //print!("{:?}\n",a.iter().map(|p|p.compress()).collect::<Vec<CompressedRistretto>>());
        for e in a {
            print!("CompressedRistretto({:?}),\n",e.compress().as_bytes());
        }
        //
        //assert_eq!(a,static_gens());
    }

    #[test]
    fn create_uosig() {
        let msgs = vec![Bytes::from("Huey"), Bytes::from("Dewey"),Bytes::from("Louie")];
        //let mut signer = Vec::<(Vec<OTAccount>,usize,TypeCommitment)>::new();
        let mut csprng = thread_rng();
        let sk = Scalar::random(&mut csprng);

        let asig = UOSignature::<signature::Schnorr, Bytes>::sign(&sk, &msgs,100).expect("broke");

        //let sigver = signers.iter().map(|(acct,_,com)|(acct,com)).collect();

        assert!(asig.verify(&(sk*RISTRETTO_BASEPOINT_POINT), &msgs,100).is_ok());
    }

    #[test]
    fn add_uosig() {
        let mut msgs = vec![Bytes::from("Huey"), Bytes::from("Dewey"),Bytes::from("Louie")];
        //let mut signer = Vec::<(Vec<OTAccount>,usize,TypeCommitment)>::new();
        let mut csprng = thread_rng();
        let sk = Scalar::random(&mut csprng);

        let asig1 = UOSignature::<signature::Schnorr, Bytes>::sign(&sk, &msgs,200).expect("broke");

        let msgs2 = vec![Bytes::from("Donald"), Bytes::from("Daisy")];

        let asig2 = UOSignature::<signature::Schnorr, Bytes>::sign(&sk, &msgs2,200).expect("broke");

        //let sigver = signers.iter().map(|(acct,_,com)|(acct,com)).collect();
        msgs.extend(msgs2);
        let sigsum = asig1+asig2;

        assert!(sigsum.verify(&(sk*RISTRETTO_BASEPOINT_POINT), &msgs,200).is_ok());
    }
    
    #[test]
    fn merge_uosig() {
        let mut msgs = vec![Bytes::from("Huey"), Bytes::from("Dewey"),Bytes::from("Louie")];
        //let mut signer = Vec::<(Vec<OTAccount>,usize,TypeCommitment)>::new();
        let mut csprng = thread_rng();
        let sk = Scalar::random(&mut csprng);

        let asig1 = UOSignature::<signature::Schnorr, Bytes>::sign(&sk, &msgs,10).expect("broke");

        let msgs2 = vec![Bytes::from("Donald"), Bytes::from("Daisy")];

        let asig2 = UOSignature::<signature::Schnorr, Bytes>::sign(&sk, &msgs2,10).expect("broke");

        //let sigver = signers.iter().map(|(acct,_,com)|(acct,com)).collect();
        msgs.extend(msgs2);
        let sigsum = UOSignature::<signature::Schnorr, Bytes>::merge(&vec![asig1,asig2]);

        assert!(sigsum.verify(&(sk*RISTRETTO_BASEPOINT_POINT), &msgs,10).is_ok());
    }

}
