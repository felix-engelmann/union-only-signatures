use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::thread_rng;

use crate::external::transcript::TranscriptProtocol;


#[derive(Debug, Default, Hash, Clone)]
pub struct VSigmaProof{
    cprime: CompressedRistretto,
    z: Vec<Scalar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum VSigmaError{
    InvalidGeneratorsLength,
    VerificationError
}

impl VSigmaProof {
    pub fn prove(transcript: &mut Transcript,
                 exponents: &[Scalar],
                 bases: &[RistrettoPoint]) -> Result<(VSigmaProof, RistrettoPoint),VSigmaError> {
        if exponents.len() != bases.len() {
            return Err(VSigmaError::InvalidGeneratorsLength)
        }
        transcript.vsigma_domain_sep(bases.len() as u64);

        let original_point = RistrettoPoint::multiscalar_mul(exponents, bases);
        transcript.append_point(b"Commitment", &original_point.compress());

        let mut csprng = thread_rng();
        let eq_rand = Scalar::random(&mut csprng);
        let random_exponents: Vec<Scalar> = bases.iter().enumerate().map(|(i,_)| {
            match i {
                0 => Scalar::random(&mut csprng),
                _ => eq_rand
            } 
        }).collect();

        let cprime = RistrettoPoint::multiscalar_mul(&random_exponents, bases).compress();
        transcript.append_point(b"Point",&cprime);

        let chl = transcript.challenge_scalar(b"challenge");

        let mut proof = VSigmaProof{ cprime, z: Vec::new()};

        for (i, (&exp,rand_exp)) in exponents.iter().zip(random_exponents).enumerate() {
            if i < 2 {
                proof.z.push(rand_exp - chl * exp);
            }
        }
        Ok((proof, original_point))
    }

    pub fn verify(&self, transcript: &mut Transcript, bases: &[RistrettoPoint], com: &RistrettoPoint) -> Result<(),VSigmaError> {
        if self.z.len() > bases.len(){
            return Err(VSigmaError::InvalidGeneratorsLength)
        }

        transcript.vsigma_domain_sep(bases.len() as u64);

        transcript.append_point(b"Commitment", &com.compress());
        transcript.append_point(b"Point", &self.cprime);

        let chl = transcript.challenge_scalar(b"challenge");

        let mut exp = Vec::new();
        for (i,_) in bases.iter().enumerate() {
            if i < 2 {
                exp.push(self.z[i])
            }
            else {
                exp.push(self.z[1])
            }
        }

        let expect_cprime = (chl*com+RistrettoPoint::multiscalar_mul(exp, bases)).compress();
        if expect_cprime == self.cprime {
            Ok(())
        } else {
            Err(VSigmaError::VerificationError)
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut b:Vec<u8> = self.cprime.as_bytes().to_vec();
        self.z.iter().map(|s|b.extend(s.to_bytes()));
        b
    }
}



#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;

    use super::VSigmaProof;
    use crate::{PEDERSEN_H, HashGens};

    #[test]
    fn create_vsigma() {

        let mut prover_transcript = Transcript::new(b"test example");

        let val1 = Scalar::from(37264829u64);
        let val2 = Scalar::from(372614829u64);

        let (proof, commitment) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![val1,val2],
                                                     &vec![RISTRETTO_BASEPOINT_POINT, PEDERSEN_H()]
        ).expect("valid proof inputs");
        let a = proof.as_bytes();
        //print!("{:#?}", tr);
        let mut verifier_transcript = Transcript::new(b"test example");
        assert!(proof.verify(&mut verifier_transcript, &vec![RISTRETTO_BASEPOINT_POINT, PEDERSEN_H()], &commitment).is_ok());
    }
    #[test]
    fn single_vsigma() {

        let mut prover_transcript = Transcript::new(b"test example");

        let val1 = Scalar::from(981623u64);

        let (proof, commitment) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![val1],
                                                     &vec![RISTRETTO_BASEPOINT_POINT]
        ).expect("valid proof inputs");
        //print!("{:#?}", tr);
        let mut verifier_transcript = Transcript::new(b"test example");
        assert!(proof.verify(&mut verifier_transcript, &vec![RISTRETTO_BASEPOINT_POINT], &commitment).is_ok());
    }

    #[test]
    fn wrong_vsigma() {

        let mut prover_transcript = Transcript::new(b"test example");

        let val1 = Scalar::from(1234u64);

        let (proof, commitment) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![val1],
                                                     &vec![RISTRETTO_BASEPOINT_POINT]
        ).expect("valid proof inputs");
        //print!("{:#?}", tr);
        let mut verifier_transcript = Transcript::new(b"test example");
        assert!(proof.verify(&mut verifier_transcript, &vec![RISTRETTO_BASEPOINT_POINT], &(commitment+RISTRETTO_BASEPOINT_POINT)).is_err());
    }

    #[test]
    fn triple_vsigma() {

        let mut prover_transcript = Transcript::new(b"test example");

        let val1 = Scalar::from(37264829u64);
        let val2 = Scalar::from(372614829u64);
        let val3 = Scalar::from(372614829u64);
        let g = HashGens(3);

        let (proof, commitment) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![val1,val2,val3],
                                                     &g
        ).expect("valid proof inputs");
        //print!("{:#?}", tr);
        let mut verifier_transcript = Transcript::new(b"test example");
        assert!(proof.verify(&mut verifier_transcript, &g, &commitment).is_ok());
    }

    #[test]
    fn triple_wrong_vsigma() {

        let mut prover_transcript = Transcript::new(b"test example");

        let val1 = Scalar::from(37264829u64);
        let val2 = Scalar::from(372614829u64);
        let val3 = Scalar::from(372614828u64);
        let g = HashGens(3);

        let (proof, commitment) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![val1,val2,val3],
                                                     &g
        ).expect("valid proof inputs");
        //print!("{:#?}", tr);
        let mut verifier_transcript = Transcript::new(b"test example");
        assert!(proof.verify(&mut verifier_transcript, &g, &commitment).is_err());
    }

}