use merlin::Transcript;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use crate::external::transcript::{ProofError, TranscriptProtocol};
use crate::vsigma::VSigmaProof;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

pub trait Signature: Sized{
    fn sign(secret_key: &Scalar, msg: &RistrettoPoint) -> Result<Self, ProofError>;
    fn verify(&self, public_key: &RistrettoPoint, msg: &RistrettoPoint) -> Result<(), ProofError>;
}

#[derive(Debug, Default, Hash, Clone)]
pub struct Schnorr{
    sig: VSigmaProof
}

impl Signature for Schnorr {
    fn sign(secret_key: &Scalar, msg: &RistrettoPoint) -> Result<Self, ProofError> {
        let mut prover_transcript = Transcript::new(b"schnorr sig");
        prover_transcript.append_point(b"message",&msg.compress());
        let (proof, _) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![*secret_key],
                                                     &vec![RISTRETTO_BASEPOINT_POINT]
        ).expect("valid proof inputs");
        Ok(Schnorr{sig:proof})
    }

    fn verify(&self, public_key: &RistrettoPoint, msg: &RistrettoPoint) -> Result<(), ProofError> {
        let mut verifier_transcript = Transcript::new(b"schnorr sig");
        verifier_transcript.append_point(b"message",&msg.compress());
        match self.sig.verify(&mut verifier_transcript, &vec![RISTRETTO_BASEPOINT_POINT], &public_key) {
            Ok(_) => Ok(()),
            _ => Err(ProofError::VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;
    use crate::signature::{Schnorr, Signature};
    use curve25519_dalek::ristretto::RistrettoPoint;

    #[test]
    fn sign_verify() {

        let mut csprng = thread_rng();
        let sk = Scalar::random(&mut csprng);
        let msg = RistrettoPoint::random(&mut csprng);
        let sig = Schnorr::sign(&sk,&msg).expect("should not fail");
        assert!(sig.verify(&(sk*RISTRETTO_BASEPOINT_POINT), &msg).is_ok())
    }

}