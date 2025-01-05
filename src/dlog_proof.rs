use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::ConstantTimeEq;
use elliptic_curve::{Field, PrimeField};
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::serialization::{
    deserialize_point_hex, deserialize_scalar_hex, serialize_point_hex, serialize_scalar_hex,
};

/// This struct represents a proof that demonstrates the prover knows a secret value x (the discrete logarithm)
///
/// The proof consists of two components:
/// * `t` - The commitment value t = r * G, where
///    - r is a random scalar
///    - G is the base point (generator)
/// * `s` - The proof value s = r + c * x, where
///   - r is a random scalar
///   - c is challenge value
///   - x is the secret scalar that we're proving knowledge of
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DLogProof {
    #[serde(
        serialize_with = "serialize_point_hex",
        deserialize_with = "deserialize_point_hex"
    )]
    pub(crate) t: ProjectivePoint,
    #[serde(
        serialize_with = "serialize_scalar_hex",
        deserialize_with = "deserialize_scalar_hex"
    )]
    pub(crate) s: Scalar,
}

impl DLogProof {
    const DOMAIN_SEPARATOR: &'static [u8] = b"SCHNORR_PROOF";

    /// Computes a challenge using Fiat-Shamir transform
    ///
    /// Creates a challenge by hashing the session ID, participant ID, and a sequence of points.
    /// The challenge is used as 'c' in the verification equation s * G = t + c * y.
    ///
    /// # Arguments
    /// * `sid` - Session identifier for domain separation
    /// * `pid` - Participant ID for uniqueness to distinguish different proofs
    /// * `points` - Sequence of points to be included in the challenge generation
    ///
    /// # Returns
    /// * `Ok(Scalar)` - Challenge scalar derived from the hash
    /// * `Err(String)` - If the hash cannot be converted to a valid scalar
    fn hash_points(sid: &str, pid: u32, points: &[ProjectivePoint]) -> Result<Scalar, String> {
        let mut hasher = Sha256::new();
        // Add domain separation tag to prevent cross-protocol attacks
        hasher.update(Self::DOMAIN_SEPARATOR);
        // Add session ID to bind challenge to specific session
        hasher.update(sid.as_bytes());
        // Add participant ID to bind challenge to specific participant
        hasher.update(pid.to_le_bytes());
        // Include all provided points in the hash
        for point in points {
            hasher.update(point.to_bytes());
        }

        let challenge = hasher.finalize();

        // Attempt to convert hash to scalar for use in verification equation
        let scalar_option: Option<Scalar> = Scalar::from_repr(challenge).into();
        scalar_option.ok_or_else(|| "Failed to convert hash to scalar".to_string())
    }

    /// Creates a Schnorr Zero-Knowledge Proof that demonstrates knowledge of a discrete logarithm.
    ///
    /// This function generates a proof that demonstrate the prover knows the secret value 'x'
    /// without revealing the value of 'x'. This is a non-interactive version using the Fiat-Shamir
    /// transform, which eliminates the need for back-and-forth communication between prover and verifier.
    ///
    /// # Arguments
    /// * `sid` - Session identifier string used for domain separation
    /// * `pid` - Participant ID for uniqueness to distinguish different proofs
    /// * `x` - The secret scalar (private key) that we're proving knowledge of
    /// * `y` - The public point, must satisfy y = x * G
    /// * `base_point` - Base point of secp256k1 curve
    ///
    /// # Returns
    /// * `Ok(DLogProof)` - A proof consisting of (t, s) values if successful
    /// * `Err(String)` - An error message if proof generation fails
    pub fn prove(
        sid: &str,
        pid: u32,
        x: &Scalar,
        y: ProjectivePoint,
        base_point: ProjectivePoint,
    ) -> Result<Self, String> {
        // Step 1: Generate random scalar r (the commitment randomness)
        // The random r ensures that multiple proofs of the same secret x look completely different
        let r = Scalar::random(&mut OsRng);

        // Step 2: Compute the commitment t = r * G
        let t = base_point * r;

        // Step 3: Compute the challenge c using Fiat-Shamir transform
        // This makes the proof non-interactive (instead of Verifier sending challenge (interactive)),
        // by deriving the challenge from the hash of all public values
        let c = Self::hash_points(sid, pid, &[base_point, y, t])?;

        // Step 4: Compute the proof value s = r + c * x
        // This allows the verifier to check the proof without knowing x
        // Note: Numbers are converted to Montgomery form,
        // i.e., results are automatically reduced mod q, so they are never larger than q,
        // where q is the curve order (number of points on the elliptic curve)
        let s = r + (c * x);

        // Finally return the proof with the commitment t and the proof value s
        Ok(DLogProof { t, s })
    }

    /// Verifies a Schnorr Zero-Knowledge Proof
    ///
    /// This function verifies that the prover knows a secret value 'x' but the secret itself is
    /// never revealed during the verification process.
    ///
    /// The verification uses only public information & the proof values (t, s) provided by the prover.
    /// It checks if the proof satisfies the equation: s * G = t + c * y
    ///
    /// # Arguments
    /// * `sid` - Session identifier (must match the one used in proof generation)
    /// * `pid` - Participant ID (must match the one used in proof generation)
    /// * `y` - The public point to verify against (y = x * G)
    /// * `base_point` - Base point of secp256k1 curve
    ///
    /// # Returns
    /// * `Ok(bool)` - Validity of proof, indicating whether the prover knows the secret value x
    /// * `Err(String)` - Any error during verification
    pub fn verify(
        &self,
        sid: &str,
        pid: u32,
        y: ProjectivePoint,
        base_point: ProjectivePoint,
    ) -> Result<bool, String> {
        // Recompute challenge c using Fiat-Shamir transform
        let c = Self::hash_points(sid, pid, &[base_point, y, self.t])?;

        // Compute left side of verification equation: s * G
        let lhs = base_point * self.s;

        // Compute right side of verification equation: t + c * y
        let rhs = self.t + (y * c);

        // Constant time equality comparison to prevent timing attacks
        Ok(lhs.ct_eq(&rhs).into())
    }
}
