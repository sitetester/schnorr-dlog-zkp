mod serialization;
mod dlog_proof;

use crate::dlog_proof::DLogProof;
use elliptic_curve::{Field};
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
use std::time::Instant;

/// Discrete Logarithm Zero-Knowledge Proof System
///
/// It implements a non-interactive Schnorr zero-knowledge proof system
/// for discrete logarithms on the secp256k1 curve
///
/// The system proves knowledge of a secret value x (the discrete logarithm)
/// satisfying y = x * G, where:
/// - g is the generator point (base point)
/// - y is the public point
/// - x is the secret scalar
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Base point of secp256k1 curve
    let base_point = ProjectivePoint::GENERATOR;

    // Session identifier for domain separation in the proof (any string value)
    let sid = "sid";

    // Participant ID, make proofs distinct when using the same session ID
    // Just an additional input to the hash function
    let pid = 1;

    // Generate a random secret scalar (private key) using OS random number generator
    let x = Scalar::random(&mut OsRng);
    println!("Random secret: {:#?}", x);

    // Calculate the public point y = x * G where G is the base point
    let y = base_point * x;

    let proof_start_time = Instant::now();

    // Generate the zero-knowledge proof that we know x such that y = x * G
    let proof = DLogProof::prove(sid, pid, &x, y, base_point)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;
    println!(
        "Proof computation time: {} ms",
        proof_start_time.elapsed().as_millis()
    );

    println!("\nProof values:");
    println!("t: {:#?}", proof.t); // commitment value
    println!("s: {:#?}", proof.s); // proof value

    let verify_start_time = Instant::now();

    // Verify the proof without knowing the secret x
    let result = proof.verify(sid, pid, y, base_point)
        .map_err(|e| format!("Verification failed: {:?}", e))?;
    println!(
        "Verify computation time: {} ms",
        verify_start_time.elapsed().as_millis()
    );

    if result {
        println!("✅ DLOG proof is correct");
    } else {
        println!("❌ DLOG proof is not correct");
    }

    let json = serde_json::to_string(&proof)?;
    println!("Proof JSON: {}", json);

    let parsed_proof: DLogProof = serde_json::from_str(&json)?;
    println!("Parsed Proof: {:#?}", parsed_proof);

    assert_eq!(
        parsed_proof, proof,
        "❌ Parsed proof doesn't match original"
    );
    println!("✅ DLog proof recovered successfully!");

    Ok(())
}