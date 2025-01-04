mod dlog_proof;
mod serialization;

use crate::dlog_proof::DLogProof;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
use serde::Serialize;
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

    let verify_start_time = Instant::now();
    // Verify the proof without knowing the secret x
    let result = proof
        .verify(sid, pid, y, base_point)
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

    print_proof_in_multiple_formats(&proof);
    Ok(())
}

fn print_proof_in_multiple_formats(proof: &DLogProof) {
    println!("Printing proof...");

    println!("-----Original-----");
    // t:  ProjectivePoint where each x, y & z coordinate (some values on curve) is in `Montgomery Form`
    // (some_value × 2^256 mod p), split in 5 chunks of 52 bits, (where p is a large prime used in the curve)
    // Used internally for efficient calculations (working with big number directly vs small chunks)
    // Why 52 bits - Working with 52 bits leaves room for calculations without overflow for 64-bit numbers
    // Why 5? Since we need to handle 256-bit numbers (52 bits × 5 = 260 bits, still give us enough space (260 > 256))
    // `magnitude`: tells how big the number has grown (e.g., magnitude: 5 means 5 times)
    // `normalized` indicates if the number is in final expected format
    // s: A regular big number
    println!("{:?}", proof);

    println!("-----Affine-----");
    // Standard (x,y) coordinates after normalizing the z-coordinate (computing x/z, y/z)
    // Easier to read, but less efficient for calculations
    let affine = proof.t.to_affine();
    println!("t: {:?}", affine);

    println!("-----HEX-----");
    // Normalized (uncompressed) coordinates in hexadecimal format
    // `false` gives both x,y values
    let encoded = affine.to_encoded_point(false);
    println!("t.x: 0x{}", hex::encode(encoded.x().unwrap()));
    println!("t.y: 0x{}", hex::encode(encoded.y().unwrap()));
    let s_bytes = proof.s.to_bytes();
    println!("s: 0x{}", hex::encode(s_bytes));

    print_proof_json(proof);
}

fn print_proof_json(proof: &DLogProof) {
    println!("-----JSON-----");
    // Compressed format - Uses prefix (02=even y, 03=odd y) + x-coordinate
    let json = serde_json::to_string(&proof).expect("JSON serialization failed");
    println!("Compressed JSON (standard): {}", json);

    // Create a struct for uncompressed format
    #[derive(Serialize)]
    struct UncompressedProof<'a> {
        t: UncompressedPoint<'a>,
        s: &'a str,
    }
    #[derive(Serialize)]
    struct UncompressedPoint<'a> {
        x: &'a str,
        y: &'a str,
    }

    // Create uncompressed JSON representation
    let affine = proof.t.to_affine();
    let encoded = affine.to_encoded_point(false);
    let uncompressed_proof = UncompressedProof {
        t: UncompressedPoint {
            x: &format!("0x{}", hex::encode(encoded.x().unwrap())),
            y: &format!("0x{}", hex::encode(encoded.y().unwrap())),
        },
        s: &format!("0x{}", hex::encode(proof.s.to_bytes())),
    };

    println!("Uncompressed JSON (with both coordinates):");

    // This line uses serialize_point_hex and serialize_scalar_hex internally
    println!(
        "serde_json::to_string: {}",
        serde_json::to_string(&uncompressed_proof).expect("JSON serialization failed")
    );
    println!(
        "serde_json::to_string_pretty: {}",
        serde_json::to_string_pretty(&uncompressed_proof).expect("JSON serialization failed")
    );

    // This line uses deserialize_point_hex and deserialize_scalar_hex internally
    let parsed_proof: DLogProof = serde_json::from_str(&json).expect("JSON deserialization failed");
    println!("Parsed proof from JSON: \n{:?}", parsed_proof);

    assert_eq!(
        parsed_proof, *proof,
        "❌ Parsed proof doesn't match original"
    );
    println!("✅ DLog proof recovered successfully!");
}
