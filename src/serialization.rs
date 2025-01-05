use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hex::{decode, encode};
use k256::{elliptic_curve::PrimeField, AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::Deserialize;

/// Serializes a ProjectivePoint to a hex string in compressed SEC1 (Standards for Efficient Cryptography 1) format
/// SEC1 format is a standard for representing elliptic curve points.
/// Format:
///  - Uncompressed: 0x04 + x_coordinate + y_coordinate (65 bytes total)
///  - Compressed:   (0x02 or 0x03) + x_coordinate (33 bytes total)
///    02 (if y is even), 03 (if y is odd)
pub(crate) fn serialize_point_hex<S>(point: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Convert to (x,y) coordinates
    let affine = point.to_affine();
    // `true` means use compressed format
    let encoded_point = affine.to_encoded_point(true);
    let bytes = encoded_point.as_bytes();
    let hex = encode(bytes);

    serializer.serialize_str(&hex)
}

/// Deserializes a hex string in SEC1 format back to ProjectivePoint
pub(crate) fn deserialize_point_hex<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: String = String::deserialize(deserializer)?;
    let bytes = decode(&hex_str)
        .map_err(|_| serde::de::Error::custom("Invalid hex encoding"))?;

    // Parse bytes as SEC1 encoded point, then convert to AffinePoint
    let affine = AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(&bytes)
        .map_err(|_| serde::de::Error::custom("Invalid point bytes"))?);

    // Convert to ProjectivePoint if valid
    if affine.is_some().into() {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        Err(serde::de::Error::custom("Invalid point encoding"))
    }
}

/// Serializes a Scalar (field element) to hex string
pub(crate) fn serialize_scalar_hex<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let repr = scalar.to_repr();
    let hex = encode::<&[u8]>(repr.as_ref());

    // Serialize as string
    serializer.serialize_str(&hex)
}

/// Deserializes a hex string back to a Scalar
pub(crate) fn deserialize_scalar_hex<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: String = String::deserialize(deserializer)?;
    let bytes = decode(&hex_str)
        .map_err(|_| serde::de::Error::custom("Invalid hex encoding"))?;

    // Ensure bytes are exactly 32 bytes (256 bits)
    let bytes_array: [u8; 32] = bytes.try_into()
        .map_err(|_| serde::de::Error::custom("Invalid length for Scalar"))?;

    // Convert bytes to Scalar
    Option::from(Scalar::from_repr(FieldBytes::from(bytes_array)))
        .ok_or_else(|| serde::de::Error::custom("Invalid Scalar value"))
}
