use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hex::{decode, encode};
use k256::{elliptic_curve::PrimeField, FieldBytes, ProjectivePoint, Scalar};
use serde::Deserialize;

pub(crate) fn serialize_point_hex<S>(point: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let affine = point.to_affine();
    let encoded_point = affine.to_encoded_point(true);
    let bytes = encoded_point.as_bytes();
    let hex = encode(bytes);

    serializer.serialize_str(&hex)
}

pub(crate) fn deserialize_point_hex<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: String = String::deserialize(deserializer)?;
    let bytes = decode(&hex_str)
        .map_err(|_| serde::de::Error::custom("Invalid hex encoding"))?;

    let affine = k256::AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(&bytes)
        .map_err(|_| serde::de::Error::custom("Invalid point bytes"))?);

    if affine.is_some().into() {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        Err(serde::de::Error::custom("Invalid point encoding"))
    }
}

pub(crate) fn serialize_scalar_hex<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let repr = scalar.to_repr();
    let hex = encode::<&[u8]>(repr.as_ref());

    serializer.serialize_str(&hex)
}

pub(crate) fn deserialize_scalar_hex<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: String = String::deserialize(deserializer)?;
    let bytes = decode(&hex_str)
        .map_err(|_| serde::de::Error::custom("Invalid hex encoding"))?;

    let bytes_array: [u8; 32] = bytes.try_into()
        .map_err(|_| serde::de::Error::custom("Invalid length for Scalar"))?;

    Option::from(Scalar::from_repr(FieldBytes::from(bytes_array)))
        .ok_or_else(|| serde::de::Error::custom("Invalid Scalar value"))
}
