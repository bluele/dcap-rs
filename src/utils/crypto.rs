use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

// verify_p256_signature_bytes verifies a P256 ECDSA signature
// using the provided data, signature, and public key.
// The data is the message that was signed as a byte slice.
// The signature is the signature (in raw form [r][s]) of the data as a byte slice. (64 bytes)
// The public_key is the public key (in uncompressed form [4][x][y]) of the entity that signed the data. (65 bytes)
// Returns true if the signature is valid, false otherwise.
pub fn verify_p256_signature_bytes(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let signature = Signature::from_bytes(signature.try_into().unwrap()).unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key).unwrap();
    verifying_key.verify(data, &signature).is_ok()
}

pub fn verify_p256_signature_der(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let signature = Signature::from_der(signature).unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key).unwrap();
    verifying_key.verify(data, &signature).is_ok()
}
