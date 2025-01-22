use crate::types::tcbinfo::TcbInfoV3;
use crate::types::ValidityIntersection;
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::X509Certificate;

pub fn validate_tcbinfov3(
    tcbinfov3: &TcbInfoV3,
    sgx_signing_cert: &X509Certificate,
    current_time: u64,
) -> Option<ValidityIntersection> {
    let issue_date_seconds = tcbinfov3
        .tcb_info
        .issue_date()
        .unwrap()
        .timestamp()
        .try_into()
        .unwrap();
    let next_update_seconds = tcbinfov3
        .tcb_info
        .next_update()
        .unwrap()
        .timestamp()
        .try_into()
        .unwrap();

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        return None;
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let tcbinfov3_signature_bytes = hex::decode(&tcbinfov3.signature).unwrap();

    // verify that the tcb_info_root is signed by the root cert
    let tcbinfov3_signature_data = serde_json::to_vec(&tcbinfov3.tcb_info).unwrap();
    if verify_p256_signature_bytes(
        &tcbinfov3_signature_data,
        &tcbinfov3_signature_bytes,
        sgx_signing_cert.public_key().subject_public_key.as_ref(),
    ) {
        Some(ValidityIntersection {
            validity_not_before_max: issue_date_seconds,
            validity_not_after_min: next_update_seconds,
        })
    } else {
        None
    }
}
