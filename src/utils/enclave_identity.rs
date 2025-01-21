use crate::types::{
    enclave_identity::EnclaveIdentityV2, quotes::body::EnclaveReport, TcbStatus,
    ValidityIntersection,
};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::X509Certificate;

pub fn validate_enclave_identityv2(
    enclave_identityv2: &EnclaveIdentityV2,
    sgx_signing_pubkey: &X509Certificate,
    current_time: u64,
) -> Option<ValidityIntersection> {
    let issue_date_seconds = enclave_identityv2
        .enclave_identity
        .issue_date()
        .unwrap()
        .timestamp()
        .try_into()
        .unwrap();
    let next_update_seconds = enclave_identityv2
        .enclave_identity
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
    let enclave_identityv2_signature_bytes = hex::decode(&enclave_identityv2.signature).unwrap();

    // verify that the enclave_identity_root is signed by the root cert
    let enclave_identityv2_signature_data =
        serde_json::to_vec(&enclave_identityv2.enclave_identity).unwrap();
    if verify_p256_signature_bytes(
        &enclave_identityv2_signature_data,
        &enclave_identityv2_signature_bytes,
        sgx_signing_pubkey.public_key().subject_public_key.as_ref(),
    ) {
        Some(ValidityIntersection {
            validity_not_before_max: issue_date_seconds,
            validity_not_after_min: next_update_seconds,
        })
    } else {
        None
    }
}

pub fn get_qe_tcbstatus(
    enclave_report: &EnclaveReport,
    qeidentityv2: &EnclaveIdentityV2,
) -> TcbStatus {
    for tcb_level in qeidentityv2.enclave_identity.tcb_levels.iter() {
        if tcb_level.tcb.isvsvn <= enclave_report.isv_svn {
            let tcb_status = match &tcb_level.tcb_status[..] {
                "UpToDate" => TcbStatus::OK,
                "SWHardeningNeeded" => TcbStatus::TcbSwHardeningNeeded,
                "ConfigurationAndSWHardeningNeeded" => {
                    TcbStatus::TcbConfigurationAndSwHardeningNeeded
                }
                "ConfigurationNeeded" => TcbStatus::TcbConfigurationNeeded,
                "OutOfDate" => TcbStatus::TcbOutOfDate,
                "OutOfDateConfigurationNeeded" => TcbStatus::TcbOutOfDateConfigurationNeeded,
                "Revoked" => TcbStatus::TcbRevoked,
                _ => TcbStatus::TcbUnrecognized,
            };
            return tcb_status;
        }
    }

    TcbStatus::TcbUnrecognized
}
