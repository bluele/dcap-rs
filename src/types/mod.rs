use self::quotes::body::*;
use crate::{constants::{ENCLAVE_REPORT_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE}, utils::hash::keccak256sum};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

pub mod cert;
pub mod collaterals;
pub mod enclave_identity;
pub mod quotes;
pub mod tcbinfo;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcbStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized,
}

impl TcbStatus {
    pub fn from_str(s: &str) -> Self {
        return match s {
            "UpToDate" => TcbStatus::OK,
            "SWHardeningNeeded" => TcbStatus::TcbSwHardeningNeeded,
            "ConfigurationAndSWHardeningNeeded" => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
            "ConfigurationNeeded" => TcbStatus::TcbConfigurationNeeded,
            "OutOfDate" => TcbStatus::TcbOutOfDate,
            "OutOfDateConfigurationNeeded" => TcbStatus::TcbOutOfDateConfigurationNeeded,
            "Revoked" => TcbStatus::TcbRevoked,
            _ => TcbStatus::TcbUnrecognized,
        };
    }
}

impl ToString for TcbStatus {
    fn to_string(&self) -> String {
        return match self {
            TcbStatus::OK => "UpToDate".to_string(),
            TcbStatus::TcbSwHardeningNeeded => "SWHardeningNeeded".to_string(),
            TcbStatus::TcbConfigurationAndSwHardeningNeeded => {
                "ConfigurationAndSWHardeningNeeded".to_string()
            }
            TcbStatus::TcbConfigurationNeeded => "ConfigurationNeeded".to_string(),
            TcbStatus::TcbOutOfDate => "OutOfDate".to_string(),
            TcbStatus::TcbOutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded".to_string(),
            TcbStatus::TcbRevoked => "Revoked".to_string(),
            TcbStatus::TcbUnrecognized => "Unrecognized".to_string(),
        };
    }
}

// serialization:
// [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes]
// 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584)
// total: 13 + var bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: TcbStatus,
    pub fmspc: [u8; 6],
    pub quote_body: QuoteBody,
    pub advisory_ids: Option<Vec<String>>,
}

impl VerifiedOutput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output_vec = Vec::new();

        output_vec.extend_from_slice(&self.quote_version.to_be_bytes());
        output_vec.extend_from_slice(&self.tee_type.to_be_bytes());
        output_vec.push(match self.tcb_status {
            TcbStatus::OK => 0,
            TcbStatus::TcbSwHardeningNeeded => 1,
            TcbStatus::TcbConfigurationAndSwHardeningNeeded => 2,
            TcbStatus::TcbConfigurationNeeded => 3,
            TcbStatus::TcbOutOfDate => 4,
            TcbStatus::TcbOutOfDateConfigurationNeeded => 5,
            TcbStatus::TcbRevoked => 6,
            TcbStatus::TcbUnrecognized => 7,
        });
        output_vec.extend_from_slice(&self.fmspc);

        match self.quote_body {
            QuoteBody::SGXQuoteBody(body) => {
                output_vec.extend_from_slice(&body.to_bytes());
            }
            QuoteBody::TD10QuoteBody(body) => {
                output_vec.extend_from_slice(&body.to_bytes());
            }
        }

        if let Some(advisory_ids) = self.advisory_ids.as_ref() {
            let encoded = advisory_ids.abi_encode();
            output_vec.extend_from_slice(encoded.as_slice());
        }

        output_vec
    }

    pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
        let mut quote_version = [0; 2];
        quote_version.copy_from_slice(&slice[0..2]);
        let mut tee_type = [0; 4];
        tee_type.copy_from_slice(&slice[2..6]);
        let tcb_status = match slice[6] {
            0 => TcbStatus::OK,
            1 => TcbStatus::TcbSwHardeningNeeded,
            2 => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
            3 => TcbStatus::TcbConfigurationNeeded,
            4 => TcbStatus::TcbOutOfDate,
            5 => TcbStatus::TcbOutOfDateConfigurationNeeded,
            6 => TcbStatus::TcbRevoked,
            7 => TcbStatus::TcbUnrecognized,
            _ => panic!("Invalid TCB Status"),
        };
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[7..13]);

        let mut offset = 13usize;
        let quote_body = match u32::from_be_bytes(tee_type) {
            SGX_TEE_TYPE => {
                let raw_quote_body = &slice[offset..offset + ENCLAVE_REPORT_LEN];
                offset += ENCLAVE_REPORT_LEN;
                QuoteBody::SGXQuoteBody(EnclaveReport::from_bytes(raw_quote_body))
            }
            TDX_TEE_TYPE => {
                let raw_quote_body = &slice[offset..offset + TD10_REPORT_LEN];
                offset += TD10_REPORT_LEN;
                QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(raw_quote_body))
            }
            _ => panic!("unknown TEE type"),
        };

        let mut advisory_ids = None;
        if offset < slice.len() {
            let advisory_ids_slice = &slice[offset..];
            advisory_ids = Some(<Vec<String>>::abi_decode(advisory_ids_slice, true).unwrap());
        }

        VerifiedOutput {
            quote_version: u16::from_be_bytes(quote_version),
            tee_type: u32::from_be_bytes(tee_type),
            tcb_status,
            fmspc,
            quote_body,
            advisory_ids,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DCAPVerifierCommit {
    pub attestation_time: u64,
    pub sgx_intel_root_ca_hash: [u8; 32],
    pub output: VerifiedOutput,
}

impl DCAPVerifierCommit {
    pub fn new(attestation_time: u64, output: VerifiedOutput, sgx_intel_root_ca: &[u8]) -> Self {
        Self {
            attestation_time,
            sgx_intel_root_ca_hash: keccak256sum(sgx_intel_root_ca),
            output,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = self.output.to_bytes();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.attestation_time.to_le_bytes());
        bytes.extend_from_slice(&self.sgx_intel_root_ca_hash);
        bytes.append(&mut output);
        bytes
    }

    pub fn from_bytes(slice: &[u8]) -> Self {
        let mut attestation_time = [0; 8];
        attestation_time.copy_from_slice(&slice[0..8]);
        let mut sgx_intel_root_ca_hash = [0; 32];
        sgx_intel_root_ca_hash.copy_from_slice(&slice[8..40]);
        let output = VerifiedOutput::from_bytes(&slice[40..]);
        Self {
            attestation_time: u64::from_le_bytes(attestation_time),
            sgx_intel_root_ca_hash,
            output,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        keccak256sum(&self.to_bytes())
    }
}
