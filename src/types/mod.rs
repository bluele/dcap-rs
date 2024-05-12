use serde::{Serialize, Deserialize};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

use crate::utils::cert::{parse_der, parse_der_multi, pem_to_der};

use self::{enclave_identity::EnclaveIdentityV2, tcbinfo::TcbInfoV2};

pub mod quote;
pub mod tcbinfo;
pub mod enclave_identity;
pub mod cert;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TcbStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized
}

#[derive(Clone, Debug)]
pub struct IntelCollateralV3 {
    pub tcbinfov2: Option<TcbInfoV2>,
    pub qe_identityv2: Option<EnclaveIdentityV2>,
    pub intel_root_ca_der: Option<Vec<u8>>,
    pub sgx_tcb_signing_der: Option<Vec<u8>>,
    pub sgx_pck_certchain_der: Option<Vec<u8>>,
    pub sgx_intel_root_ca_crl_der: Option<Vec<u8>>,
    pub sgx_pck_processor_crl_der: Option<Vec<u8>>,
    pub sgx_pck_platform_crl_der: Option<Vec<u8>>,
}

// builder pattern for IntelCollateralV3
impl IntelCollateralV3 {
    pub fn new() -> IntelCollateralV3 {
        IntelCollateralV3 {
            tcbinfov2: None,
            qe_identityv2: None,
            intel_root_ca_der: None,
            sgx_tcb_signing_der: None,
            sgx_pck_certchain_der: None,
            sgx_intel_root_ca_crl_der: None,
            sgx_pck_processor_crl_der: None,
            sgx_pck_platform_crl_der: None,
        }
    }

    pub fn set_tcbinfov2(&mut self, tcbinfov2_slice: &[u8]) {
        self.tcbinfov2 = serde_json::from_slice(tcbinfov2_slice).unwrap();
    }

    pub fn set_qeidentityv2(&mut self, qeidentityv2_slice: &[u8]) {
        self.qe_identityv2 = serde_json::from_slice(qeidentityv2_slice).unwrap();
    }

    pub fn get_intel_root_ca<'a>(&'a self) -> X509Certificate<'a> {
        match self.intel_root_ca_der {
            Some(ref der) => {
                let cert = parse_der(der);
                cert
            },
            None => panic!("Intel Root CA not set"),
        }
    }

    pub fn set_intel_root_ca_der(&mut self, intel_root_ca_der: &[u8]) {
        self.intel_root_ca_der = Some(intel_root_ca_der.to_vec());
    }

    pub fn get_sgx_tcb_signing<'a>(&'a self) -> X509Certificate<'a> {
        match self.sgx_tcb_signing_der {
            Some(ref der) => {
                let cert = parse_der(der);
                cert
            },
            None => panic!("SGX TCB Signing Cert not set"),
        }
    }

    pub fn set_sgx_tcb_signing_der(&mut self, sgx_tcb_signing_der: &[u8]) {
        self.sgx_tcb_signing_der = Some(sgx_tcb_signing_der.to_vec());
    }

    pub fn set_sgx_tcb_signing_pem(&mut self, sgx_tcb_signing_pem: &[u8]) {
        // convert pem to der
        let sgx_tcb_signing_der = pem_to_der(sgx_tcb_signing_pem);
        self.sgx_tcb_signing_der = Some(sgx_tcb_signing_der);
    }

    pub fn get_sgx_pck_certchain<'a>(&'a self) -> Option<Vec<X509Certificate<'a>>> {
        match &self.sgx_pck_certchain_der {
            Some(certchain_der) => {
                let certchain = parse_der_multi(certchain_der);
                Some(certchain)
            },
            None => None,
        }
    }

    pub fn set_sgx_pck_certchain_der(&mut self, sgx_pck_certchain_der: Option<&[u8]>) {
        match sgx_pck_certchain_der {
            Some(certchain_der) => {
                self.sgx_pck_certchain_der = Some(certchain_der.to_vec());
            },
            None => {
                self.sgx_pck_certchain_der = None;
            },
        }
    }

    pub fn set_sgx_pck_certchain_pem(&mut self, sgx_pck_certchain_pem: Option<&[u8]>) {
        match sgx_pck_certchain_pem {
            Some(certchain_pem) => {
                // convert pem to der
                let sgx_pck_certchain_der = pem_to_der(certchain_pem);
                self.sgx_pck_certchain_der = Some(sgx_pck_certchain_der);
            },
            None => {
                self.sgx_pck_certchain_der = None;
            },
        }
    }

    pub fn set_sgx_processor_crl_der(&mut self, sgx_pck_processor_crl_der: &[u8]) {
        self.sgx_pck_processor_crl_der = Some(sgx_pck_processor_crl_der.to_vec());
    }
}

// serialization:
// [tcb_status] [mr_enclave] [mr_signer] [report_data]
// [ 1 byte   ] [32 bytes  ] [32 bytes ] [64 bytes   ]
// total: 129 bytes
#[derive(Clone, Debug)]
pub struct VerifiedOutput {
    pub tcb_status: TcbStatus,
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub report_data: [u8; 64],
    pub fmspc: [u8; 6],
}

impl VerifiedOutput {
    pub fn to_bytes(self) -> [u8; 135] {
        let mut raw_bytes = [0; 135];
        raw_bytes[0] = match self.tcb_status {
            TcbStatus::OK => 0,
            TcbStatus::TcbSwHardeningNeeded => 1,
            TcbStatus::TcbConfigurationAndSwHardeningNeeded => 2,
            TcbStatus::TcbConfigurationNeeded => 3,
            TcbStatus::TcbOutOfDate => 4,
            TcbStatus::TcbOutOfDateConfigurationNeeded => 5,
            TcbStatus::TcbRevoked => 6,
            TcbStatus::TcbUnrecognized => 7,
        };
        raw_bytes[1..33].copy_from_slice(&self.mr_enclave);
        raw_bytes[33..65].copy_from_slice(&self.mr_signer);
        raw_bytes[65..129].copy_from_slice(&self.report_data);
        raw_bytes[129..135].copy_from_slice(&self.fmspc);

        raw_bytes
    }

    pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
        let tcb_status = match slice[0] {
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
        let mut mr_enclave = [0; 32];
        mr_enclave.copy_from_slice(&slice[1..33]);
        let mut mr_signer = [0; 32];
        mr_signer.copy_from_slice(&slice[33..65]);
        let mut report_data= [0; 64];
        report_data.copy_from_slice(&slice[65..129]);
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[129..135]);

        VerifiedOutput {
            tcb_status,
            mr_enclave,
            mr_signer,
            report_data,
            fmspc,
        }
    }
    
}
