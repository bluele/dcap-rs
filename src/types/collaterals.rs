use super::enclave_identity::EnclaveIdentityV2;
use super::tcbinfo::TcbInfoV3;
use crate::utils::cert::{parse_crl_der, parse_x509_der};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

#[derive(Clone, Debug)]
pub struct IntelCollateral {
    pub tcbinfo_bytes: Vec<u8>,
    pub qeidentity_bytes: Vec<u8>,
    pub sgx_intel_root_ca_der: Vec<u8>,
    pub sgx_tcb_signing_der: Vec<u8>,
    pub sgx_intel_root_ca_crl_der: Vec<u8>,
    pub sgx_pck_crl_der: Vec<u8>,
}

impl IntelCollateral {
    pub fn to_bytes(&self) -> Vec<u8> {
        // serialization scheme is simple: the bytestream is made of 2 parts
        // the first contains a u32 length for each of the members
        // the second contains the actual data
        // [lengths of each of the member][data segment]

        // get the total length
        let total_length = 4 * 6
            + self.tcbinfo_bytes.len()
            + self.qeidentity_bytes.len()
            + self.sgx_intel_root_ca_der.len()
            + self.sgx_tcb_signing_der.len()
            + self.sgx_intel_root_ca_crl_der.len()
            + self.sgx_pck_crl_der.len();

        // create the vec and copy the data
        let mut data = Vec::with_capacity(total_length);
        data.extend_from_slice(&(self.tcbinfo_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.qeidentity_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_intel_root_ca_der.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_tcb_signing_der.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_intel_root_ca_crl_der.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_pck_crl_der.len() as u32).to_le_bytes());

        data.extend_from_slice(&self.tcbinfo_bytes);
        data.extend_from_slice(&self.qeidentity_bytes);
        data.extend_from_slice(&self.sgx_intel_root_ca_der);
        data.extend_from_slice(&self.sgx_tcb_signing_der);
        data.extend_from_slice(&self.sgx_intel_root_ca_crl_der);
        data.extend_from_slice(&self.sgx_pck_crl_der);

        data
    }

    pub fn from_bytes(slice: &[u8]) -> Self {
        // reverse the serialization process
        // each length is 4 bytes long, we have a total of 6 members
        let tcbinfo_bytes_len = u32::from_le_bytes(slice[0..4].try_into().unwrap()) as usize;
        let qeidentity_bytes_len = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize;
        let sgx_intel_root_ca_der_len =
            u32::from_le_bytes(slice[8..12].try_into().unwrap()) as usize;
        let sgx_tcb_signing_der_len =
            u32::from_le_bytes(slice[12..16].try_into().unwrap()) as usize;
        let sgx_intel_root_ca_crl_der_len =
            u32::from_le_bytes(slice[16..20].try_into().unwrap()) as usize;
        let sgx_pck_crl_der_len = u32::from_le_bytes(slice[20..24].try_into().unwrap()) as usize;

        let mut offset = 4 * 6 as usize;

        let tcbinfo_bytes = slice[offset..offset + tcbinfo_bytes_len].to_vec();
        offset += tcbinfo_bytes_len;
        let qeidentity_bytes = slice[offset..offset + qeidentity_bytes_len].to_vec();
        offset += qeidentity_bytes_len;
        let sgx_intel_root_ca_der = slice[offset..offset + sgx_intel_root_ca_der_len].to_vec();
        offset += sgx_intel_root_ca_der_len;
        let sgx_tcb_signing_der = slice[offset..offset + sgx_tcb_signing_der_len].to_vec();
        offset += sgx_tcb_signing_der_len;
        let sgx_intel_root_ca_crl_der =
            slice[offset..offset + sgx_intel_root_ca_crl_der_len].to_vec();
        offset += sgx_intel_root_ca_crl_der_len;
        let sgx_pck_crl_der = slice[offset..offset + sgx_pck_crl_der_len].to_vec();
        offset += sgx_pck_crl_der_len;

        assert!(offset == slice.len());

        IntelCollateral {
            tcbinfo_bytes,
            qeidentity_bytes,
            sgx_intel_root_ca_der,
            sgx_tcb_signing_der,
            sgx_intel_root_ca_crl_der,
            sgx_pck_crl_der,
        }
    }

    pub fn get_tcbinfov3(&self) -> TcbInfoV3 {
        let tcbinfo: TcbInfoV3 = serde_json::from_slice(&self.tcbinfo_bytes).unwrap();
        assert_eq!(tcbinfo.tcb_info.version, 3);
        tcbinfo
    }

    pub fn get_qeidentityv2(&self) -> EnclaveIdentityV2 {
        serde_json::from_slice(&self.qeidentity_bytes).unwrap()
    }

    pub fn get_sgx_intel_root_ca<'a>(&'a self) -> X509Certificate<'a> {
        parse_x509_der(&self.sgx_intel_root_ca_der)
    }

    pub fn get_sgx_tcb_signing<'a>(&'a self) -> X509Certificate<'a> {
        parse_x509_der(&self.sgx_tcb_signing_der)
    }

    pub fn get_sgx_intel_root_ca_crl<'a>(&'a self) -> CertificateRevocationList<'a> {
        parse_crl_der(&self.sgx_intel_root_ca_crl_der)
    }

    pub fn get_sgx_pck_crl<'a>(&'a self) -> CertificateRevocationList<'a> {
        parse_crl_der(&self.sgx_pck_crl_der)
    }
}
