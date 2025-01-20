use serde::{Serialize, Deserialize};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

use crate::utils::cert::{get_crl_uri, is_cert_revoked, parse_x509_der_multi, pem_to_der};

use super::{collaterals::IntelCollateral, ValidityIntersection};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxExtensionTcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
    pub cpusvn: [u8; 16]
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SgxExtensions {
    pub ppid: [u8; 16],
    pub tcb: SgxExtensionTcbLevel,
    pub pceid: [u8; 2],
    pub fmspc: [u8; 6],
    pub sgx_type: u32,
    pub platform_instance_id: Option<[u8; 16]>,
    pub configuration: Option<PckPlatformConfiguration>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PckPlatformConfiguration {
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

#[derive(Debug)]
pub struct IntelSgxCrls<'a> {
    pub sgx_root_ca_crl: Option<CertificateRevocationList<'a>>,
    pub sgx_pck_processor_crl: Option<CertificateRevocationList<'a>>,
    pub sgx_pck_platform_crl: Option<CertificateRevocationList<'a>>,
}

impl<'a> IntelSgxCrls<'a> {
    pub fn new(sgx_root_ca_crl: Option<CertificateRevocationList<'a>>, sgx_pck_processor_crl: Option<CertificateRevocationList<'a>>, sgx_pck_platform_crl: Option<CertificateRevocationList<'a>>) -> Self {
        Self {
            sgx_root_ca_crl,
            sgx_pck_processor_crl,
            sgx_pck_platform_crl,
        }
    }

    pub fn from_collaterals(collaterals: &'a IntelCollateral) -> Self {
        let sgx_root_ca_crl = collaterals.get_sgx_intel_root_ca_crl();
        let sgx_pck_processor_crl = collaterals.get_sgx_pck_processor_crl();
        let sgx_pck_platform_crl = collaterals.get_sgx_pck_platform_crl();

        Self::new(sgx_root_ca_crl, sgx_pck_processor_crl, sgx_pck_platform_crl)
    }

    pub fn is_cert_revoked(&self, cert: &X509Certificate) -> bool {
        let crl = match get_crl_uri(cert) {
            Some(crl_uri) => {
                if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform")
                    || crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform") {
                    self.sgx_pck_platform_crl.as_ref()
                } else if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=processor")
                    || crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor") {
                    self.sgx_pck_processor_crl.as_ref()
                } else if crl_uri.contains("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der") {
                    self.sgx_root_ca_crl.as_ref()
                } else {
                    panic!("Unknown CRL URI: {}", crl_uri);
                }
            },
            None => {
                panic!("No CRL URI found in certificate");
            }
        }.unwrap();

        // check if the cert is revoked given the crl
        is_cert_revoked(cert, crl)
    }

    pub fn validity_intersection(&self) -> ValidityIntersection {
        let mut max_last_update = i64::MIN;
        let mut min_next_update = i64::MAX;
        for crl in [
            self.sgx_root_ca_crl.as_ref(),
            self.sgx_pck_processor_crl.as_ref(),
            self.sgx_pck_platform_crl.as_ref(),
        ] {
            if let Some(crl) = crl {
                let last_update = crl.last_update().timestamp();
                if last_update > max_last_update {
                    max_last_update = last_update;
                }
                if let Some(next_update) = crl.next_update().map(|t| t.timestamp()) {
                    if next_update < min_next_update {
                        min_next_update = next_update;
                    }
                }
            }
        }
        ValidityIntersection {
            validity_not_before_max: max_last_update.try_into().unwrap(),
            validity_not_after_min: min_next_update.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Certificates {
    pub certs_der: Vec<u8>,
}

impl Certificates {
    pub fn from_der(certs_der: &[u8]) -> Self {
        Self {
            certs_der: certs_der.to_vec(),
        }
    }

    pub fn from_pem(pem_bytes: &[u8]) -> Self {
        let certs_der = pem_to_der(pem_bytes);
        Self::from_der(&certs_der)
    }

    pub fn get_certs(&self) -> Vec<X509Certificate> {
        let certs = parse_x509_der_multi(&self.certs_der);
        certs
    }
}