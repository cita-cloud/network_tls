// Copyright Joseph Birr-Pixton <jpixton@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tokio_rustls::rustls::internal::msgs::handshake::DistinguishedName;
use tokio_rustls::rustls::{Certificate, DistinguishedNames};
use tokio_rustls::webpki;

/// A trust anchor, commonly known as a "Root Certificate."
#[derive(Debug, Clone)]
pub struct OwnedTrustAnchor {
    subject: Vec<u8>,
    spki: Vec<u8>,
    name_constraints: Option<Vec<u8>>,
}

impl OwnedTrustAnchor {
    /// Get a `webpki::TrustAnchor` by borrowing the owned elements.
    pub(crate) fn to_trust_anchor(&self) -> webpki::TrustAnchor {
        webpki::TrustAnchor {
            subject: &self.subject,
            spki: &self.spki,
            name_constraints: self.name_constraints.as_deref(),
        }
    }

    /// Constructs an `OwnedTrustAnchor` from its components.
    ///
    /// `subject` is the subject field of the trust anchor.
    ///
    /// `spki` is the `subjectPublicKeyInfo` field of the trust anchor.
    ///
    /// `name_constraints` is the value of a DER-encoded name constraints to
    /// apply for this trust anchor, if any.
    pub fn from_subject_spki_name_constraints(
        subject: impl Into<Vec<u8>>,
        spki: impl Into<Vec<u8>>,
        name_constraints: Option<impl Into<Vec<u8>>>,
    ) -> Self {
        Self {
            subject: subject.into(),
            spki: spki.into(),
            name_constraints: name_constraints.map(|x| x.into()),
        }
    }
}

/// A container for root certificates able to provide a root-of-trust
/// for connection authentication.
#[derive(Debug, Clone)]
pub struct RootCertStore {
    /// The list of roots.
    pub roots: Vec<OwnedTrustAnchor>,
}

impl RootCertStore {
    /// Make a new, empty `RootCertStore`.
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Return the Subject Names for certificates in the container.
    pub fn subjects(&self) -> DistinguishedNames {
        let mut r = DistinguishedNames::new();

        for ota in &self.roots {
            let mut name = Vec::new();
            name.extend_from_slice(&ota.subject);
            wrap_in_asn1_len(&mut name);
            name.insert(0, 0x30);
            r.push(DistinguishedName::new(name));
        }

        r
    }

    /// Add a single DER-encoded certificate to the store.
    pub fn add(&mut self, der: &Certificate) -> Result<(), webpki::Error> {
        let ta = webpki::TrustAnchor::try_from_cert_der(&der.0)?;
        let ota = OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        );
        self.roots.push(ota);
        Ok(())
    }
}

pub(crate) fn wrap_in_asn1_len(bytes: &mut Vec<u8>) {
    let len = bytes.len();

    if len <= 0x7f {
        bytes.insert(0, len as u8);
    } else {
        bytes.insert(0, 0x80u8);
        let mut left = len;
        while left > 0 {
            let byte = (left & 0xff) as u8;
            bytes.insert(1, byte);
            bytes[0] += 1;
            left >>= 8;
        }
    }
}
