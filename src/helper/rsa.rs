use std::{fmt, marker::PhantomData};

use digest::{typenum::Unsigned, OutputSizeUser};
use rand::{CryptoRng, Rng};
use rsa::pkcs1v15::Signature;
use sha2::Digest;
use signature::{hazmat::PrehashSigner, Keypair, SignatureEncoding};

use super::PgpHash;

use crate::{
    bail,
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::PacketTrait,
    ser::Serialize,
    types::{
        EskType, Fingerprint, KeyId, KeyVersion, Mpi, PkeskBytes, PublicKeyTrait, PublicParams,
        SecretKeyTrait, SignatureBytes,
    },
};

/// [`signature::Signer`] backed signer for PGP.
#[derive(Clone)]
pub struct RsaSigner<T, D> {
    inner: T,
    _digest: PhantomData<D>,
}

impl<D, T> fmt::Debug for RsaSigner<T, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner").finish()
    }
}

impl<T, D> RsaSigner<T, D>
where
    D: Digest,
{
    /// Create a new signer with a given public key
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            _digest: PhantomData,
        }
    }
}

impl<D, T> RsaSigner<T, D>
where
    D: Digest + PgpHash,
    T: PrehashSigner<Signature>,
{
    fn sign_prehash(&self, hash: HashAlgorithm, prehash: &[u8]) -> Result<Vec<Vec<u8>>> {
        if D::HASH_ALGORITHM != hash {
            bail!(
                "Signer only support {expected:?}, found {found:?}",
                expected = D::HASH_ALGORITHM,
                found = hash
            );
        }

        if <D as OutputSizeUser>::OutputSize::USIZE != prehash.len() {
            bail!(
                "Signer expected a hash of length ({expected} bytes), found ({found} bytes)",
                expected = <D as OutputSizeUser>::OutputSize::USIZE,
                found = prehash.len()
            );
        }

        let sig = self.inner.sign_prehash(prehash)?;

        Ok(vec![sig.to_vec()])
    }
}

impl<D, T> Keypair for RsaSigner<T, D>
where
    T: Keypair,
{
    type VerifyingKey = T::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl<D, T> SecretKeyTrait for RsaSigner<T, D>
where
    T: PrehashSigner<Signature> + PublicKeyTrait,
    D: Digest + PgpHash,
{
    type PublicKey = ();
    type Unlocked = Self;

    fn unlock<F, G, Tr>(&self, _pw: F, work: G) -> Result<Tr>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<Tr>,
    {
        work(self)
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        hash: HashAlgorithm,
        prehashed_data: &[u8],
    ) -> Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        let sig = self.sign_prehash(hash, prehashed_data)?;

        // MPI format:
        // strip leading zeros, to match parse results from MPIs
        let mpis = sig
            .iter()
            .map(|v| Mpi::from_slice(&v[..]))
            .collect::<Vec<_>>();

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn public_key(&self) -> Self::PublicKey {}
}

impl<T, D> PublicKeyTrait for RsaSigner<T, D>
where
    T: PublicKeyTrait,
{
    fn version(&self) -> KeyVersion {
        self.inner.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.inner.algorithm()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.inner.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.inner.expiration()
    }

    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.inner.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.inner.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        self.inner.serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        self.inner.public_params()
    }
}

impl<T, D> PacketTrait for RsaSigner<T, D>
where
    T: PacketTrait,
{
    fn packet_version(&self) -> crate::types::Version {
        self.inner.packet_version()
    }

    fn tag(&self) -> crate::types::Tag {
        self.inner.tag()
    }
}

impl<T, D> Serialize for RsaSigner<T, D>
where
    T: Serialize,
{
    fn to_writer<W: std::io::Write>(&self, w: &mut W) -> Result<()> {
        self.inner.to_writer(w)
    }
}
