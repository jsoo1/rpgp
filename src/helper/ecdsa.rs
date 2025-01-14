use std::{fmt, marker::PhantomData};

use digest::{typenum::Unsigned, OutputSizeUser};
use ecdsa::{
    elliptic_curve::{array::ArraySize, CurveArithmetic},
    hazmat::DigestPrimitive,
    EcdsaCurve, PrimeCurve, SignatureSize,
};
use rand::{CryptoRng, Rng};
use signature::{hazmat::PrehashSigner, Keypair};

use super::{PgpHash, PgpPublicKey};
use crate::{
    bail,
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    types::{
        EcdsaPublicParams, EskType, Fingerprint, KeyId, KeyVersion, Mpi, PkeskBytes,
        PublicKeyTrait, PublicParams, SecretKeyTrait, SignatureBytes,
    },
};

impl<C> PgpPublicKey for ecdsa::VerifyingKey<C>
where
    Self: PgpEcdsaPublicKey,
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
{
    const PGP_ALGORITHM: PublicKeyAlgorithm = PublicKeyAlgorithm::ECDSA;

    fn pgp_parameters(&self) -> PublicParams {
        let key = self.ecdsa_public_key();
        PublicParams::ECDSA(key)
    }
}

/// Encoding for an ecdsa public key
pub trait PgpEcdsaPublicKey {
    /// public key parameter for a given public key
    fn ecdsa_public_key(&self) -> EcdsaPublicParams;
}

impl PgpEcdsaPublicKey for p256::ecdsa::VerifyingKey {
    fn ecdsa_public_key(&self) -> EcdsaPublicParams {
        let key = self.into();
        let p = Mpi::from_raw(self.to_sec1_bytes().to_vec());
        EcdsaPublicParams::P256 { key, p }
    }
}

/// [`signature::Signer`] backed signer for PGP.
pub struct EcdsaSigner<T, C> {
    inner: T,
    _signature: PhantomData<C>,
}

impl<C, T> EcdsaSigner<T, C> {
    /// Create a new signer with a given public key
    pub fn new(inner: T) -> Result<Self> {
        Ok(Self {
            inner,
            _signature: PhantomData,
        })
    }
}

impl<C, T> Keypair for EcdsaSigner<T, C>
where
    T: Keypair,
{
    type VerifyingKey = T::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl<C, T> EcdsaSigner<T, C>
where
    C: PrimeCurve + DigestPrimitive,
    SignatureSize<C>: ArraySize,
    T: PrehashSigner<ecdsa::Signature<C>>,
    C::Digest: PgpHash,
{
    fn sign_prehash(&self, hash: HashAlgorithm, prehash: &[u8]) -> Result<Vec<Vec<u8>>> {
        if C::Digest::HASH_ALGORITHM != hash {
            bail!(
                "Signer only support {expected:?}, found {found:?}",
                expected = C::Digest::HASH_ALGORITHM,
                found = hash
            );
        }

        if <C::Digest as OutputSizeUser>::OutputSize::USIZE != prehash.len() {
            bail!(
                "Signer expected a hash of length ({expected} bytes), found ({found} bytes)",
                expected = <C::Digest as OutputSizeUser>::OutputSize::USIZE,
                found = prehash.len()
            );
        }

        let signature = self.inner.sign_prehash(prehash)?;
        let (r, s) = signature.split_bytes();
        Ok(vec![r.to_vec(), s.to_vec()])
    }
}

impl<C, T> fmt::Debug for EcdsaSigner<T, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigner").finish()
    }
}

impl<C, T> SecretKeyTrait for EcdsaSigner<T, C>
where
    C: PrimeCurve + DigestPrimitive,
    SignatureSize<C>: ArraySize,
    T: PrehashSigner<ecdsa::Signature<C>> + PublicKeyTrait,
    C::Digest: PgpHash,
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
        let mpis = sig.iter().map(|v| Mpi::from_slice(&v[..])).collect();

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn public_key(&self) -> Self::PublicKey {}
}

impl<C, T> PublicKeyTrait for EcdsaSigner<T, C>
where
    T: PublicKeyTrait,
{
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
        _rng: R,
        _plain: &[u8],
        _esk_type: EskType,
    ) -> Result<PkeskBytes> {
        bail!("Encryption is unsupported")
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        self.inner.serialize_for_hashing(writer)
    }

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

    fn public_params(&self) -> &PublicParams {
        self.inner.public_params()
    }

    fn is_encryption_key(&self) -> bool {
        self.inner.is_encryption_key()
    }
}
