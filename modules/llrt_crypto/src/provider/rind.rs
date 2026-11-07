// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! rind crypto provider: every operation on [rind](https://github.com/moq-dev/rind),
//! a pure-Rust library with assembly for x86_64 and aarch64.
//!
//! Key data uses the RustCrypto provider's formats: RSA keys as PKCS#1 DER,
//! EC private keys as PKCS#8 and public keys as uncompressed SEC1 points,
//! Ed25519 private keys as PKCS#8, and X25519 private keys and every OKP
//! public key as raw bytes. The `der` crates only encode; rind validates
//! every key it loads.
//!
//! Not supported, as rind refuses them: RSA or ECDSA signatures with SHA-1
//! (RSASSA-PKCS1-v1_5 verification with SHA-1 is), RSA moduli outside 2048
//! to 8192 bits, RSA public exponents other than 65537 for generated keys,
//! and HMAC with MD5.

use std::num::NonZeroU32;

use der::{asn1::UintRef, Decode, Encode};
use rind::{
    aead::gcm,
    agreement,
    cipher::{self, AesCbcDecryptingKey, AesCbcEncryptingKey, AesCtr},
    digest, hkdf, hmac,
    key_wrap::AesKek,
    pbkdf2,
    rsa::{self as rind_rsa, KeySize},
    signature::{
        self, sign, verify, EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair, RsaPssSaltLength,
        RsaSigningAlgorithm, RsaVerificationAlgorithm,
    },
};

use crate::hash::HashAlgorithm;
use crate::provider::{
    parse_rsa_public_exponent, AesMode, CryptoError, CryptoProvider, EcImportResult, EcJwkExport,
    EcJwkImport, HmacProvider, OkpImportResult, OkpJwkExport, OkpJwkImport, RsaImportResult,
    RsaJwkExport, RsaJwkImport, SimpleDigest,
};
use crate::subtle::EllipticCurve;

pub struct RindProvider;

pub struct RindDigest(digest::Context);

impl SimpleDigest for RindDigest {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(mut self) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}

pub struct RindHmac(hmac::Context);

impl HmacProvider for RindHmac {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.sign().as_ref().to_vec()
    }
}

fn invalid_key(_: rind::Error) -> CryptoError {
    CryptoError::InvalidKey(None)
}

fn invalid_data(_: rind::Error) -> CryptoError {
    CryptoError::InvalidData(None)
}

fn operation_failed(_: rind::Error) -> CryptoError {
    CryptoError::OperationFailed(None)
}

fn der_invalid_key(_: der::Error) -> CryptoError {
    CryptoError::InvalidKey(None)
}

/// The hash a signature takes: SHA-256, SHA-384, or SHA-512.
fn signature_hash(hash: HashAlgorithm) -> Result<&'static digest::Algorithm, CryptoError> {
    match hash {
        HashAlgorithm::Sha256 => Ok(&digest::SHA256),
        HashAlgorithm::Sha384 => Ok(&digest::SHA384),
        HashAlgorithm::Sha512 => Ok(&digest::SHA512),
        HashAlgorithm::Md5 | HashAlgorithm::Sha1 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// The curve's signing algorithm, whose fixed-length `r || s` signatures
/// WebCrypto uses. Signing takes the message's hash from its digest.
fn ecdsa_signing(curve: EllipticCurve) -> &'static signature::EcdsaSigningAlgorithm {
    match curve {
        EllipticCurve::P256 => &sign::ECDSA_P256_SHA256_FIXED,
        EllipticCurve::P384 => &sign::ECDSA_P384_SHA384_FIXED,
        EllipticCurve::P521 => &sign::ECDSA_P521_SHA512_FIXED,
    }
}

fn ecdsa_verification(curve: EllipticCurve) -> &'static signature::VerificationAlgorithm {
    match curve {
        EllipticCurve::P256 => verify::ECDSA_P256_SHA256_FIXED.as_ref(),
        EllipticCurve::P384 => verify::ECDSA_P384_SHA384_FIXED.as_ref(),
        EllipticCurve::P521 => verify::ECDSA_P521_SHA512_FIXED.as_ref(),
    }
}

fn ecdh(curve: EllipticCurve) -> &'static agreement::Algorithm {
    match curve {
        EllipticCurve::P256 => &agreement::ECDH_P256,
        EllipticCurve::P384 => &agreement::ECDH_P384,
        EllipticCurve::P521 => &agreement::ECDH_P521,
    }
}

fn coordinate_len(curve: EllipticCurve) -> usize {
    match curve {
        EllipticCurve::P256 => 32,
        EllipticCurve::P384 => 48,
        EllipticCurve::P521 => 66,
    }
}

fn aes(key: &[u8]) -> Result<&'static cipher::Algorithm, CryptoError> {
    match key.len() {
        16 => Ok(&cipher::AES_128),
        24 => Ok(&cipher::AES_192),
        32 => Ok(&cipher::AES_256),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn gcm_key(key: &[u8], tag_length: u8) -> Result<gcm::Key, CryptoError> {
    let tag = match tag_length {
        128 => gcm::TagLength::Full,
        120 => gcm::TagLength::Truncated120,
        112 => gcm::TagLength::Truncated112,
        104 => gcm::TagLength::Truncated104,
        96 => gcm::TagLength::Truncated96,
        64 => gcm::TagLength::Truncated64,
        32 => gcm::TagLength::Truncated32,
        _ => return Err(CryptoError::InvalidData(None)),
    };
    gcm::Key::new(aes(key)?, key, tag).map_err(invalid_key)
}

fn block(iv: &[u8]) -> Result<&[u8; 16], CryptoError> {
    iv.try_into().map_err(|_| CryptoError::InvalidData(None))
}

fn oaep(hash: HashAlgorithm) -> Result<&'static rind_rsa::OaepAlgorithm, CryptoError> {
    match hash {
        HashAlgorithm::Sha1 => Ok(&rind_rsa::legacy::OAEP_SHA1),
        HashAlgorithm::Sha256 => Ok(&rind_rsa::OAEP_SHA256),
        HashAlgorithm::Sha384 => Ok(&rind_rsa::OAEP_SHA384),
        HashAlgorithm::Sha512 => Ok(&rind_rsa::OAEP_SHA512),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn pss_salt(salt_length: usize) -> Result<RsaPssSaltLength, CryptoError> {
    u16::try_from(salt_length)
        .map(RsaPssSaltLength::Custom)
        .map_err(|_| CryptoError::InvalidData(None))
}

fn hkdf_algorithm(hash: HashAlgorithm) -> Result<&'static hkdf::Algorithm, CryptoError> {
    match hash {
        HashAlgorithm::Sha1 => Ok(&hkdf::legacy::HKDF_SHA1),
        HashAlgorithm::Sha256 => Ok(&hkdf::HKDF_SHA256),
        HashAlgorithm::Sha384 => Ok(&hkdf::HKDF_SHA384),
        HashAlgorithm::Sha512 => Ok(&hkdf::HKDF_SHA512),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn pbkdf2_algorithm(hash: HashAlgorithm) -> Result<&'static pbkdf2::Algorithm, CryptoError> {
    match hash {
        HashAlgorithm::Sha1 => Ok(&pbkdf2::legacy::PBKDF2_HMAC_SHA1),
        HashAlgorithm::Sha256 => Ok(&pbkdf2::PBKDF2_HMAC_SHA256),
        HashAlgorithm::Sha384 => Ok(&pbkdf2::PBKDF2_HMAC_SHA384),
        HashAlgorithm::Sha512 => Ok(&pbkdf2::PBKDF2_HMAC_SHA512),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn random(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0; len];
    rind::rand::fill(&mut bytes).map_err(operation_failed)?;
    Ok(bytes)
}

/// The PKCS#1 `RSAPrivateKey` inside a PKCS#8 `PrivateKeyInfo`.
fn pkcs8_to_pkcs1(pkcs8: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let info = pkcs8::PrivateKeyInfoRef::from_der(pkcs8).map_err(der_invalid_key)?;
    Ok(info.private_key.as_bytes().to_vec())
}

/// Imports a PKCS#1 `RSAPublicKey`, re-encoded.
fn rsa_public_pkcs1(der: &[u8]) -> Result<RsaImportResult, CryptoError> {
    let key = pkcs1::RsaPublicKey::<UintRef>::from_der(der).map_err(der_invalid_key)?;
    Ok(RsaImportResult {
        key_data: key.to_der().map_err(der_invalid_key)?,
        modulus_length: (key.modulus.as_bytes().len() * 8) as u32,
        public_exponent: key.public_exponent.as_bytes().to_vec(),
        is_private: false,
    })
}

/// Imports a PKCS#1 `RSAPrivateKey`, refused unless rind loads it.
fn rsa_private_pkcs1(der: &[u8]) -> Result<RsaImportResult, CryptoError> {
    let key = pkcs1::RsaPrivateKey::<UintRef>::from_der(der).map_err(der_invalid_key)?;
    let key_data = key.to_der().map_err(der_invalid_key)?;
    RsaKeyPair::from_pkcs1(&key_data).map_err(invalid_key)?;
    Ok(RsaImportResult {
        key_data,
        modulus_length: (key.modulus.as_bytes().len() * 8) as u32,
        public_exponent: key.public_exponent.as_bytes().to_vec(),
        is_private: true,
    })
}

/// A NIST curve's uncompressed point, `0x04 || x || y`.
fn uncompressed_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    point
}

impl CryptoProvider for RindProvider {
    type Digest = RindDigest;
    type Hmac = RindHmac;

    fn digest(&self, algorithm: HashAlgorithm) -> Self::Digest {
        RindDigest(digest::Context::new(match algorithm {
            HashAlgorithm::Md5 => &digest::legacy::MD5,
            HashAlgorithm::Sha1 => &digest::legacy::SHA1,
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha384 => &digest::SHA384,
            HashAlgorithm::Sha512 => &digest::SHA512,
        }))
    }

    fn hmac(&self, algorithm: HashAlgorithm, key: &[u8]) -> Self::Hmac {
        let algorithm = match algorithm {
            HashAlgorithm::Md5 => panic!("HMAC-MD5 not supported"),
            HashAlgorithm::Sha1 => &hmac::legacy::HMAC_SHA1,
            HashAlgorithm::Sha256 => &hmac::HMAC_SHA256,
            HashAlgorithm::Sha384 => &hmac::HMAC_SHA384,
            HashAlgorithm::Sha512 => &hmac::HMAC_SHA512,
        };
        RindHmac(hmac::Context::with_key(&hmac::Key::new(algorithm, key)))
    }

    fn ecdsa_sign(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let digest = digest::digest(signature_hash(hash_alg)?, data);
        let key =
            EcdsaKeyPair::from_pkcs8(ecdsa_signing(curve), private_key_der).map_err(invalid_key)?;
        let signature = key
            .sign_digest(&digest)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        Ok(signature.as_ref().to_vec())
    }

    fn ecdsa_verify(
        &self,
        curve: EllipticCurve,
        public_key_sec1: &[u8],
        signature: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let digest = digest::digest(signature_hash(hash_alg)?, data);
        let key = signature::PublicKey::new(ecdsa_verification(curve), public_key_sec1)
            .map_err(invalid_key)?;
        Ok(key.verify_digest(&digest, signature).is_ok())
    }

    fn ed25519_sign(&self, private_key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = Ed25519KeyPair::from_pkcs8(private_key_der).map_err(invalid_key)?;
        Ok(key.sign(data).as_ref().to_vec())
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, CryptoError> {
        // rind refuses a small-order point, which verifies signatures nobody
        // made, as ed25519-dalek's `verify_strict` does.
        Ok(
            signature::PublicKey::new(&verify::ED25519, public_key_bytes)
                .and_then(|key| key.verify(data, signature))
                .is_ok(),
        )
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let salt = pss_salt(salt_length)?;
        let algorithm = match hash_alg {
            HashAlgorithm::Sha256 => RsaSigningAlgorithm::pss_sha256(salt),
            HashAlgorithm::Sha384 => RsaSigningAlgorithm::pss_sha384(salt),
            HashAlgorithm::Sha512 => RsaSigningAlgorithm::pss_sha512(salt),
            HashAlgorithm::Md5 | HashAlgorithm::Sha1 => {
                return Err(CryptoError::UnsupportedAlgorithm)
            },
        };
        let key = RsaKeyPair::from_pkcs1(private_key_der).map_err(invalid_key)?;
        let signature = key
            .sign(&algorithm, data)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        Ok(signature.as_ref().to_vec())
    }

    fn rsa_pss_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        data: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let salt = pss_salt(salt_length)?;
        let algorithm = match hash_alg {
            HashAlgorithm::Sha256 => RsaVerificationAlgorithm::pss_sha256(salt),
            HashAlgorithm::Sha384 => RsaVerificationAlgorithm::pss_sha384(salt),
            HashAlgorithm::Sha512 => RsaVerificationAlgorithm::pss_sha512(salt),
            HashAlgorithm::Md5 | HashAlgorithm::Sha1 => {
                return Err(CryptoError::UnsupportedAlgorithm)
            },
        };
        let key = signature::PublicKey::new(&algorithm, public_key_der).map_err(invalid_key)?;
        Ok(key.verify(data, signature).is_ok())
    }

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let algorithm = match hash_alg {
            HashAlgorithm::Sha256 => &sign::RSA_PKCS1_SHA256,
            HashAlgorithm::Sha384 => &sign::RSA_PKCS1_SHA384,
            HashAlgorithm::Sha512 => &sign::RSA_PKCS1_SHA512,
            HashAlgorithm::Md5 | HashAlgorithm::Sha1 => {
                return Err(CryptoError::UnsupportedAlgorithm)
            },
        };
        let key = RsaKeyPair::from_pkcs1(private_key_der).map_err(invalid_key)?;
        let signature = key
            .sign(algorithm, data)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        Ok(signature.as_ref().to_vec())
    }

    fn rsa_pkcs1v15_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let algorithm: &signature::VerificationAlgorithm = match hash_alg {
            HashAlgorithm::Sha1 => verify::legacy::RSA_PKCS1_SHA1.as_ref(),
            HashAlgorithm::Sha256 => verify::RSA_PKCS1_SHA256.as_ref(),
            HashAlgorithm::Sha384 => verify::RSA_PKCS1_SHA384.as_ref(),
            HashAlgorithm::Sha512 => verify::RSA_PKCS1_SHA512.as_ref(),
            HashAlgorithm::Md5 => return Err(CryptoError::UnsupportedAlgorithm),
        };
        let key = signature::PublicKey::new(algorithm, public_key_der).map_err(invalid_key)?;
        Ok(key.verify(data, signature).is_ok())
    }

    fn rsa_oaep_encrypt(
        &self,
        public_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let key =
            rind_rsa::EncryptingKey::new(oaep(hash_alg)?, public_key_der).map_err(invalid_key)?;
        let ciphertext = key
            .encrypt(data, label.unwrap_or_default())
            .map_err(|_| CryptoError::EncryptionFailed(None))?;
        Ok(ciphertext.as_ref().to_vec())
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = rind_rsa::DecryptingKey::from_pkcs1(oaep(hash_alg)?, private_key_der)
            .map_err(invalid_key)?;
        let plaintext = key
            .decrypt(data, label.unwrap_or_default())
            .map_err(|_| CryptoError::DecryptionFailed(None))?;
        Ok(plaintext.as_ref().to_vec())
    }

    fn ecdh_derive_bits(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        public_key_sec1: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key =
            agreement::PrivateKey::from_pkcs8(ecdh(curve), private_key_der).map_err(invalid_key)?;
        let secret = key.agree(public_key_sec1).map_err(invalid_key)?;
        Ok(secret.as_ref().to_vec())
    }

    fn x25519_derive_bits(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = agreement::PrivateKey::from_scalar(&agreement::X25519, private_key)
            .map_err(invalid_key)?;
        // rind refuses the all-zero secret of a small-order public key.
        let secret = key.agree(public_key).map_err(operation_failed)?;
        Ok(secret.as_ref().to_vec())
    }

    fn aes_encrypt(
        &self,
        mode: AesMode,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut in_out = data.to_vec();
        match mode {
            AesMode::Cbc => {
                AesCbcEncryptingKey::new(aes(key)?, key)
                    .map_err(invalid_key)?
                    .encrypt(block(iv)?, &mut in_out);
            },
            AesMode::Ctr { counter_length } => {
                let counter_bits =
                    u8::try_from(counter_length).map_err(|_| CryptoError::InvalidData(None))?;
                AesCtr::new(aes(key)?, key, counter_bits)
                    .map_err(invalid_data)?
                    .apply_keystream(block(iv)?, &mut in_out)
                    .map_err(operation_failed)?;
            },
            AesMode::Gcm { tag_length } => {
                let iv = gcm::Iv::assume_unique_for_key(iv).map_err(invalid_data)?;
                gcm_key(key, tag_length)?
                    .seal_in_place_append_tag(iv, additional_data.unwrap_or_default(), &mut in_out)
                    .map_err(|_| CryptoError::EncryptionFailed(None))?;
            },
        }
        Ok(in_out)
    }

    fn aes_decrypt(
        &self,
        mode: AesMode,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut in_out = data.to_vec();
        match mode {
            AesMode::Cbc => {
                let len = AesCbcDecryptingKey::new(aes(key)?, key)
                    .map_err(invalid_key)?
                    .decrypt(block(iv)?, &mut in_out)
                    .map_err(|_| CryptoError::DecryptionFailed(None))?
                    .len();
                in_out.truncate(len);
            },
            AesMode::Ctr { .. } => return self.aes_encrypt(mode, key, iv, data, additional_data),
            AesMode::Gcm { tag_length } => {
                let iv = gcm::Iv::assume_unique_for_key(iv).map_err(invalid_data)?;
                let len = gcm_key(key, tag_length)?
                    .open_in_place(iv, additional_data.unwrap_or_default(), &mut in_out)
                    .map_err(|_| CryptoError::DecryptionFailed(None))?
                    .len();
                in_out.truncate(len);
            },
        }
        Ok(in_out)
    }

    fn aes_kw_wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kek = AesKek::new(aes(kek)?, kek).map_err(invalid_key)?;
        let mut wrapped = vec![0; key.len() + 8];
        kek.wrap(key, &mut wrapped).map_err(operation_failed)?;
        Ok(wrapped)
    }

    fn aes_kw_unwrap(&self, kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kek = AesKek::new(aes(kek)?, kek).map_err(invalid_key)?;
        let len = wrapped_key
            .len()
            .checked_sub(8)
            .ok_or(CryptoError::OperationFailed(None))?;
        let mut key = vec![0; len];
        kek.unwrap(wrapped_key, &mut key)
            .map_err(operation_failed)?;
        Ok(key)
    }

    fn hkdf_derive_key(
        &self,
        key: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let prk = hkdf::Salt::new(hkdf_algorithm(hash_alg)?, salt).extract(key);
        let mut out = vec![0; length];
        prk.expand(&[info], length)
            .fill(&mut out)
            .map_err(|_| CryptoError::DerivationFailed(None))?;
        Ok(out)
    }

    fn pbkdf2_derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let iterations = NonZeroU32::new(iterations).ok_or(CryptoError::InvalidData(None))?;
        let mut out = vec![0; length];
        pbkdf2::Secret::new(pbkdf2_algorithm(hash_alg)?, password)
            .derive(iterations, salt, &mut out)
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(out)
    }

    fn generate_aes_key(&self, length_bits: u16) -> Result<Vec<u8>, CryptoError> {
        if !matches!(length_bits, 128 | 192 | 256) {
            return Err(CryptoError::InvalidLength);
        }
        random((length_bits / 8) as usize)
    }

    fn generate_hmac_key(
        &self,
        hash_alg: HashAlgorithm,
        length_bits: u16,
    ) -> Result<Vec<u8>, CryptoError> {
        let length_bytes = if length_bits == 0 {
            hash_alg.block_len()
        } else {
            (length_bits / 8) as usize
        };
        if length_bytes > 128 {
            return Err(CryptoError::InvalidLength);
        }
        random(length_bytes)
    }

    fn generate_ec_key(&self, curve: EllipticCurve) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key = EcdsaKeyPair::generate(ecdsa_signing(curve)).map_err(operation_failed)?;
        Ok((
            key.to_pkcs8().as_ref().to_vec(),
            key.public_key().as_ref().to_vec(),
        ))
    }

    fn generate_ed25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key = Ed25519KeyPair::generate().map_err(operation_failed)?;
        Ok((
            key.to_pkcs8v1().as_ref().to_vec(),
            key.public_key().as_ref().to_vec(),
        ))
    }

    fn generate_x25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key = agreement::PrivateKey::generate(&agreement::X25519).map_err(operation_failed)?;
        Ok((
            key.to_scalar().as_ref().to_vec(),
            key.public_key().as_ref().to_vec(),
        ))
    }

    fn generate_rsa_key(
        &self,
        modulus_length: u32,
        public_exponent: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // WebCrypto fails generation it cannot do with an OperationError.
        if parse_rsa_public_exponent(public_exponent)? != 65537 {
            return Err(CryptoError::OperationFailed(None));
        }
        let size = match modulus_length {
            2048 => KeySize::Rsa2048,
            3072 => KeySize::Rsa3072,
            4096 => KeySize::Rsa4096,
            6144 => KeySize::Rsa6144,
            8192 => KeySize::Rsa8192,
            _ => return Err(CryptoError::OperationFailed(None)),
        };
        let key = RsaKeyPair::generate(size).map_err(operation_failed)?;
        let public_key = key.public_key(&sign::RSA_PKCS1_SHA256);
        Ok((
            pkcs8_to_pkcs1(key.to_pkcs8().as_ref())?,
            public_key.as_ref().to_vec(),
        ))
    }

    fn import_rsa_public_key_pkcs1(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError> {
        rsa_public_pkcs1(der)
    }

    fn import_rsa_private_key_pkcs1(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError> {
        rsa_private_pkcs1(der)
    }

    fn import_rsa_public_key_spki(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError> {
        let spki = spki::SubjectPublicKeyInfoRef::try_from(der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        rsa_public_pkcs1(spki.subject_public_key.raw_bytes())
    }

    fn import_rsa_private_key_pkcs8(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError> {
        rsa_private_pkcs1(&pkcs8_to_pkcs1(der)?)
    }

    fn export_rsa_public_key_pkcs1(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(key_data.to_vec())
    }

    fn export_rsa_public_key_spki(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let spki = spki::SubjectPublicKeyInfo {
            algorithm: spki::AlgorithmIdentifier::<der::asn1::Any> {
                oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
                parameters: Some(der::asn1::Null.into()),
            },
            subject_public_key: der::asn1::BitString::from_bytes(key_data)
                .map_err(der_invalid_key)?,
        };
        spki.to_der().map_err(der_invalid_key)
    }

    fn export_rsa_private_key_pkcs8(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = RsaKeyPair::from_pkcs1(key_data).map_err(invalid_key)?;
        Ok(key.to_pkcs8().as_ref().to_vec())
    }

    fn import_ec_public_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError> {
        let key = agreement::PublicKey::new(ecdh(curve), data).map_err(invalid_key)?;
        Ok(EcImportResult {
            key_data: key.as_ref().to_vec(),
            is_private: false,
        })
    }

    fn import_ec_public_key_spki(
        &self,
        der: &[u8],
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError> {
        let key = agreement::PublicKey::from_spki(ecdh(curve), der).map_err(invalid_key)?;
        Ok(EcImportResult {
            key_data: key.as_ref().to_vec(),
            is_private: false,
        })
    }

    fn import_ec_private_key_pkcs8(&self, der: &[u8]) -> Result<EcImportResult, CryptoError> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(der).map_err(der_invalid_key)?;
        let curve = info
            .algorithm
            .parameters_oid()
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let curve = match curve {
            const_oid::db::rfc5912::SECP_256_R_1 => EllipticCurve::P256,
            const_oid::db::rfc5912::SECP_384_R_1 => EllipticCurve::P384,
            const_oid::db::rfc5912::SECP_521_R_1 => EllipticCurve::P521,
            _ => return Err(CryptoError::InvalidKey(None)),
        };
        let key = EcdsaKeyPair::from_pkcs8(ecdsa_signing(curve), der).map_err(invalid_key)?;
        Ok(EcImportResult {
            key_data: key.to_pkcs8().as_ref().to_vec(),
            is_private: true,
        })
    }

    fn import_ec_private_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError> {
        let public_key = agreement::PrivateKey::from_scalar(ecdh(curve), data)
            .map_err(invalid_key)?
            .public_key();
        let key = EcdsaKeyPair::from_scalar_and_public_key(
            ecdsa_signing(curve),
            data,
            public_key.as_ref(),
        )
        .map_err(invalid_key)?;
        Ok(EcImportResult {
            key_data: key.to_pkcs8().as_ref().to_vec(),
            is_private: true,
        })
    }

    fn export_ec_public_key_sec1(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
        is_private: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        if !is_private {
            return Ok(key_data.to_vec());
        }
        let key = EcdsaKeyPair::from_pkcs8(ecdsa_signing(curve), key_data).map_err(invalid_key)?;
        Ok(key.public_key().as_ref().to_vec())
    }

    fn export_ec_public_key_spki(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = agreement::PublicKey::new(ecdh(curve), key_data).map_err(invalid_key)?;
        Ok(key.to_spki().as_ref().to_vec())
    }

    fn export_ec_private_key_pkcs8(
        &self,
        key_data: &[u8],
        _curve: EllipticCurve,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(key_data.to_vec())
    }

    fn import_okp_public_key_raw(&self, data: &[u8]) -> Result<OkpImportResult, CryptoError> {
        if data.len() != 32 {
            return Err(CryptoError::InvalidLength);
        }
        Ok(OkpImportResult {
            key_data: data.to_vec(),
            is_private: false,
        })
    }

    fn import_okp_public_key_spki(
        &self,
        der: &[u8],
        expected_oid: &[u8],
    ) -> Result<OkpImportResult, CryptoError> {
        let spki = spki::SubjectPublicKeyInfoRef::try_from(der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        if spki.algorithm.oid.as_bytes() != expected_oid {
            return Err(CryptoError::InvalidKey(None));
        }
        self.import_okp_public_key_raw(spki.subject_public_key.raw_bytes())
    }

    fn import_okp_private_key_pkcs8(
        &self,
        der: &[u8],
        expected_oid: &[u8],
    ) -> Result<OkpImportResult, CryptoError> {
        let key_data = if expected_oid == const_oid::db::rfc8410::ID_ED_25519.as_bytes() {
            Ed25519KeyPair::from_pkcs8(der).map_err(invalid_key)?;
            der.to_vec()
        } else if expected_oid == const_oid::db::rfc8410::ID_X_25519.as_bytes() {
            agreement::PrivateKey::from_pkcs8(&agreement::X25519, der)
                .map_err(invalid_key)?
                .to_scalar()
                .as_ref()
                .to_vec()
        } else {
            return Err(CryptoError::InvalidKey(None));
        };
        Ok(OkpImportResult {
            key_data,
            is_private: true,
        })
    }

    fn export_okp_public_key_raw(
        &self,
        key_data: &[u8],
        is_private: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        // A private key's algorithm is not passed, and its public key is
        // reached through `export_okp_jwk` instead.
        if is_private {
            return Err(CryptoError::InvalidAccess(None));
        }
        Ok(key_data.to_vec())
    }

    fn export_okp_public_key_spki(
        &self,
        key_data: &[u8],
        oid: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if oid == const_oid::db::rfc8410::ID_ED_25519.as_bytes() {
            let key = signature::PublicKey::new(&verify::ED25519, key_data).map_err(invalid_key)?;
            Ok(key.to_spki().as_ref().to_vec())
        } else if oid == const_oid::db::rfc8410::ID_X_25519.as_bytes() {
            let key =
                agreement::PublicKey::new(&agreement::X25519, key_data).map_err(invalid_key)?;
            Ok(key.to_spki().as_ref().to_vec())
        } else {
            Err(CryptoError::InvalidKey(None))
        }
    }

    fn export_okp_private_key_pkcs8(
        &self,
        key_data: &[u8],
        oid: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if oid == const_oid::db::rfc8410::ID_ED_25519.as_bytes() {
            Ok(key_data.to_vec())
        } else if oid == const_oid::db::rfc8410::ID_X_25519.as_bytes() {
            let key = agreement::PrivateKey::from_scalar(&agreement::X25519, key_data)
                .map_err(invalid_key)?;
            Ok(key.to_pkcs8().as_ref().to_vec())
        } else {
            Err(CryptoError::InvalidKey(None))
        }
    }

    fn import_rsa_jwk(&self, jwk: RsaJwkImport<'_>) -> Result<RsaImportResult, CryptoError> {
        let modulus = UintRef::new(jwk.n).map_err(der_invalid_key)?;
        let public_exponent = UintRef::new(jwk.e).map_err(der_invalid_key)?;
        let (Some(d), Some(p), Some(q), Some(dp), Some(dq), Some(qi)) =
            (jwk.d, jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi)
        else {
            let key = pkcs1::RsaPublicKey {
                modulus,
                public_exponent,
            };
            return rsa_public_pkcs1(&key.to_der().map_err(der_invalid_key)?);
        };
        let uint = |bytes| UintRef::new(bytes).map_err(der_invalid_key);
        let key = pkcs1::RsaPrivateKey {
            modulus,
            public_exponent,
            private_exponent: uint(d)?,
            prime1: uint(p)?,
            prime2: uint(q)?,
            exponent1: uint(dp)?,
            exponent2: uint(dq)?,
            coefficient: uint(qi)?,
            other_prime_infos: None,
        };
        rsa_private_pkcs1(&key.to_der().map_err(der_invalid_key)?)
    }

    fn export_rsa_jwk(
        &self,
        key_data: &[u8],
        is_private: bool,
    ) -> Result<RsaJwkExport, CryptoError> {
        if is_private {
            let key =
                pkcs1::RsaPrivateKey::<UintRef>::from_der(key_data).map_err(der_invalid_key)?;
            Ok(RsaJwkExport {
                n: key.modulus.as_bytes().to_vec(),
                e: key.public_exponent.as_bytes().to_vec(),
                d: Some(key.private_exponent.as_bytes().to_vec()),
                p: Some(key.prime1.as_bytes().to_vec()),
                q: Some(key.prime2.as_bytes().to_vec()),
                dp: Some(key.exponent1.as_bytes().to_vec()),
                dq: Some(key.exponent2.as_bytes().to_vec()),
                qi: Some(key.coefficient.as_bytes().to_vec()),
            })
        } else {
            let key =
                pkcs1::RsaPublicKey::<UintRef>::from_der(key_data).map_err(der_invalid_key)?;
            Ok(RsaJwkExport {
                n: key.modulus.as_bytes().to_vec(),
                e: key.public_exponent.as_bytes().to_vec(),
                d: None,
                p: None,
                q: None,
                dp: None,
                dq: None,
                qi: None,
            })
        }
    }

    fn import_ec_jwk(
        &self,
        jwk: EcJwkImport<'_>,
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError> {
        let point = uncompressed_point(jwk.x, jwk.y);
        let Some(d) = jwk.d else {
            return self.import_ec_public_key_sec1(&point, curve);
        };
        let key = EcdsaKeyPair::from_scalar_and_public_key(ecdsa_signing(curve), d, &point)
            .map_err(invalid_key)?;
        Ok(EcImportResult {
            key_data: key.to_pkcs8().as_ref().to_vec(),
            is_private: true,
        })
    }

    fn export_ec_jwk(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
        is_private: bool,
    ) -> Result<EcJwkExport, CryptoError> {
        let len = coordinate_len(curve);
        let (point, d) = if is_private {
            let key =
                EcdsaKeyPair::from_pkcs8(ecdsa_signing(curve), key_data).map_err(invalid_key)?;
            (
                key.public_key().as_ref().to_vec(),
                Some(key.to_scalar().as_ref().to_vec()),
            )
        } else {
            (key_data.to_vec(), None)
        };
        if point.len() != 1 + 2 * len || point[0] != 0x04 {
            return Err(CryptoError::InvalidKey(None));
        }
        Ok(EcJwkExport {
            x: point[1..1 + len].to_vec(),
            y: point[1 + len..].to_vec(),
            d,
        })
    }

    fn import_okp_jwk(
        &self,
        jwk: OkpJwkImport<'_>,
        is_ed25519: bool,
    ) -> Result<OkpImportResult, CryptoError> {
        let Some(d) = jwk.d else {
            return self.import_okp_public_key_raw(jwk.x);
        };
        let key_data = if is_ed25519 {
            Ed25519KeyPair::from_seed_and_public_key(d, jwk.x)
                .map_err(invalid_key)?
                .to_pkcs8v1()
                .as_ref()
                .to_vec()
        } else {
            let key =
                agreement::PrivateKey::from_scalar(&agreement::X25519, d).map_err(invalid_key)?;
            if key.public_key().as_ref() != jwk.x {
                return Err(CryptoError::InvalidKey(None));
            }
            d.to_vec()
        };
        Ok(OkpImportResult {
            key_data,
            is_private: true,
        })
    }

    fn export_okp_jwk(
        &self,
        key_data: &[u8],
        is_private: bool,
        is_ed25519: bool,
    ) -> Result<OkpJwkExport, CryptoError> {
        if !is_private {
            return Ok(OkpJwkExport {
                x: key_data.to_vec(),
                d: None,
            });
        }
        if is_ed25519 {
            let key = Ed25519KeyPair::from_pkcs8(key_data).map_err(invalid_key)?;
            Ok(OkpJwkExport {
                x: key.public_key().as_ref().to_vec(),
                d: Some(key.to_seed().as_ref().to_vec()),
            })
        } else {
            let key = agreement::PrivateKey::from_scalar(&agreement::X25519, key_data)
                .map_err(invalid_key)?;
            Ok(OkpJwkExport {
                x: key.public_key().as_ref().to_vec(),
                d: Some(key_data.to_vec()),
            })
        }
    }
}
