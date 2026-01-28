{-# LANGUAGE LambdaCase #-}

-- |
-- Module      : Data.X509.AC.Validation.Signature
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Attribute Certificate signature verification.
--
-- This module provides signature verification for Attribute Certificates,
-- checking that:
--
-- * The AC signature is cryptographically valid using the AA public key
-- * The signature algorithm in the AC info matches the outer signature algorithm
-- * The signature algorithm is not weak (MD2, MD5 rejected) or deprecated (SHA1 warning)
--
-- == PKITS Test Coverage
--
-- This module covers tests AC-SIG-1.1 through AC-SIG-1.7:
--
-- * AC-SIG-1.1: Valid AC signature
-- * AC-SIG-1.2: Invalid AC signature (corrupted)
-- * AC-SIG-1.3: Algorithm mismatch
-- * AC-SIG-1.4: DSA signature verification
-- * AC-SIG-1.5: ECDSA signature verification
-- * AC-SIG-1.6: MD5 signature (weak)
-- * AC-SIG-1.7: SHA1 signature (deprecated)
module Data.X509.AC.Validation.Signature (
    -- * Signature Verification
    verifyACSignature,
    SignatureResult (..),
    SignatureError (..),
    SignatureWarning (..),

    -- * Re-exports from x509-validation
    SignatureVerification (..),
    SignatureFailure (..),
)
where

import Data.X509 (PubKey, SignatureALG (..), getSigned, signedAlg, signedObject)
import Data.X509.AlgorithmIdentifier (HashALG (..))
import Data.X509.AttCert
import Data.X509.Validation (
    SignatureFailure (..),
    SignatureVerification (..),
    verifySignedSignature,
 )
import Data.X509AC (SignedAttributeCertificate)

-- | Errors specific to AC signature verification.
data SignatureError
    = -- | The signature verification failed (invalid signature, unsupported algorithm, etc.)
      SigVerificationFailed SignatureFailure
    | -- | The signature algorithm in AttributeCertificateInfo doesn't match the outer signature
      SigAlgorithmMismatch
        { saeInnerAlg :: SignatureALG
        -- ^ Algorithm in AttributeCertificateInfo.signature
        , saeOuterAlg :: SignatureALG
        -- ^ Algorithm in outer signed structure
        }
    | -- | Weak signature algorithm (MD2, MD5) that MUST NOT be accepted
      SigWeakAlgorithm String
    deriving (Show, Eq)

-- | Warning for deprecated signature algorithms.
data SignatureWarning
    = -- | Deprecated signature algorithm (SHA1) - should be avoided
      SigDeprecatedAlgorithm String
    deriving (Show, Eq)

-- | Result of signature verification including both errors and warnings.
data SignatureResult
    = -- | Signature verification passed
      SigSuccess
    | -- | Signature verification passed but with warnings
      SigWarning SignatureWarning
    | -- | Signature verification failed
      SigError SignatureError
    deriving (Show, Eq)

-- | Verify an Attribute Certificate signature.
--
-- This function performs the following checks:
--
-- 1. Verifies that the inner signature algorithm (in AttributeCertificateInfo)
--    matches the outer signature algorithm
-- 2. Checks for weak algorithms (MD2, MD5) and rejects them
-- 3. Warns about deprecated algorithms (SHA1)
-- 4. Verifies the cryptographic signature using the AA public key
--
-- The @pubKey@ parameter should be the public key from the AA certificate
-- that issued this AC.
verifyACSignature
    :: PubKey
    -- ^ AA public key (from AA certificate)
    -> SignedAttributeCertificate
    -- ^ Signed Attribute Certificate to verify
    -> SignatureResult
verifyACSignature pubKey signedAC
    -- Check algorithm match first
    | innerSigAlg /= outerSigAlg =
        SigError $ SigAlgorithmMismatch innerSigAlg outerSigAlg
    -- Check for weak algorithms
    | isWeakAlgorithm innerSigAlg =
        SigError $ SigWeakAlgorithm (showAlgorithm innerSigAlg)
    -- Perform actual signature verification
    | otherwise = case verifySignedSignature signedAC pubKey of
        SignaturePass
            | isDeprecatedAlgorithm innerSigAlg ->
                SigWarning $ SigDeprecatedAlgorithm (showAlgorithm innerSigAlg)
            | otherwise -> SigSuccess
        SignatureFailed failure ->
            SigError $ SigVerificationFailed failure
  where
    signed = getSigned signedAC
    innerSigAlg = aciSignature (signedObject signed)
    outerSigAlg = signedAlg signed

-- | Check if a signature algorithm is weak (cryptographically broken).
--
-- MD2 and MD5 are considered weak due to known collision attacks.
isWeakAlgorithm :: SignatureALG -> Bool
isWeakAlgorithm = \case
    SignatureALG HashMD2 _ -> True
    SignatureALG HashMD5 _ -> True
    _ -> False

-- | Check if a signature algorithm is deprecated (should be avoided).
--
-- SHA1 is considered deprecated due to theoretical collision attacks,
-- though it may still be acceptable in some contexts.
isDeprecatedAlgorithm :: SignatureALG -> Bool
isDeprecatedAlgorithm = \case
    SignatureALG HashSHA1 _ -> True
    _ -> False

-- | Display a signature algorithm for error/warning messages.
showAlgorithm :: SignatureALG -> String
showAlgorithm = \case
    SignatureALG HashMD2 _ -> "MD2"
    SignatureALG HashMD5 _ -> "MD5"
    SignatureALG HashSHA1 _ -> "SHA1"
    SignatureALG HashSHA224 _ -> "SHA224"
    SignatureALG HashSHA256 _ -> "SHA256"
    SignatureALG HashSHA384 _ -> "SHA384"
    SignatureALG HashSHA512 _ -> "SHA512"
    SignatureALG_IntrinsicHash _ -> "Intrinsic"
    SignatureALG_Unknown oid -> "Unknown(" ++ show oid ++ ")"
