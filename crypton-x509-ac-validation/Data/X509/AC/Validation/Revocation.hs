{-# LANGUAGE LambdaCase #-}

-- |
-- Module      : Data.X509.AC.Validation.Revocation
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Attribute Certificate revocation checking.
--
-- This module provides revocation status checking for:
--
-- * The Attribute Certificate itself (via ACRL - Attribute Certificate Revocation List)
-- * The AA certificate that issued the AC (via standard CRL)
--
-- Note: Per RFC 5755, ACRLs use the same format as PKI CRLs but with the
-- onlyContainsAttributeCerts flag set in the IssuingDistributionPoint extension.
--
-- == PKITS Test Coverage
--
-- This module covers tests AC-REV-6.1 through AC-REV-6.6:
--
-- * AC-REV-6.1: AC revoked (on ACRL)
-- * AC-REV-6.2: AC not revoked (not on ACRL)
-- * AC-REV-6.3: AA certificate revoked
-- * AC-REV-6.4: CRL expired
-- * AC-REV-6.5: CRL signature invalid
-- * AC-REV-6.6: Revocation status unknown (no CRL available)
module Data.X509.AC.Validation.Revocation (
    -- * Revocation Checking
    checkACRevocation,
    checkCRLValidity,
    isSerialRevoked,
    RevocationError (..),
    RevocationResult (..),
)
where

import Data.Hourglass (DateTime, Seconds (..), timeDiff)
import Data.List (find)
import Data.X509 (
    CRL (..),
    Certificate (..),
    PubKey,
    RevokedCertificate (..),
    SignedCRL,
    getSigned,
    signedObject,
 )
import Data.X509.AttCert
import Data.X509.Validation (SignatureVerification (..), verifySignedSignature)
import Data.X509AC (SignedAttributeCertificate)

-- | Errors related to revocation checking.
data RevocationError
    = -- | The AC has been revoked (found on ACRL)
      ACRevoked
        { acrSerialNumber :: Integer
        -- ^ Serial number of the revoked AC
        , acrRevocationDate :: DateTime
        -- ^ Date the AC was revoked
        }
    | -- | The AA certificate has been revoked
      AARevoked
        { aarSerialNumber :: Integer
        -- ^ Serial number of the revoked AA certificate
        , aarRevocationDate :: DateTime
        -- ^ Date the AA certificate was revoked
        }
    | -- | The CRL has expired (nextUpdate is in the past)
      CRLExpired
        { creNextUpdate :: DateTime
        -- ^ The CRL's nextUpdate time
        , creValidationTime :: DateTime
        -- ^ Time at which validation was performed
        }
    | -- | The CRL signature is invalid
      CRLSignatureInvalid
        { csiReason :: String
        -- ^ Description of signature failure
        }
    | -- | Revocation status could not be determined (no CRL available)
      RevocationStatusUnknown
        { rsuReason :: String
        -- ^ Reason revocation status is unknown
        }
    deriving (Show, Eq)

-- | Result of revocation checking.
data RevocationResult
    = -- | Not revoked (explicitly checked against CRL)
      NotRevoked
    | -- | Revocation check failed with error
      RevocationFailed RevocationError
    | -- | CRL not available, revocation status unknown
      RevocationUnknown String
    deriving (Show, Eq)

-- | Check AC revocation status.
--
-- This function checks:
--
-- 1. If an ACRL is provided, verify the AC is not on it
-- 2. If an AA CRL is provided, verify the AA certificate is not revoked
-- 3. If no CRLs are provided, returns RevocationUnknown
--
-- The function does NOT verify CRL signatures - use 'checkCRLValidity' first
-- to ensure CRL integrity before calling this function.
checkACRevocation
    :: DateTime
    -- ^ Validation time
    -> Maybe SignedCRL
    -- ^ Optional ACRL for checking AC revocation
    -> Maybe SignedCRL
    -- ^ Optional CRL for checking AA certificate revocation
    -> Certificate
    -- ^ AA certificate
    -> SignedAttributeCertificate
    -- ^ Signed Attribute Certificate to check
    -> RevocationResult
checkACRevocation validationTime mAcrl mAaCrl aaCert signedAC
    -- If no CRLs provided, status is unknown
    | Nothing <- mAcrl
    , Nothing <- mAaCrl =
        RevocationUnknown "No CRL or ACRL provided"
    | otherwise =
        let aci = signedObject (getSigned signedAC)
            acSerial = aciSerialNumber aci
            aaSerial = certSerial aaCert
         in -- Check AA certificate revocation first (if CRL provided)
            case mAaCrl of
                Just aaCrl ->
                    let crl = signedObject (getSigned aaCrl)
                     in case checkCRLNotExpired validationTime crl of
                            Just err -> RevocationFailed err
                            Nothing ->
                                case isSerialRevoked aaSerial crl of
                                    Just revCert ->
                                        RevocationFailed $
                                            AARevoked aaSerial (revokedDate revCert)
                                    Nothing ->
                                        checkACOnACRL validationTime mAcrl acSerial
                Nothing ->
                    checkACOnACRL validationTime mAcrl acSerial

-- | Check if AC is on ACRL.
checkACOnACRL
    :: DateTime
    -> Maybe SignedCRL
    -> Integer
    -> RevocationResult
checkACOnACRL _ Nothing _ = NotRevoked -- No ACRL means we can't check AC revocation
checkACOnACRL validationTime (Just acrl) acSerial =
    let crl = signedObject (getSigned acrl)
     in case checkCRLNotExpired validationTime crl of
            Just err -> RevocationFailed err
            Nothing ->
                case isSerialRevoked acSerial crl of
                    Just revCert ->
                        RevocationFailed $
                            ACRevoked acSerial (revokedDate revCert)
                    Nothing -> NotRevoked

-- | Check if a serial number appears on a CRL.
--
-- Returns the RevokedCertificate entry if found, Nothing otherwise.
isSerialRevoked :: Integer -> CRL -> Maybe RevokedCertificate
isSerialRevoked serialNum crl =
    find (\rc -> revokedSerialNumber rc == serialNum) (crlRevokedCertificates crl)

-- | Check if a CRL has expired.
checkCRLNotExpired :: DateTime -> CRL -> Maybe RevocationError
checkCRLNotExpired validationTime crl =
    case crlNextUpdate crl of
        Nothing -> Nothing -- No nextUpdate means CRL doesn't expire
        Just nextUpdate ->
            if isAfter validationTime nextUpdate
                then Just $ CRLExpired nextUpdate validationTime
                else Nothing

-- | Validate CRL integrity.
--
-- This function verifies:
--
-- 1. The CRL signature is valid (using the issuer's public key)
-- 2. The CRL has not expired (nextUpdate is not in the past)
--
-- Call this function before using 'checkACRevocation' to ensure CRL integrity.
checkCRLValidity
    :: DateTime
    -- ^ Validation time
    -> PubKey
    -- ^ Public key of the CRL issuer
    -> SignedCRL
    -- ^ Signed CRL to validate
    -> RevocationResult
checkCRLValidity validationTime pubKey signedCRL =
    let crl = signedObject (getSigned signedCRL)
     in -- Check signature first
        case verifySignedSignature signedCRL pubKey of
            SignatureFailed failure ->
                RevocationFailed $ CRLSignatureInvalid (show failure)
            SignaturePass ->
                case checkCRLNotExpired validationTime crl of
                    Just err -> RevocationFailed err
                    Nothing -> NotRevoked

-- | Check if time1 is strictly after time2.
isAfter :: DateTime -> DateTime -> Bool
isAfter time1 time2 = timeDiff time1 time2 > Seconds 0
