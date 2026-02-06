{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Data.X509.AC.Validation.Path
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Attribute Certificate path validation.
--
-- This module provides validation of the certification path from a trust
-- anchor to the Attribute Authority (AA) that issued the AC, including:
--
-- * Issuer name matching between AC and AA certificate
-- * Basic Constraints checking (AA must be a CA)
-- * Key Usage checking (AA must have appropriate key usage)
--
-- == PKITS Test Coverage
--
-- This module covers tests:
--
-- * AC-ISS-3.1 through AC-ISS-3.6: Issuer verification
-- * AC-BC-4.1 through AC-BC-4.5: Basic Constraints
-- * AC-KU-5.1 through AC-KU-5.3: Key Usage
module Data.X509.AC.Validation.Path (
    -- * Path Validation
    validateACIssuer,
    validateAABasicConstraints,
    validateAAKeyUsage,
    PathError (..),
    PathResult (..),

    -- * DN Matching
    matchDistinguishedName,
)
where

import Data.ASN1.Types (ASN1CharacterString (..))
import Data.Char (toLower)
import Data.List (find)
import Data.X509 (
    AltName (..),
    Certificate (..),
    DistinguishedName (..),
    ExtBasicConstraints (..),
    ExtKeyUsage (..),
    ExtKeyUsageFlag (..),
    Extension (..),
    ExtensionRaw (..),
    Extensions (..),
    getSigned,
    signedObject,
 )
import Data.X509.AttCert
import Data.X509AC (SignedAttributeCertificate)

-- | Errors related to path validation.
data PathError
    = -- | AC issuer does not match AA certificate subject
      IssuerMismatch
        { imACIssuer :: [AltName]
        -- ^ Issuer names in the AC
        , imAASubject :: DistinguishedName
        -- ^ Subject DN of the AA certificate
        }
    | -- | AA certificate does not have basicConstraints with cA=true
      AANotCA
        { ancReason :: String
        -- ^ Reason why the AA is not considered a CA
        }
    | -- | Path length constraint exceeded
      PathTooLong
        { ptlMaxLen :: Int
        -- ^ Maximum allowed path length
        , ptlActualLen :: Int
        -- ^ Actual path length
        }
    | -- | AA certificate does not have required key usage
      InvalidKeyUsage
        { ikuMissing :: [ExtKeyUsageFlag]
        -- ^ Required key usage flags that are missing
        }
    deriving (Show, Eq)

-- | Result of path validation.
data PathResult
    = -- | Validation passed
      PathOK
    | -- | Validation failed with error
      PathFailed PathError
    deriving (Show, Eq)

-- | Validate that the AC issuer matches the AA certificate.
--
-- The AC issuer (V2Form.issuerName) must contain at least one GeneralName
-- that matches the AA certificate's subject DN.
--
-- DN matching follows X.500 rules:
-- * Case insensitive comparison for printable strings
-- * Whitespace normalization (leading/trailing removed, internal collapsed)
-- * RDN order must match
validateACIssuer
    :: Certificate
    -- ^ AA certificate (issuer of the AC)
    -> SignedAttributeCertificate
    -- ^ Signed Attribute Certificate
    -> PathResult
validateACIssuer aaCert signedAC =
    let aci = signedObject (getSigned signedAC)
        aaSubjectDN = certSubjectDN aaCert
     in case aciIssuer aci of
            AttCertIssuerV1 gns ->
                validateIssuerNames gns aaSubjectDN
            AttCertIssuerV2 v2 ->
                validateIssuerNames (v2formIssuerName v2) aaSubjectDN

-- | Validate issuer names against AA subject DN.
validateIssuerNames :: [AltName] -> DistinguishedName -> PathResult
validateIssuerNames [] aaSubjectDN =
    PathFailed $ IssuerMismatch [] aaSubjectDN
validateIssuerNames issuerNames aaSubjectDN =
    case find (matchesAASubject aaSubjectDN) issuerNames of
        Just _ -> PathOK
        Nothing -> PathFailed $ IssuerMismatch issuerNames aaSubjectDN
  where
    matchesAASubject dn (AltDirectoryName issDN) = matchDistinguishedName dn issDN
    matchesAASubject _ _ = False

-- | Match two DistinguishedNames using X.500 rules.
--
-- This performs case-insensitive matching for printable strings
-- and basic whitespace normalization.
matchDistinguishedName :: DistinguishedName -> DistinguishedName -> Bool
matchDistinguishedName (DistinguishedName rdns1) (DistinguishedName rdns2)
    | length rdns1 /= length rdns2 = False
    | otherwise = all matchRDN (zip rdns1 rdns2)
  where
    matchRDN ((oid1, val1), (oid2, val2)) =
        oid1 == oid2 && normalizeAndCompare val1 val2

    normalizeAndCompare :: ASN1CharacterString -> ASN1CharacterString -> Bool
    normalizeAndCompare (ASN1CharacterString _ bs1) (ASN1CharacterString _ bs2) =
        map toLower (normalizeWhitespace $ show bs1)
            == map toLower (normalizeWhitespace $ show bs2)

    normalizeWhitespace :: String -> String
    normalizeWhitespace = unwords . words

-- | Validate AA certificate basic constraints.
--
-- For an AA to issue Attribute Certificates, it should have:
-- * basicConstraints extension present
-- * cA = TRUE
--
-- Note: The pathLenConstraint check is performed separately if there
-- is a certificate chain involved.
validateAABasicConstraints
    :: Certificate
    -- ^ AA certificate
    -> PathResult
validateAABasicConstraints cert =
    case getExtensionFromCert cert of
        Nothing ->
            PathFailed $ AANotCA "No basicConstraints extension"
        Just (ExtBasicConstraints isCA _) ->
            if isCA
                then PathOK
                else PathFailed $ AANotCA "basicConstraints.cA is FALSE"

-- | Validate AA certificate key usage.
--
-- An AA certificate that issues ACs should have:
-- * KeyUsage_keyCertSign for signing ACs (or digitalSignature)
--
-- For CRL signing, KeyUsage_cRLSign is also required.
validateAAKeyUsage
    :: Certificate
    -- ^ AA certificate
    -> PathResult
validateAAKeyUsage cert =
    case getExtensionFromCert cert of
        Nothing ->
            -- No keyUsage extension means all usages are permitted (per RFC 5280)
            PathOK
        Just (ExtKeyUsage flags) ->
            let hasKeyCertSign = KeyUsage_keyCertSign `elem` flags
                hasDigitalSig = KeyUsage_digitalSignature `elem` flags
             in if hasKeyCertSign || hasDigitalSig
                    then PathOK
                    else
                        PathFailed $
                            InvalidKeyUsage
                                [KeyUsage_keyCertSign, KeyUsage_digitalSignature]

-- | Get an extension from a certificate.
getExtensionFromCert :: forall a. Extension a => Certificate -> Maybe a
getExtensionFromCert cert =
    case certExtensions cert of
        Extensions Nothing -> Nothing
        Extensions (Just exts) ->
            case find matchOID exts of
                Nothing -> Nothing
                Just (ExtensionRaw _ _ bs) -> either (const Nothing) Just (extDecodeBs bs)
  where
    matchOID :: ExtensionRaw -> Bool
    matchOID (ExtensionRaw oid _ _) = oid == extOID (undefined :: a)
