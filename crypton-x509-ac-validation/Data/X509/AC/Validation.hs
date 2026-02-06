{-# LANGUAGE LambdaCase #-}

-- |
-- Module      : Data.X509.AC.Validation
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Profile validation for Attribute Certificates.
--
-- This module provides validation functions that enforce profile constraints
-- from RFC 5755. The design principle is "parser is lenient, validation is
-- strict" - the ASN.1 parser accepts structurally valid certificates, while
-- this module validates profile constraints.
--
-- == RFC 5755 Profile Constraints
--
-- * v1Form issuer MUST NOT be used (section 4.2.3)
-- * V2Form MUST NOT include baseCertificateID or objectDigestInfo
-- * serialNumber MUST be positive and at most 20 octets (section 4.2.5)
-- * Holder MUST have at least one field present
-- * Role attribute roleName MUST be a uniformResourceIdentifier
-- * Unknown critical extensions MUST cause rejection (RFC 5280)
--
-- == Architectural Note
--
-- This module is placed in a separate package (crypton-x509-ac-validation) to
-- follow the same architectural pattern as PKC validation (crypton-x509-validation).
-- This separation allows:
--
-- * Core parsing (crypton-x509) to remain independent of validation logic
-- * Validation rules to be updated independently
module Data.X509.AC.Validation (
    -- * Validation Results
    ValidationError (..),
    ValidationWarning (..),
    ValidationResult (..),

    -- * RFC 5755 Profile Validation
    validateRFC5755Profile,

    -- * Helper Functions
    isValid,
    hasErrors,
    hasWarnings,

    -- * Extension Validation
    validateCriticalExtensions,
    knownACExtensionOIDs,

    -- * Attribute Validation
    validateRoleAttributes,

    -- * Signature Algorithm Validation
    validateSignatureAlgorithm,
)
where

import Data.ASN1.OID (OID)
import Data.X509 (
    AltName (..),
    DistinguishedName (..),
    ExtensionRaw (..),
    Extensions (..),
 )
import Data.X509.AlgorithmIdentifier (HashALG (..), SignatureALG (..))
import Data.X509.AttCert
import Data.X509.Attribute (
    Attr_Role (..),
    Attributes,
    RoleSyntax (..),
    getAttribute,
 )

-- | Validation errors that indicate non-compliance with profile requirements.
-- These represent hard failures that MUST NOT occur per the relevant specification.
data ValidationError
    = -- | RFC 5755 4.2.3: v1Form MUST NOT be used
      V1FormNotAllowed
    | -- | RFC 5755 4.2.5: serialNumber exceeds 20 octet limit
      SerialNumberTooLong
        { snActualLength :: Int
        -- ^ Actual byte length of the serial number
        }
    | -- | RFC 5755: serialNumber MUST be positive
      SerialNumberNotPositive
        { snValue :: Integer
        -- ^ The invalid serial number value
        }
    | -- | ITU-T X.509 WITH COMPONENTS: at least one Holder field required
      HolderMissingAllFields
    | -- | RFC 5755 profile: V2Form MUST NOT contain baseCertificateID
      V2FormBaseCertificateIDPresent
    | -- | RFC 5755 profile: V2Form MUST NOT contain objectDigestInfo
      V2FormObjectDigestInfoPresent
    | -- | RFC 5755: V2Form issuerName MUST contain exactly one directoryName
      IssuerNameNotSingleDirectoryName
        { inActualCount :: Int
        -- ^ Actual number of GeneralNames present
        }
    | -- | RFC 5755: V2Form issuerName directoryName MUST NOT be empty
      IssuerDirectoryNameEmpty
    | -- | RFC 5280: Unknown critical extension MUST cause rejection
      UnknownCriticalExtension
        { uceOID :: OID
        -- ^ OID of the unknown critical extension
        }
    | -- | Weak signature algorithm (MD2, MD5) MUST NOT be used
      WeakSignatureAlgorithm
        { wsaAlgorithm :: String
        -- ^ Name of the weak algorithm
        }
    deriving (Show, Eq)

-- | Validation warnings for non-critical profile deviations.
-- These indicate potential issues but do not necessarily mean the certificate
-- is invalid.
data ValidationWarning
    = -- | RFC 5755: at least one Holder field SHOULD be present (soft requirement)
      HolderAllFieldsEmpty
    | -- | Role attribute roleName is not a URI (RFC 5755 4.4.5)
      RoleNameNotURI
    | -- | V2Form contains optional fields (baseCertificateID or objectDigestInfo)
      V2FormOptionalFieldsPresent
    | -- | Deprecated signature algorithm (SHA1) - should be avoided
      DeprecatedSignatureAlgorithm
        { dsaAlgorithm :: String
        -- ^ Name of the deprecated algorithm
        }
    deriving (Show, Eq)

-- | Result of validation containing both errors and warnings.
data ValidationResult = ValidationResult
    { vrErrors :: [ValidationError]
    , vrWarnings :: [ValidationWarning]
    }
    deriving (Show, Eq)

instance Semigroup ValidationResult where
    (ValidationResult e1 w1) <> (ValidationResult e2 w2) =
        ValidationResult (e1 <> e2) (w1 <> w2)

instance Monoid ValidationResult where
    mempty = ValidationResult [] []

-- | Check if validation passed with no errors.
isValid :: ValidationResult -> Bool
isValid = null . vrErrors

-- | Check if there are any validation errors.
hasErrors :: ValidationResult -> Bool
hasErrors = not . null . vrErrors

-- | Check if there are any validation warnings.
hasWarnings :: ValidationResult -> Bool
hasWarnings = not . null . vrWarnings

-- | Validate an AttributeCertificateInfo against RFC 5755 profile requirements.
--
-- This function checks the following constraints:
--
-- * v1Form issuer MUST NOT be used
-- * V2Form MUST NOT include baseCertificateID or objectDigestInfo
-- * serialNumber MUST be positive and at most 20 octets
-- * Holder MUST have at least one field present
-- * Unknown critical extensions MUST cause rejection (RFC 5280)
-- * Role attribute roleName SHOULD be a URI (warning if not)
-- * Weak signature algorithms (MD2, MD5) MUST NOT be used (error)
-- * Deprecated signature algorithms (SHA1) SHOULD NOT be used (warning)
--
-- Note: The parser already enforces some structural constraints, so this
-- function focuses on profile-level validation.
validateRFC5755Profile :: AttributeCertificateInfo -> ValidationResult
validateRFC5755Profile aci =
    mconcat
        [ validateIssuerRFC5755 (aciIssuer aci)
        , validateHolderRFC5755 (aciHolder aci)
        , validateSerialNumber (aciSerialNumber aci)
        , validateExtensions (aciExtensions aci)
        , validateRoleAttributes (aciAttributes aci)
        , validateSignatureAlgorithm (aciSignature aci)
        ]
  where
    validateExtensions (Extensions Nothing) = mempty
    validateExtensions (Extensions (Just exts)) = validateCriticalExtensions exts

-- | Validate the AttCertIssuer per RFC 5755 profile.
validateIssuerRFC5755 :: AttCertIssuer -> ValidationResult
validateIssuerRFC5755 = \case
    AttCertIssuerV1 _ ->
        ValidationResult [V1FormNotAllowed] []
    AttCertIssuerV2 v2 ->
        validateV2FormRFC5755 v2

-- | Validate V2Form per RFC 5755 profile.
--
-- RFC 5755 section 4.2.3:
-- * issuerName MUST contain a non-empty distinguished name
-- * baseCertificateID MUST be omitted
-- * objectDigestInfo MUST be omitted
validateV2FormRFC5755 :: V2Form -> ValidationResult
validateV2FormRFC5755 v2 =
    let errors =
            concat
                [ validateIssuerName (v2formIssuerName v2)
                , case v2formBaseCertificateID v2 of
                    Just _ -> [V2FormBaseCertificateIDPresent]
                    Nothing -> []
                , case v2formObjectDigestInfo v2 of
                    Just _ -> [V2FormObjectDigestInfoPresent]
                    Nothing -> []
                ]
     in ValidationResult errors []

-- | Validate issuerName contains exactly one non-empty directoryName.
validateIssuerName :: GeneralNames -> [ValidationError]
validateIssuerName gns = case gns of
    [AltDirectoryName (DistinguishedName dn)]
        | null dn -> [IssuerDirectoryNameEmpty]
        | otherwise -> []
    _ -> [IssuerNameNotSingleDirectoryName (length gns)]

-- | Validate Holder per RFC 5755/ITU-T X.509 requirements.
--
-- ITU-T X.509 WITH COMPONENTS constraint: at least one field MUST be present.
validateHolderRFC5755 :: Holder -> ValidationResult
validateHolderRFC5755 (Holder mBaseCert mEntity mObjDigest) =
    case (mBaseCert, mEntity, mObjDigest) of
        (Nothing, Nothing, Nothing) ->
            ValidationResult [HolderMissingAllFields] []
        _ -> ValidationResult [] []

-- | Validate serial number per RFC 5755.
--
-- RFC 5755 section 4.2.5:
-- * serialNumber MUST be a positive integer
-- * serialNumber SHOULD NOT be longer than 20 octets
validateSerialNumber :: Integer -> ValidationResult
validateSerialNumber sn
    | sn <= 0 = ValidationResult [SerialNumberNotPositive sn] []
    | byteLen > 20 = ValidationResult [SerialNumberTooLong byteLen] []
    | otherwise = ValidationResult [] []
  where
    byteLen = integerByteLength sn

-- | Calculate the byte length of an Integer when encoded in two's complement.
integerByteLength :: Integer -> Int
integerByteLength 0 = 1
integerByteLength n
    | n > 0 = (bitLen + 8) `div` 8 -- +8 to account for sign bit
    | otherwise = (bitLen + 8) `div` 8
  where
    bitLen = ceiling (logBase 2 (fromInteger (abs n) + 1) :: Double)

-- | Validate Role attributes per RFC 5755 section 4.4.5.
--
-- RFC 5755 states:
-- \"The roleName MUST be a uniformResourceIdentifier\"
--
-- This function checks all Role attributes in the certificate and reports
-- a warning if any roleName is not a URI.
validateRoleAttributes :: Attributes -> ValidationResult
validateRoleAttributes attrs =
    case getAttribute attrs :: Maybe [Attr_Role] of
        Nothing -> mempty -- No Role attributes present
        Just roles ->
            let warnings =
                    [ RoleNameNotURI
                    | Attr_Role (RoleSyntax _ rn) <- roles
                    , not (isURI rn)
                    ]
             in ValidationResult [] warnings
  where
    isURI (AltNameURI _) = True
    isURI _ = False

-- | Validate signature algorithm security.
--
-- This function checks that the signature algorithm is not weak or deprecated:
--
-- * MD2, MD5 are rejected as errors (cryptographically broken)
-- * SHA1 produces a warning (deprecated, collision attacks exist)
-- * SHA-2 family (SHA224, SHA256, SHA384, SHA512) are accepted
validateSignatureAlgorithm :: SignatureALG -> ValidationResult
validateSignatureAlgorithm sigAlg = case sigAlg of
    SignatureALG hashAlg _ -> validateHashAlg hashAlg
    SignatureALG_IntrinsicHash _ -> mempty -- EdDSA etc., hash is part of algorithm
    SignatureALG_Unknown _ -> mempty -- Unknown algorithm, cannot validate
  where
    validateHashAlg HashMD2 = ValidationResult [WeakSignatureAlgorithm "MD2"] []
    validateHashAlg HashMD5 = ValidationResult [WeakSignatureAlgorithm "MD5"] []
    validateHashAlg HashSHA1 = ValidationResult [] [DeprecatedSignatureAlgorithm "SHA1"]
    validateHashAlg _ = mempty -- SHA-2 family is acceptable

-- | Known Attribute Certificate extension OIDs that this implementation supports.
--
-- This list includes:
-- * RFC 5280 standard extensions applicable to ACs
-- * RFC 5755 AC-specific extensions
--
-- Per RFC 5280 section 4.2: If a certificate contains a critical extension
-- that is not recognized, then that certificate MUST be rejected.
knownACExtensionOIDs :: [OID]
knownACExtensionOIDs =
    [ -- RFC 5280 standard extensions
      [2, 5, 29, 35] -- authorityKeyIdentifier
    , [2, 5, 29, 31] -- cRLDistributionPoints
    , [2, 5, 29, 56] -- deltaCRLIndicator (used in some ACs)
    , [2, 5, 29, 55] -- targetingInformation
    , [2, 5, 29, 19] -- basicConstraints
    , [2, 5, 29, 15] -- keyUsage
    , [2, 5, 29, 37] -- extKeyUsage
    , [2, 5, 29, 14] -- subjectKeyIdentifier
    , [2, 5, 29, 17] -- subjectAltName
    , [2, 5, 29, 32] -- certificatePolicies
    , [2, 5, 29, 54] -- noRevAvail
    -- PKIX extensions
    , [1, 3, 6, 1, 5, 5, 7, 1, 1] -- authorityInfoAccess
    ]

-- | Validate that all critical extensions are known.
--
-- Per RFC 5280 section 4.2:
-- \"If a certificate contains a critical extension that is not recognized,
-- then that certificate MUST be rejected.\"
--
-- This function checks each extension marked as critical and reports
-- an error for any that are not in the known extension list.
validateCriticalExtensions :: [ExtensionRaw] -> ValidationResult
validateCriticalExtensions exts =
    let unknownCritical =
            [ UnknownCriticalExtension (extRawOID ext)
            | ext <- exts
            , extRawCritical ext
            , extRawOID ext `notElem` knownACExtensionOIDs
            ]
     in ValidationResult unknownCritical []
