-- |
-- Module      : Data.X509AC
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write X.509 Attribute Certificate and their signed equivalents.
--
-- This module provides functionality for handling Attribute Certificates as defined
-- in RFC 5755. Attribute Certificates are similar to X.509 Public Key Certificates
-- but are used to bind attributes (rather than public keys) to holders.
--
-- For general-purpose X.509 types and signing functions (e.g., 'DistinguishedName',
-- 'objectToSignedExactF', 'PrivKey'), please import the main 'Data.X509' module.
--
-- For validation functions (profile validation, critical extension checking, etc.),
-- import the 'Data.X509.AC.Validation' module from the crypton-x509-ac-validation package.
module Data.X509AC (
    -- * Core Types
    SignedAttributeCertificate,
    AttributeCertificateInfo (..),

    -- * Validity and Identification
    AttCertValidityPeriod (..),
    UniqueID,

    -- * Holder Information
    Holder (..),
    IssuerSerial (..),
    ObjectDigestInfo (..),
    DigestedObjectType (..),

    -- * Issuer Information
    AttCertIssuer (..),
    V2Form (..),

    -- * Attributes
    module Data.X509.Attribute,

    -- * Marshalling Operations
    encodeSignedAttributeCertificate,
    decodeSignedAttributeCertificate,

    -- * Accessor Functions
    getAttributesCertificate,
    getHolder,
    getIssuer,
    getAttributes,
    getValidity,
    getSerialNumber,

    -- * AC Extensions
    module Data.X509.AC.Extension,
)
where

import qualified Data.ByteString as B
import Data.X509.AttCert
import Data.X509.AC.Extension
import Data.X509.Attribute
import Data.X509.Signed

-- | A Signed Attribute Certificate is a 'SignedExact' of an 'AttributeCertificateInfo'.
--
-- This type represents a complete, signed attribute certificate that can be
-- encoded/decoded and has its signature verified. It maintains both the
-- parsed structure and the original raw bytes for signature verification.
type SignedAttributeCertificate = SignedExact AttributeCertificateInfo

-- * Marshalling Operations

-- | Encode a SignedAttributeCertificate to a DER-encoded bytestring.
--
-- This function serializes the complete signed attribute certificate,
-- including the signature, into DER format suitable for storage or transmission.
encodeSignedAttributeCertificate :: SignedAttributeCertificate -> B.ByteString
encodeSignedAttributeCertificate = encodeSignedObject

-- | Decode a DER-encoded bytestring to a SignedAttributeCertificate.
--
-- This function parses a DER-encoded attribute certificate and maintains
-- the original raw bytes for signature verification purposes.
--
-- Returns 'Left' with an error message if parsing fails,
-- or 'Right' with the parsed certificate if successful.
decodeSignedAttributeCertificate
    :: B.ByteString -> Either String SignedAttributeCertificate
decodeSignedAttributeCertificate = decodeSignedObject

-- * Accessor Functions

-- | Extract the AttributeCertificateInfo from a SignedAttributeCertificate.
--
-- This returns the core certificate information without the signature data.
getAttributesCertificate
    :: SignedAttributeCertificate -> AttributeCertificateInfo
getAttributesCertificate = signedObject . getSigned

-- | Extract the holder information from an attribute certificate.
--
-- The holder identifies the entity to which the attributes are bound.
getHolder :: SignedAttributeCertificate -> Holder
getHolder = aciHolder . getAttributesCertificate

-- | Extract the issuer information from an attribute certificate.
--
-- The issuer identifies the Attribute Authority (AA) that issued the certificate.
getIssuer :: SignedAttributeCertificate -> AttCertIssuer
getIssuer = aciIssuer . getAttributesCertificate

-- | Extract the attributes from an attribute certificate.
--
-- These are the actual attributes (roles, clearances, etc.) bound to the holder.
getAttributes :: SignedAttributeCertificate -> Attributes
getAttributes = aciAttributes . getAttributesCertificate

-- | Extract the validity period from an attribute certificate.
--
-- Returns the time period during which the certificate is valid.
getValidity :: SignedAttributeCertificate -> AttCertValidityPeriod
getValidity = aciValidity . getAttributesCertificate

-- | Extract the serial number from an attribute certificate.
--
-- The serial number uniquely identifies the certificate within the
-- context of the issuing Attribute Authority.
getSerialNumber :: SignedAttributeCertificate -> Integer
getSerialNumber = aciSerialNumber . getAttributesCertificate
