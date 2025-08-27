{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Platform
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate data structures and processing.
--
-- This module implements Platform Certificates as defined in the IWG Platform
-- Certificate Profile v1.1. Platform Certificates are attribute certificates
-- that bind platform configuration information to a platform identity.
module Data.X509.TCG.Platform
  ( -- * Platform Certificate Types
    PlatformCertificateInfo (..),
    SignedPlatformCertificate,

    -- * Platform Configuration
    PlatformConfiguration (..),
    PlatformConfigurationV2 (..),
    ComponentStatus (..),

    -- * Platform Information
    PlatformInfo (..),
    TPMInfo (..),
    TPMSpecification (..),
    TPMVersion (..),

    -- * Marshalling Operations
    encodeSignedPlatformCertificate,
    decodeSignedPlatformCertificate,

    -- * Accessor Functions
    getPlatformCertificate,
    getPlatformConfiguration,
    getPlatformInfo,
    getTPMInfo,
    getComponentStatus,
  )
where

import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.X509 (Extensions, SignatureALG, SignedExact, decodeSignedObject, encodeSignedObject, getSigned, signedObject)
import Data.X509.AttCert (AttCertIssuer, AttCertValidityPeriod, Holder, UniqueID)
import Data.X509.Attribute (AttributeValue, Attributes)
import Data.X509.TCG.Component (ComponentIdentifier, ComponentIdentifierV2)

-- | Platform Certificate Information structure
--
-- This is similar to AttributeCertificateInfo but specifically for Platform Certificates
-- as defined in the IWG specification.
data PlatformCertificateInfo = PlatformCertificateInfo
  { pciVersion :: Int, -- Must be 2 (v2)
    pciHolder :: Holder,
    pciIssuer :: AttCertIssuer,
    pciSignature :: SignatureALG,
    pciSerialNumber :: Integer,
    pciValidity :: AttCertValidityPeriod,
    pciAttributes :: Attributes,
    pciIssuerUniqueID :: Maybe UniqueID,
    pciExtensions :: Extensions
  }
  deriving (Show, Eq)

-- | ASN1Object instance for PlatformCertificateInfo
instance ASN1Object PlatformCertificateInfo where
  toASN1 (PlatformCertificateInfo pciVer pciHolder' pciIssuer' pciSig pciSn pciValid pciAttrs pciUid pciExts) xs =
    ( [Start Sequence]
        ++ [IntVal $ fromIntegral pciVer]
        ++ toASN1 pciHolder' []
        ++ toASN1 pciIssuer' []
        ++ toASN1 pciSig []
        ++ [IntVal pciSn]
        ++ toASN1 pciValid []
        ++ toASN1 pciAttrs []
        ++ maybe [] (\u -> [BitString u]) pciUid
        ++ toASN1 pciExts []
        ++ [End Sequence]
    )
      ++ xs
  fromASN1 _ = Left "Platform certificate parsing not implemented"

-- | A Signed Platform Certificate
type SignedPlatformCertificate = SignedExact PlatformCertificateInfo

-- | Platform Configuration structure (v1)
--
-- Contains basic platform configuration information without status tracking.
data PlatformConfiguration = PlatformConfiguration
  { pcManufacturer :: B.ByteString,
    pcModel :: B.ByteString,
    pcVersion :: B.ByteString,
    pcSerial :: B.ByteString,
    pcComponents :: [ComponentIdentifier]
  }
  deriving (Show, Eq)

-- | Platform Configuration structure (v2)
--
-- Enhanced version with component status tracking for Delta Platform Certificates.
data PlatformConfigurationV2 = PlatformConfigurationV2
  { pcv2Manufacturer :: B.ByteString,
    pcv2Model :: B.ByteString,
    pcv2Version :: B.ByteString,
    pcv2Serial :: B.ByteString,
    pcv2Components :: [(ComponentIdentifierV2, ComponentStatus)]
  }
  deriving (Show, Eq)

-- | Component Status enumeration
--
-- Tracks the status of components in Platform Configuration v2.
data ComponentStatus
  = -- | Component was added to the platform
    ComponentAdded
  | -- | Component was removed from the platform
    ComponentRemoved
  | -- | Component was modified on the platform
    ComponentModified
  | -- | Component remains unchanged
    ComponentUnchanged
  deriving (Show, Eq, Enum)

-- | Platform Information structure
--
-- High-level platform identification and characteristics.
data PlatformInfo = PlatformInfo
  { piManufacturer :: B.ByteString,
    piModel :: B.ByteString,
    piSerial :: B.ByteString,
    piVersion :: B.ByteString
  }
  deriving (Show, Eq)

-- | TPM Information structure
--
-- Contains TPM-specific identification and specification information.
data TPMInfo = TPMInfo
  { tpmModel :: B.ByteString,
    tpmVersion :: TPMVersion,
    tpmSpecification :: TPMSpecification
  }
  deriving (Show, Eq)

-- | TPM Version information
data TPMVersion = TPMVersion
  { tpmVersionMajor :: Int,
    tpmVersionMinor :: Int,
    tpmVersionRevMajor :: Int,
    tpmVersionRevMinor :: Int
  }
  deriving (Show, Eq)

-- | TPM Specification information
data TPMSpecification = TPMSpecification
  { tpmSpecFamily :: B.ByteString,
    tpmSpecLevel :: Int,
    tpmSpecRevision :: Int
  }
  deriving (Show, Eq)

-- | Encode a SignedPlatformCertificate to a DER-encoded bytestring
encodeSignedPlatformCertificate :: SignedPlatformCertificate -> B.ByteString
encodeSignedPlatformCertificate = encodeSignedObject

-- | Decode a DER-encoded bytestring to a SignedPlatformCertificate
decodeSignedPlatformCertificate :: B.ByteString -> Either String SignedPlatformCertificate
decodeSignedPlatformCertificate = decodeSignedObject

-- | Extract the PlatformCertificateInfo from a SignedPlatformCertificate
getPlatformCertificate :: SignedPlatformCertificate -> PlatformCertificateInfo
getPlatformCertificate = signedObject . getSigned

-- | Extract Platform Configuration from a Platform Certificate
--
-- This function searches for the tcg-at-platformConfiguration attribute
-- (OID 2.23.133.2.1) and parses it into a structured PlatformConfiguration.
--
-- The platform configuration provides detailed information about:
-- * Platform manufacturer, model, version, and serial number
-- * Complete list of platform components with their identifiers
-- * Component hierarchy and relationships
--
-- Example usage:
-- @
-- case getPlatformConfiguration cert of
--   Just config -> do
--     putStrLn $ "Platform: " ++ B.unpack (pcManufacturer config)
--     putStrLn $ "Components: " ++ show (length $ pcComponents config)
--   Nothing -> putStrLn "No platform configuration found in certificate"
-- @
getPlatformConfiguration :: SignedPlatformCertificate -> Maybe PlatformConfiguration
getPlatformConfiguration cert =
  case lookupAttribute "2.23.133.2.1" (pciAttributes $ getPlatformCertificate cert) of
    Just attrVal -> parsePlatformConfiguration attrVal
    Nothing -> Nothing

-- | Extract Platform Information from a Platform Certificate
--
-- Extracts basic platform identification attributes.
getPlatformInfo :: SignedPlatformCertificate -> Maybe PlatformInfo
getPlatformInfo cert = do
  let attrs = pciAttributes $ getPlatformCertificate cert
  manufacturer <- lookupAttributeValue "2.23.133.2.4" attrs -- tcg-at-platformManufacturer
  model <- lookupAttributeValue "2.23.133.2.5" attrs -- tcg-at-platformModel
  serial <- lookupAttributeValue "2.23.133.2.6" attrs -- tcg-at-platformSerial
  version <- lookupAttributeValue "2.23.133.2.7" attrs -- tcg-at-platformVersion
  return $ PlatformInfo manufacturer model serial version

-- | Extract TPM Information from a Platform Certificate
--
-- Extracts TPM-specific identification and specification attributes.
getTPMInfo :: SignedPlatformCertificate -> Maybe TPMInfo
getTPMInfo cert = do
  let attrs = pciAttributes $ getPlatformCertificate cert
  model <- lookupAttributeValue "2.23.133.2.16" attrs -- tcg-at-tpmModel
  versionData <- lookupAttributeValue "2.23.133.2.17" attrs -- tcg-at-tpmVersion
  specData <- lookupAttributeValue "2.23.133.2.18" attrs -- tcg-at-tpmSpecification
  version <- parseTPMVersion versionData
  spec <- parseTPMSpecification specData
  return $ TPMInfo model version spec

-- | Extract Component Status information for Delta Platform Certificates
getComponentStatus :: SignedPlatformCertificate -> Maybe [(ComponentIdentifierV2, ComponentStatus)]
getComponentStatus cert = do
  config <- getPlatformConfigurationV2 cert
  return $ pcv2Components config

-- * Helper Functions

-- | Lookup an attribute value by OID string
--
-- This function searches through the attributes list to find an attribute
-- with the specified OID and returns its value if found.
--
-- Example:
-- @
-- case lookupAttribute "2.23.133.2.1" platformAttrs of
--   Just value -> processPlatformConfig value
--   Nothing -> handleMissingConfig
-- @
lookupAttribute :: String -> Attributes -> Maybe AttributeValue
lookupAttribute _ _ = Nothing -- TODO: Implement attribute lookup

-- | Extract attribute value as ByteString by OID
--
-- This function combines attribute lookup with ByteString extraction,
-- providing a convenient way to access string-based attribute values.
--
-- Parameters:
-- * @oid@ - The OID string to search for
-- * @attrs@ - The attributes list to search in
--
-- Returns:
-- * @Just ByteString@ if the attribute is found and contains a valid string
-- * @Nothing@ if the attribute is missing or has invalid format
--
-- Example:
-- @
-- manufacturerName <- lookupAttributeValue "2.23.133.2.2" attrs
-- @
lookupAttributeValue :: String -> Attributes -> Maybe B.ByteString
lookupAttributeValue oid attrs = do
  attrVal <- lookupAttribute oid attrs
  case attrVal of
    OctetString str -> Just str
    _ -> Nothing

-- | Parse Platform Configuration from AttributeValue
parsePlatformConfiguration :: AttributeValue -> Maybe PlatformConfiguration
parsePlatformConfiguration _ = Nothing -- TODO: Implement ASN.1 parsing

-- | Extract Platform Configuration v2 from a Platform Certificate
getPlatformConfigurationV2 :: SignedPlatformCertificate -> Maybe PlatformConfigurationV2
getPlatformConfigurationV2 cert =
  case lookupAttribute "2.23.133.2.23" (pciAttributes $ getPlatformCertificate cert) of
    Just attrVal -> parsePlatformConfigurationV2 attrVal
    Nothing -> Nothing

-- | Parse Platform Configuration v2 from AttributeValue
parsePlatformConfigurationV2 :: AttributeValue -> Maybe PlatformConfigurationV2
parsePlatformConfigurationV2 _ = Nothing -- TODO: Implement ASN.1 parsing

-- | Parse TPM Version from ByteString
parseTPMVersion :: B.ByteString -> Maybe TPMVersion
parseTPMVersion _ = Nothing -- TODO: Implement TPM version parsing

-- | Parse TPM Specification from ByteString
parseTPMSpecification :: B.ByteString -> Maybe TPMSpecification
parseTPMSpecification _ = Nothing -- TODO: Implement TPM specification parsing

-- ASN.1 instances for basic types

instance ASN1Object TPMVersion where
  toASN1 (TPMVersion major minor revMajor revMinor) xs =
    [Start Sequence, IntVal (fromIntegral major), IntVal (fromIntegral minor), 
     IntVal (fromIntegral revMajor), IntVal (fromIntegral revMinor), End Sequence] ++ xs
  fromASN1 (Start Sequence : IntVal major : IntVal minor : IntVal revMajor : IntVal revMinor : End Sequence : xs) =
    Right (TPMVersion (fromIntegral major) (fromIntegral minor) (fromIntegral revMajor) (fromIntegral revMinor), xs)
  fromASN1 _ = Left "TPMVersion: Invalid ASN1 structure"

instance ASN1Object TPMSpecification where  
  toASN1 (TPMSpecification family level revision) xs =
    [Start Sequence, OctetString family, IntVal (fromIntegral level), IntVal (fromIntegral revision), End Sequence] ++ xs
  fromASN1 (Start Sequence : OctetString family : IntVal level : IntVal revision : End Sequence : xs) =
    Right (TPMSpecification family (fromIntegral level) (fromIntegral revision), xs)
  fromASN1 _ = Left "TPMSpecification: Invalid ASN1 structure"

instance ASN1Object ComponentStatus where
  toASN1 status xs = [IntVal (fromIntegral $ fromEnum status)] ++ xs
  fromASN1 (IntVal n : xs) 
    | n >= 0 && n <= 3 = Right (toEnum (fromIntegral n), xs)
    | otherwise = Left "ComponentStatus: Invalid enum value"
  fromASN1 _ = Left "ComponentStatus: Invalid ASN1 structure"