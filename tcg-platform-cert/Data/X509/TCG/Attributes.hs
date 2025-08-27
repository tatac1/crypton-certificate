{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE InstanceSigs #-}

-- |
-- Module      : Data.X509.TCG.Attributes
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate attributes and attribute processing.
--
-- This module implements the specific attributes defined in the IWG Platform 
-- Certificate Profile v1.1, including Platform Configuration, Component 
-- Identification, and TPM-related attributes.
module Data.X509.TCG.Attributes
  ( -- * TCG Attribute Types
    TCGAttribute (..),
    TCGAttributeValue (..),
    
    -- * Platform Configuration Attributes
    PlatformConfigurationAttr (..),
    PlatformConfigurationV2Attr (..),
    
    -- * Component Attributes
    ComponentIdentifierAttr (..),
    ComponentIdentifierV2Attr (..),
    ComponentClassAttr (..),
    
    -- * Platform Information Attributes
    PlatformManufacturerAttr (..),
    PlatformModelAttr (..),
    PlatformSerialAttr (..),
    PlatformVersionAttr (..),
    
    -- * TPM Attributes
    TPMModelAttr (..),
    TPMVersionAttr (..),
    TPMSpecificationAttr (..),
    
    -- * Certificate Extension Attributes
    RelevantCredentialsAttr (..),
    RelevantManifestsAttr (..),
    VirtualPlatformAttr (..),
    MultiTenantAttr (..),
    
    -- * Attribute Parsing and Encoding
    parseTCGAttribute,
    encodeTCGAttribute,
    lookupTCGAttribute,
    validateTCGAttributes,
    
    -- * Attribute Utilities
    attributeOIDToType,
    attributeTypeToOID,
    isRequiredAttribute,
    isCriticalAttribute,
  ) where

import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Data.ASN1.Types
import Data.ASN1.Parse
import Data.X509.Attribute (AttributeType(..), AttributeValue(..), Attribute(..))
import Data.X509.TCG.OID
import Data.X509.TCG.Component (ComponentIdentifier, ComponentIdentifierV2, ComponentClass)
import Data.X509.TCG.Platform (PlatformConfiguration, PlatformConfigurationV2, TPMInfo, TPMVersion, TPMSpecification)

-- | TCG Attribute enumeration
--
-- Represents all types of attributes defined in the TCG specifications.
data TCGAttribute
  = TCGPlatformConfiguration PlatformConfigurationAttr
  | TCGPlatformConfigurationV2 PlatformConfigurationV2Attr
  | TCGComponentIdentifier ComponentIdentifierAttr
  | TCGComponentIdentifierV2 ComponentIdentifierV2Attr
  | TCGComponentClass ComponentClassAttr
  | TCGPlatformManufacturer PlatformManufacturerAttr
  | TCGPlatformModel PlatformModelAttr
  | TCGPlatformSerial PlatformSerialAttr
  | TCGPlatformVersion PlatformVersionAttr
  | TCGTPMModel TPMModelAttr
  | TCGTPMVersion TPMVersionAttr
  | TCGTPMSpecification TPMSpecificationAttr
  | TCGRelevantCredentials RelevantCredentialsAttr
  | TCGRelevantManifests RelevantManifestsAttr
  | TCGVirtualPlatform VirtualPlatformAttr
  | TCGMultiTenant MultiTenantAttr
  | TCGOtherAttribute OID B.ByteString  -- ^ For unknown/custom attributes
  deriving (Show, Eq)

-- | TCG Attribute Value wrapper
data TCGAttributeValue = TCGAttributeValue
  { tcgAttrOID :: OID,
    tcgAttrValue :: B.ByteString,
    tcgAttrCritical :: Bool
  }
  deriving (Show, Eq)

-- * Platform Configuration Attributes

-- | Platform Configuration attribute (v1)
data PlatformConfigurationAttr = PlatformConfigurationAttr
  { pcaConfiguration :: PlatformConfiguration,
    pcaTimestamp :: Maybe B.ByteString,
    pcaCertificationLevel :: Maybe Int
  }
  deriving (Show, Eq)

-- | Platform Configuration attribute (v2) with status tracking
data PlatformConfigurationV2Attr = PlatformConfigurationV2Attr
  { pcv2aConfiguration :: PlatformConfigurationV2,
    pcv2aTimestamp :: Maybe B.ByteString,
    pcv2aCertificationLevel :: Maybe Int,
    pcv2aChangeSequence :: Maybe Integer
  }
  deriving (Show, Eq)

-- * Component Attributes

-- | Component Identifier attribute (v1)
data ComponentIdentifierAttr = ComponentIdentifierAttr
  { ciaIdentifier :: ComponentIdentifier,
    ciaTimestamp :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Identifier attribute (v2)
data ComponentIdentifierV2Attr = ComponentIdentifierV2Attr
  { ci2aIdentifier :: ComponentIdentifierV2,
    ci2aTimestamp :: Maybe B.ByteString,
    ci2aCertificationInfo :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Class attribute
data ComponentClassAttr = ComponentClassAttr
  { ccaClass :: ComponentClass,
    ccaDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- * Platform Information Attributes

-- | Platform Manufacturer attribute
newtype PlatformManufacturerAttr = PlatformManufacturerAttr
  { pmaManufacturer :: B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Model attribute
newtype PlatformModelAttr = PlatformModelAttr
  { pmdaModel :: B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Serial attribute
newtype PlatformSerialAttr = PlatformSerialAttr
  { psaSerial :: B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Version attribute
newtype PlatformVersionAttr = PlatformVersionAttr
  { pvaVersion :: B.ByteString
  }
  deriving (Show, Eq)

-- * TPM Attributes

-- | TPM Model attribute
newtype TPMModelAttr = TPMModelAttr
  { tmaModel :: B.ByteString
  }
  deriving (Show, Eq)

-- | TPM Version attribute
newtype TPMVersionAttr = TPMVersionAttr
  { tvaVersion :: TPMVersion
  }
  deriving (Show, Eq)

-- | TPM Specification attribute
newtype TPMSpecificationAttr = TPMSpecificationAttr
  { tsaSpecification :: TPMSpecification
  }
  deriving (Show, Eq)

-- * Certificate Extension Attributes

-- | Relevant Credentials attribute
data RelevantCredentialsAttr = RelevantCredentialsAttr
  { rcaCredentials :: [B.ByteString],
    rcaCritical :: Bool
  }
  deriving (Show, Eq)

-- | Relevant Manifests attribute
data RelevantManifestsAttr = RelevantManifestsAttr
  { rmaManifests :: [B.ByteString],
    rmaCritical :: Bool
  }
  deriving (Show, Eq)

-- | Virtual Platform attribute
data VirtualPlatformAttr = VirtualPlatformAttr
  { vpaIsVirtual :: Bool,
    vpaHypervisorInfo :: Maybe B.ByteString,
    vpaCritical :: Bool
  }
  deriving (Show, Eq)

-- | Multi-Tenant attribute
data MultiTenantAttr = MultiTenantAttr
  { mtaIsMultiTenant :: Bool,
    mtaTenantInfo :: Maybe [B.ByteString],
    mtaCritical :: Bool
  }
  deriving (Show, Eq)

-- * Registry-based Attribute Parsing

-- | Type alias for attribute parser functions
type AttributeParser = [[AttributeValue]] -> Either String TCGAttribute

-- | Registry mapping OIDs to their corresponding parser functions
--
-- This registry-based approach replaces the long conditional chain
-- with a more maintainable and extensible lookup table.
attributeParserRegistry :: Map.Map OID AttributeParser
attributeParserRegistry = Map.fromList
  [ (tcg_at_platformConfiguration, parsePlatformConfigAttr)
  , (tcg_at_platformConfiguration_v2, parsePlatformConfigV2Attr)
  , (tcg_at_componentIdentifier, parseComponentIdAttr)
  , (tcg_at_componentIdentifier_v2, parseComponentIdV2Attr)
  , (tcg_at_componentClass, parseComponentClassAttr)
  , (tcg_at_platformManufacturer, parsePlatformMfgAttr)
  , (tcg_at_platformModel, parsePlatformModelAttr)
  , (tcg_at_platformSerial, parsePlatformSerialAttr)
  , (tcg_at_platformVersion, parsePlatformVersionAttr)
  , (tcg_at_tpmModel, parseTPMModelAttr)
  , (tcg_at_tpmVersion, parseTPMVersionAttr)
  , (tcg_at_tpmSpecification, parseTPMSpecAttr)
  , (tcg_ce_relevantCredentials, parseRelevantCredAttr)
  , (tcg_ce_relevantManifests, parseRelevantManiAttr)
  , (tcg_ce_virtualPlatform, parseVirtualPlatAttr)
  , (tcg_ce_multiTenant, parseMultiTenantAttr)
  ]

-- | Parse a TCG attribute from an ASN.1 Attribute using registry lookup
--
-- This function uses the registry pattern to dispatch parsing based on OID,
-- making it easy to add new attribute types by simply adding entries to the registry.
parseTCGAttribute :: Attribute -> Either String TCGAttribute
parseTCGAttribute attr = 
  let oid = attrType attr
      values = attrValues attr
  in case Map.lookup oid attributeParserRegistry of
       Just parser -> parser values
       Nothing -> parseOtherAttr oid values  -- Fallback for unknown attributes

-- | Encode a TCG attribute to an ASN.1 Attribute
encodeTCGAttribute :: TCGAttribute -> Attribute
encodeTCGAttribute tcgAttr = 
  case tcgAttr of
    TCGPlatformConfiguration attr -> encodeAttribute tcg_at_platformConfiguration [encodePlatformConfigAttr attr]
    TCGPlatformConfigurationV2 attr -> encodeAttribute tcg_at_platformConfiguration_v2 [encodePlatformConfigV2Attr attr]
    TCGComponentIdentifier attr -> encodeAttribute tcg_at_componentIdentifier [encodeComponentIdAttr attr]
    TCGComponentIdentifierV2 attr -> encodeAttribute tcg_at_componentIdentifier_v2 [encodeComponentIdV2Attr attr]
    TCGComponentClass attr -> encodeAttribute tcg_at_componentClass [encodeComponentClassAttr attr]
    TCGPlatformManufacturer attr -> encodeAttribute tcg_at_platformManufacturer [encodePlatformMfgAttr attr]
    TCGPlatformModel attr -> encodeAttribute tcg_at_platformModel [encodePlatformModelAttr attr]
    TCGPlatformSerial attr -> encodeAttribute tcg_at_platformSerial [encodePlatformSerialAttr attr]
    TCGPlatformVersion attr -> encodeAttribute tcg_at_platformVersion [encodePlatformVersionAttr attr]
    TCGTPMModel attr -> encodeAttribute tcg_at_tpmModel [encodeTPMModelAttr attr]
    TCGTPMVersion attr -> encodeAttribute tcg_at_tpmVersion [encodeTPMVersionAttr attr]
    TCGTPMSpecification attr -> encodeAttribute tcg_at_tpmSpecification [encodeTPMSpecAttr attr]
    TCGRelevantCredentials attr -> encodeAttribute tcg_ce_relevantCredentials [encodeRelevantCredAttr attr]
    TCGRelevantManifests attr -> encodeAttribute tcg_ce_relevantManifests [encodeRelevantManiAttr attr]
    TCGVirtualPlatform attr -> encodeAttribute tcg_ce_virtualPlatform [encodeVirtualPlatAttr attr]
    TCGMultiTenant attr -> encodeAttribute tcg_ce_multiTenant [encodeMultiTenantAttr attr]
    TCGOtherAttribute oid value -> encodeAttribute oid [[OctetString value]]

-- | Lookup a TCG attribute by OID in a list of attributes
lookupTCGAttribute :: OID -> [Attribute] -> Maybe TCGAttribute
lookupTCGAttribute targetOID attrs = 
  case filter (matchesOID targetOID) attrs of
    [] -> Nothing
    (attr:_) -> case parseTCGAttribute attr of
      Right tcgAttr -> Just tcgAttr
      Left _ -> Nothing
  where
    matchesOID :: OID -> Attribute -> Bool
    matchesOID oid attr = attrType attr == oid

-- | Validate a list of TCG attributes for compliance
validateTCGAttributes :: [TCGAttribute] -> [String]
validateTCGAttributes attrs = 
  checkRequiredAttributes attrs ++ 
  concatMap validateSingleAttribute attrs

-- * Attribute Utilities

-- | Convert attribute OID to TCG attribute type identifier
attributeOIDToType :: OID -> String
attributeOIDToType oid
  | oid == tcg_at_platformConfiguration = "platformConfiguration"
  | oid == tcg_at_platformConfiguration_v2 = "platformConfiguration_v2"
  | oid == tcg_at_componentIdentifier = "componentIdentifier"
  | oid == tcg_at_componentIdentifier_v2 = "componentIdentifier_v2"
  | oid == tcg_at_componentClass = "componentClass"
  | oid == tcg_at_platformManufacturer = "platformManufacturer"
  | oid == tcg_at_platformModel = "platformModel"
  | oid == tcg_at_platformSerial = "platformSerial"
  | oid == tcg_at_platformVersion = "platformVersion"
  | oid == tcg_at_tpmModel = "tpmModel"
  | oid == tcg_at_tpmVersion = "tpmVersion"
  | oid == tcg_at_tpmSpecification = "tpmSpecification"
  | otherwise = "unknown"

-- | Convert TCG attribute type to OID
attributeTypeToOID :: String -> Maybe OID
attributeTypeToOID typeName = 
  case typeName of
    "platformConfiguration" -> Just tcg_at_platformConfiguration
    "platformConfiguration_v2" -> Just tcg_at_platformConfiguration_v2
    "componentIdentifier" -> Just tcg_at_componentIdentifier
    "componentIdentifier_v2" -> Just tcg_at_componentIdentifier_v2
    "componentClass" -> Just tcg_at_componentClass
    "platformManufacturer" -> Just tcg_at_platformManufacturer
    "platformModel" -> Just tcg_at_platformModel
    "platformSerial" -> Just tcg_at_platformSerial
    "platformVersion" -> Just tcg_at_platformVersion
    "tpmModel" -> Just tcg_at_tpmModel
    "tpmVersion" -> Just tcg_at_tpmVersion
    "tpmSpecification" -> Just tcg_at_tpmSpecification
    _ -> Nothing

-- | Check if an attribute is required in Platform Certificates
isRequiredAttribute :: OID -> Bool
isRequiredAttribute oid = oid `elem` requiredAttributes
  where
    requiredAttributes = 
      [ tcg_at_platformConfiguration_v2
      , tcg_at_componentIdentifier_v2
      ]

-- | Check if an attribute is marked as critical
isCriticalAttribute :: OID -> Bool
isCriticalAttribute oid = oid `elem` criticalAttributes
  where
    criticalAttributes = 
      [ tcg_ce_relevantCredentials
      , tcg_ce_relevantManifests
      ]

-- Helper functions for parsing individual attribute types

parsePlatformConfigAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformConfigAttr _ = Left "Platform Configuration parsing not yet implemented"

parsePlatformConfigV2Attr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformConfigV2Attr _ = Left "Platform Configuration v2 parsing not yet implemented"

parseComponentIdAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseComponentIdAttr _ = Left "Component Identifier parsing not yet implemented"

parseComponentIdV2Attr :: [[AttributeValue]] -> Either String TCGAttribute
parseComponentIdV2Attr _ = Left "Component Identifier v2 parsing not yet implemented"

parseComponentClassAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseComponentClassAttr _ = Left "Component Class parsing not yet implemented"

parsePlatformMfgAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformMfgAttr [[OctetString bs]] = Right $ TCGPlatformManufacturer (PlatformManufacturerAttr bs)
parsePlatformMfgAttr _ = Left "Invalid Platform Manufacturer attribute"

parsePlatformModelAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformModelAttr [[OctetString bs]] = Right $ TCGPlatformModel (PlatformModelAttr bs)
parsePlatformModelAttr _ = Left "Invalid Platform Model attribute"

parsePlatformSerialAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformSerialAttr [[OctetString bs]] = Right $ TCGPlatformSerial (PlatformSerialAttr bs)
parsePlatformSerialAttr _ = Left "Invalid Platform Serial attribute"

parsePlatformVersionAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformVersionAttr [[OctetString bs]] = Right $ TCGPlatformVersion (PlatformVersionAttr bs)
parsePlatformVersionAttr _ = Left "Invalid Platform Version attribute"

parseTPMModelAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseTPMModelAttr [[OctetString bs]] = Right $ TCGTPMModel (TPMModelAttr bs)
parseTPMModelAttr _ = Left "Invalid TPM Model attribute"

parseTPMVersionAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseTPMVersionAttr _ = Left "TPM Version parsing not yet implemented"

parseTPMSpecAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseTPMSpecAttr _ = Left "TPM Specification parsing not yet implemented"

parseRelevantCredAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseRelevantCredAttr _ = Left "Relevant Credentials parsing not yet implemented"

parseRelevantManiAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseRelevantManiAttr _ = Left "Relevant Manifests parsing not yet implemented"

parseVirtualPlatAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseVirtualPlatAttr _ = Left "Virtual Platform parsing not yet implemented"

parseMultiTenantAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseMultiTenantAttr _ = Left "Multi-Tenant parsing not yet implemented"

parseOtherAttr :: OID -> [[AttributeValue]] -> Either String TCGAttribute
parseOtherAttr oid [[OctetString bs]] = Right $ TCGOtherAttribute oid bs
parseOtherAttr oid _ = Left $ "Invalid other attribute with OID: " ++ show oid

-- Helper functions for encoding individual attribute types

encodeAttribute :: OID -> [[AttributeValue]] -> Attribute
encodeAttribute oid values = Attribute oid values

encodePlatformConfigAttr :: PlatformConfigurationAttr -> [AttributeValue]
encodePlatformConfigAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodePlatformConfigV2Attr :: PlatformConfigurationV2Attr -> [AttributeValue]
encodePlatformConfigV2Attr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeComponentIdAttr :: ComponentIdentifierAttr -> [AttributeValue]
encodeComponentIdAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeComponentIdV2Attr :: ComponentIdentifierV2Attr -> [AttributeValue]
encodeComponentIdV2Attr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeComponentClassAttr :: ComponentClassAttr -> [AttributeValue]
encodeComponentClassAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodePlatformMfgAttr :: PlatformManufacturerAttr -> [AttributeValue]
encodePlatformMfgAttr (PlatformManufacturerAttr bs) = [OctetString bs]

encodePlatformModelAttr :: PlatformModelAttr -> [AttributeValue]
encodePlatformModelAttr (PlatformModelAttr bs) = [OctetString bs]

encodePlatformSerialAttr :: PlatformSerialAttr -> [AttributeValue]
encodePlatformSerialAttr (PlatformSerialAttr bs) = [OctetString bs]

encodePlatformVersionAttr :: PlatformVersionAttr -> [AttributeValue]
encodePlatformVersionAttr (PlatformVersionAttr bs) = [OctetString bs]

encodeTPMModelAttr :: TPMModelAttr -> [AttributeValue]
encodeTPMModelAttr (TPMModelAttr bs) = [OctetString bs]

encodeTPMVersionAttr :: TPMVersionAttr -> [AttributeValue]
encodeTPMVersionAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeTPMSpecAttr :: TPMSpecificationAttr -> [AttributeValue]
encodeTPMSpecAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeRelevantCredAttr :: RelevantCredentialsAttr -> [AttributeValue]
encodeRelevantCredAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeRelevantManiAttr :: RelevantManifestsAttr -> [AttributeValue]
encodeRelevantManiAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeVirtualPlatAttr :: VirtualPlatformAttr -> [AttributeValue]
encodeVirtualPlatAttr _ = [OctetString B.empty] -- TODO: Implement encoding

encodeMultiTenantAttr :: MultiTenantAttr -> [AttributeValue]
encodeMultiTenantAttr _ = [OctetString B.empty] -- TODO: Implement encoding

-- Helper functions for validation

checkRequiredAttributes :: [TCGAttribute] -> [String]
checkRequiredAttributes attrs = 
  let presentOIDs = map getAttributeOID attrs
      missingRequired = filter (`notElem` presentOIDs) requiredAttributeOIDs
  in map (\oid -> "Missing required attribute: " ++ attributeOIDToType oid) missingRequired
  where
    requiredAttributeOIDs = 
      [ tcg_at_platformConfiguration_v2
      , tcg_at_componentIdentifier_v2
      ]
    
    getAttributeOID :: TCGAttribute -> OID
    getAttributeOID attr = case attr of
      TCGPlatformConfiguration _ -> tcg_at_platformConfiguration
      TCGPlatformConfigurationV2 _ -> tcg_at_platformConfiguration_v2
      TCGComponentIdentifier _ -> tcg_at_componentIdentifier
      TCGComponentIdentifierV2 _ -> tcg_at_componentIdentifier_v2
      TCGComponentClass _ -> tcg_at_componentClass
      TCGPlatformManufacturer _ -> tcg_at_platformManufacturer
      TCGPlatformModel _ -> tcg_at_platformModel
      TCGPlatformSerial _ -> tcg_at_platformSerial
      TCGPlatformVersion _ -> tcg_at_platformVersion
      TCGTPMModel _ -> tcg_at_tpmModel
      TCGTPMVersion _ -> tcg_at_tpmVersion
      TCGTPMSpecification _ -> tcg_at_tpmSpecification
      TCGRelevantCredentials _ -> tcg_ce_relevantCredentials
      TCGRelevantManifests _ -> tcg_ce_relevantManifests
      TCGVirtualPlatform _ -> tcg_ce_virtualPlatform
      TCGMultiTenant _ -> tcg_ce_multiTenant
      TCGOtherAttribute oid _ -> oid

validateSingleAttribute :: TCGAttribute -> [String]
validateSingleAttribute attr = 
  case attr of
    TCGPlatformManufacturer (PlatformManufacturerAttr bs) ->
      if B.null bs then ["Platform Manufacturer cannot be empty"] else []
    TCGPlatformModel (PlatformModelAttr bs) ->
      if B.null bs then ["Platform Model cannot be empty"] else []
    _ -> [] -- TODO: Add validation for other attribute types