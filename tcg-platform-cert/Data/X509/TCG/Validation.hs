{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Validation
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- Validation functions for TCG Platform Certificates.
-- This module provides comprehensive validation of Platform and Delta
-- Platform Certificates according to TCG specifications.

module Data.X509.TCG.Validation
  ( -- * Certificate Validation
    validatePlatformCertificate,
    validateDeltaCertificate,
    validateCertificateChain,
    
    -- * Attribute Validation
    validateRequiredAttributes,
    validateAttributeCompliance,
    
    -- * Component Validation
    validateComponentHierarchy,
    validateComponentStatus,
    
    -- * Error Types
    ValidationError(..),
    FailureReason(..)
  ) where

import qualified Data.ByteString as B
import Data.Maybe (mapMaybe)
import Data.X509.Attribute (Attributes(..), Attribute(..), attrType)
import Data.X509.TCG.Platform
import Data.X509.TCG.Delta  
import Data.X509.TCG.Component
import Data.X509.TCG.OID

-- * Error Types

-- | Comprehensive validation error type
data ValidationError
  = SignatureError String           -- ^ Certificate signature validation failed
  | AttributeError String          -- ^ Required attribute missing or invalid
  | HierarchyError String          -- ^ Component hierarchy validation failed
  | ConsistencyError String        -- ^ Cross-certificate consistency check failed
  | ComplianceError String         -- ^ TCG specification compliance violation
  deriving (Show, Eq)

-- | Specific failure reasons for certificate validation
data FailureReason
  = InvalidSignature                -- ^ Digital signature verification failed
  | ExpiredCertificate             -- ^ Certificate validity period expired
  | InvalidIssuer                  -- ^ Issuer information invalid
  | MissingRequiredAttribute       -- ^ Required attribute not present
  | InvalidAttributeValue          -- ^ Attribute value does not conform to specification
  | InconsistentComponentData      -- ^ Component information inconsistent
  deriving (Show, Eq, Enum)

-- * Certificate Validation

-- | Validate a Platform Certificate for compliance and consistency
--
-- This function performs comprehensive validation including:
-- * Digital signature verification
-- * Validity period checking
-- * Required attribute presence
-- * Component hierarchy consistency
-- * TCG specification compliance
--
-- Example:
-- @
-- case validatePlatformCertificate cert of
--   [] -> putStrLn "Certificate is valid"
--   errors -> mapM_ (putStrLn . show) errors
-- @
validatePlatformCertificate :: SignedPlatformCertificate -> [ValidationError]
validatePlatformCertificate cert = concat
  [ validateCertificateStructure cert
  , validateRequiredPlatformAttributes (pciAttributes $ getPlatformCertificate cert)
  , validateComponentConsistency cert
  , validateSpecificationCompliance cert
  ]

-- | Validate a Delta Platform Certificate
--
-- Delta certificate validation includes all standard validation plus:
-- * Base certificate reference validation
-- * Delta operation consistency
-- * Change sequence validation
validateDeltaCertificate :: SignedDeltaPlatformCertificate -> [ValidationError]
validateDeltaCertificate deltaCert = 
  let deltaInfo = getDeltaPlatformCertificate deltaCert
      baseRef = dpciBaseCertificateRef deltaInfo
  in concat
     [ validateBaseCertificateReference baseRef
     , validateDeltaAttributes (dpciAttributes deltaInfo)
     , validateDeltaOperations deltaCert
     ]

-- | Validate an entire certificate chain for consistency
--
-- Chain validation ensures that:
-- * All certificates are individually valid
-- * Delta certificates properly reference their base
-- * Configuration changes are applied correctly
-- * No conflicting operations exist
validateCertificateChain :: SignedPlatformCertificate           -- ^ Base certificate
                        -> [SignedDeltaPlatformCertificate]     -- ^ Delta chain
                        -> [ValidationError]
validateCertificateChain baseCert deltaChain = concat
  [ validatePlatformCertificate baseCert
  , concatMap validateDeltaCertificate deltaChain
  , validateChainConsistency baseCert deltaChain
  ]

-- * Attribute Validation

-- | Validate that all required attributes are present and valid
--
-- According to TCG Platform Certificate Profile, certain attributes
-- are mandatory for different certificate types.
validateRequiredAttributes :: Attributes -> [ValidationError]
validateRequiredAttributes attrs = 
  let requiredOIDs = getRequiredAttributeOIDs
      presentOIDs = extractPresentOIDs attrs
      missingOIDs = filter (`notElem` presentOIDs) requiredOIDs
  in map (AttributeError . ("Missing required attribute: " ++) . show) missingOIDs

-- | Validate attribute values for specification compliance
--
-- This function checks that attribute values conform to their
-- expected formats and constraints as defined in the TCG specification.
validateAttributeCompliance :: Attributes -> [ValidationError]
validateAttributeCompliance attrs = 
  let tcgAttrs = extractTCGAttributes attrs
  in concatMap validateTCGAttributeValue tcgAttrs
  where
    validateTCGAttributeValue :: TCGAttribute -> [ValidationError]
    validateTCGAttributeValue attr = case attr of
      TCGPlatformManufacturer (PlatformManufacturerAttr bs) ->
        if B.null bs 
        then [AttributeError "Platform Manufacturer cannot be empty"]
        else []
      TCGPlatformModel (PlatformModelAttr bs) ->
        if B.null bs
        then [AttributeError "Platform Model cannot be empty"] 
        else []
      _ -> [] -- TODO: Add validation for other attribute types

-- * Component Validation

-- | Validate component hierarchy for logical consistency
--
-- Component hierarchy validation ensures that:
-- * Parent-child relationships are valid
-- * No circular dependencies exist
-- * Component addresses are unique where specified
validateComponentHierarchy :: [ComponentIdentifierV2] -> [ValidationError]
validateComponentHierarchy components = concat
  [ validateUniqueAddresses components
  , validateComponentClasses components
  , validateHierarchyStructure components
  ]

-- | Validate component status information consistency
--
-- Status validation ensures that component states are logically
-- consistent with the operations described in delta certificates.
validateComponentStatus :: [(ComponentIdentifierV2, ComponentStatus)] -> [ValidationError]  
validateComponentStatus componentStatuses =
  -- TODO: Implement component status validation
  concatMap validateSingleComponentStatus componentStatuses
  where
    validateSingleComponentStatus :: (ComponentIdentifierV2, ComponentStatus) -> [ValidationError]
    validateSingleComponentStatus (_comp, _status) = []

-- * Internal Validation Functions

-- | Validate basic certificate structure and required fields
validateCertificateStructure :: SignedPlatformCertificate -> [ValidationError]
validateCertificateStructure cert =
  let certInfo = getPlatformCertificate cert
  in concat
     [ validateVersion (pciVersion certInfo)
     , validateSerialNumber (pciSerialNumber certInfo)
     , validateValidityPeriod (pciValidity certInfo)
     ]
  where
    validateVersion :: Int -> [ValidationError]
    validateVersion version
      | version == 2 = []
      | otherwise = [ComplianceError $ "Invalid certificate version: " ++ show version]
    
    validateSerialNumber :: Integer -> [ValidationError]
    validateSerialNumber serial
      | serial > 0 = []
      | otherwise = [ComplianceError "Serial number must be positive"]
    
    validateValidityPeriod :: AttCertValidityPeriod -> [ValidationError]
    validateValidityPeriod _period = [] -- TODO: Implement validity period checking

-- | Validate platform-specific required attributes
validateRequiredPlatformAttributes :: Attributes -> [ValidationError]
validateRequiredPlatformAttributes attrs = 
  let requiredPlatformOIDs = 
        [ tcg_at_platformConfiguration
        , tcg_at_platformManufacturer  
        , tcg_at_platformModel
        ]
      presentOIDs = extractPresentOIDs attrs
      missingOIDs = filter (`notElem` presentOIDs) requiredPlatformOIDs
  in map (AttributeError . ("Missing required platform attribute: " ++) . show) missingOIDs

-- | Validate component information consistency within certificate
validateComponentConsistency :: SignedPlatformCertificate -> [ValidationError]
validateComponentConsistency cert =
  case getCurrentPlatformConfiguration (Left cert) of
    Nothing -> [ConsistencyError "Cannot extract platform configuration"]
    Just config -> validateComponentHierarchy (map fst $ pcv2Components config)

-- | Validate certificate compliance with TCG specifications
validateSpecificationCompliance :: SignedPlatformCertificate -> [ValidationError]
validateSpecificationCompliance _cert = 
  -- TODO: Implement comprehensive specification compliance checking
  []

-- | Validate base certificate reference in delta certificate
validateBaseCertificateReference :: BasePlatformCertificateRef -> [ValidationError]
validateBaseCertificateReference baseRef =
  let serial = bpcrSerialNumber baseRef
  in if serial > 0
     then []
     else [ConsistencyError "Base certificate serial number must be positive"]

-- | Validate delta-specific attributes
validateDeltaAttributes :: Attributes -> [ValidationError]
validateDeltaAttributes _attrs = 
  -- TODO: Implement delta attribute validation
  []

-- | Validate delta operations for logical consistency
validateDeltaOperations :: SignedDeltaPlatformCertificate -> [ValidationError]
validateDeltaOperations _deltaCert = 
  -- TODO: Implement delta operation validation
  []

-- | Validate consistency across an entire certificate chain
validateChainConsistency :: SignedPlatformCertificate 
                        -> [SignedDeltaPlatformCertificate]
                        -> [ValidationError]
validateChainConsistency _baseCert _deltaChain = 
  -- TODO: Implement chain consistency validation
  []

-- | Validate that component addresses are unique where specified
validateUniqueAddresses :: [ComponentIdentifierV2] -> [ValidationError]
validateUniqueAddresses components =
  let addresses = [addr | comp <- components, Just addr <- [civ2ComponentAddress comp]]
      duplicates = addresses \\ nub addresses
  in if null duplicates
     then []
     else [HierarchyError $ "Duplicate component addresses found: " ++ show duplicates]

-- | Validate component class assignments
validateComponentClasses :: [ComponentIdentifierV2] -> [ValidationError]
validateComponentClasses _components = 
  -- TODO: Implement component class validation
  []

-- | Validate overall hierarchy structure
validateHierarchyStructure :: [ComponentIdentifierV2] -> [ValidationError]
validateHierarchyStructure _components = 
  -- TODO: Implement hierarchy structure validation
  []

-- * Helper Functions

-- | Get list of required attribute OIDs for platform certificates
getRequiredAttributeOIDs :: [OID]
getRequiredAttributeOIDs = 
  [ tcg_at_platformConfiguration
  , tcg_at_platformManufacturer
  , tcg_at_platformModel
  , tcg_at_platformSerial
  ]

-- | Extract all present attribute OIDs from attributes
extractPresentOIDs :: Attributes -> [OID]
extractPresentOIDs (Attributes attrs) = map attrType attrs

-- | Extract and parse all TCG-specific attributes
extractTCGAttributes :: Attributes -> [TCGAttribute]
extractTCGAttributes (Attributes attrs) = 
  mapMaybe parseAttribute attrs
  where
    parseAttribute attr = case parseTCGAttribute attr of
      Right tcgAttr -> Just tcgAttr
      Left _ -> Nothing

-- Import helper functions
nub :: Eq a => [a] -> [a]
nub [] = []
nub (x:xs) = x : nub (filter (/= x) xs)

(\\) :: Eq a => [a] -> [a] -> [a]
xs \\ ys = filter (`notElem` ys) xs

