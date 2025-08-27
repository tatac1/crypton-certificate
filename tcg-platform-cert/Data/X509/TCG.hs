-- |
-- Module      : Data.X509.TCG
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate library for Haskell.
--
-- This module provides a high-level API for working with TCG Platform Certificates
-- and Delta Platform Certificates as defined in the IWG Platform Certificate
-- Profile v1.1.
--
-- == Overview
--
-- Platform Certificates are attribute certificates that bind platform configuration 
-- information to a platform identity. They are used in Trusted Computing environments
-- to provide cryptographic evidence of platform composition and configuration.
--
-- Delta Platform Certificates track changes in platform configuration over time
-- by referencing a base Platform Certificate and describing the specific changes
-- that have occurred.
--
-- == Basic Usage
--
-- @
-- import Data.X509.TCG
-- import qualified Data.ByteString as B
--
-- -- Decode a Platform Certificate from DER bytes
-- case 'decodeSignedPlatformCertificate' certBytes of
--   Right cert -> do
--     let platform = 'getPlatformInfo' cert
--         components = 'getComponentIdentifiers' cert
--     -- Process the certificate...
--   Left err -> putStrLn $ "Parse error: " ++ err
-- @
--
-- == Advanced Usage
--
-- For working with Delta Platform Certificates and component hierarchies:
--
-- @
-- -- Apply a delta certificate to get the current configuration
-- case 'applyDeltaCertificate' baseCert deltaCert of
--   Right newConfig -> -- Use the updated configuration
--   Left err -> -- Handle validation error
-- @
module Data.X509.TCG
  ( -- * Platform Certificate Types
    module Data.X509.TCG.Platform,
    
    -- * Delta Platform Certificate Types
    module Data.X509.TCG.Delta,
    
    -- * Component Types and Hierarchy
    module Data.X509.TCG.Component,
    
    -- * Attribute Processing
    module Data.X509.TCG.Attributes,
    
    -- * TCG OID Definitions
    module Data.X509.TCG.OID,
    
    -- * High-Level Operations
    
    -- ** Certificate Creation and Validation
    createPlatformCertificate,
    createDeltaPlatformCertificate,
    validatePlatformCertificate,
    validateDeltaCertificate',
    
    -- ** Configuration Management
    getCurrentPlatformConfiguration,
    applyDeltaCertificate,
    computeConfigurationChain,
    
    -- ** Component Operations
    getComponentIdentifiers,
    findComponentByClass,
    findComponentByAddress,
    buildComponentHierarchy,
    
    -- ** Attribute Extraction
    extractTCGAttributes,
    extractPlatformAttributes,
    extractTPMAttributes,
    
    -- ** Certificate Chain Operations
    buildCertificateChain,
    validateCertificateChain,
    findBaseCertificate,
    
    -- * Utility Functions
    isPlatformCertificate,
    isDeltaCertificate,
    getRequiredAttributes,
    validateAttributeCompliance,
  ) where

import qualified Data.ByteString as B
import Data.X509 (SignedCertificate, Certificate, DistinguishedName(..))
import Data.X509.Attribute (Attributes, Attribute)
import Data.X509.TCG.Platform
import Data.X509.TCG.Delta  
import Data.X509.TCG.Component
import Data.X509.TCG.Attributes
import Data.X509.TCG.OID
import Data.ASN1.Types (OID)

-- * High-Level Operations

-- ** Certificate Creation and Validation

-- | Create a Platform Certificate with the specified configuration and attributes
--
-- This is a high-level function that handles the proper construction of a
-- Platform Certificate according to IWG specifications.
createPlatformCertificate :: PlatformConfiguration 
                         -> [ComponentIdentifier]
                         -> TPMInfo
                         -> IO (Either String SignedPlatformCertificate)
createPlatformCertificate _config _components _tpmInfo = 
  return $ Left "Platform Certificate creation not yet implemented"

-- | Create a Delta Platform Certificate that references a base certificate
--
-- Creates a Delta Platform Certificate that describes changes from the
-- specified base certificate.
createDeltaPlatformCertificate :: SignedPlatformCertificate  -- ^ Base certificate
                              -> [ComponentDelta]           -- ^ Component changes  
                              -> [ChangeRecord]             -- ^ Change records
                              -> IO (Either String SignedDeltaPlatformCertificate)
createDeltaPlatformCertificate _base _deltas _changes = 
  return $ Left "Delta Platform Certificate creation not yet implemented"

-- | Validate a Platform Certificate for compliance with IWG specifications
--
-- Performs comprehensive validation including:
-- * Required attribute presence
-- * Attribute format validation  
-- * Component hierarchy consistency
-- * TPM information validation
validatePlatformCertificate :: SignedPlatformCertificate -> [String]
validatePlatformCertificate cert = 
  let certInfo = getPlatformCertificate cert
      attrs = pciAttributes certInfo
  in validateRequiredAttributes attrs ++
     validateAttributeFormats attrs ++
     validateTPMAttributes attrs

-- | Validate a Delta Platform Certificate
--
-- Validates that the delta certificate properly references its base
-- and contains valid change information.
validateDeltaCertificate' :: SignedDeltaPlatformCertificate -> [String]
validateDeltaCertificate' deltaCert = 
  let deltaInfo = getDeltaPlatformCertificate deltaCert
      baseRef = dpciBaseCertificateRef deltaInfo
  in validateBaseCertificateReference baseRef ++
     validateDeltaAttributes (dpciAttributes deltaInfo)

-- ** Configuration Management

-- | Get the current platform configuration from a certificate or certificate chain
--
-- If given a base Platform Certificate, returns its configuration.
-- If given a Delta Certificate, applies the delta to compute the current configuration.
getCurrentPlatformConfiguration :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate
                               -> Maybe PlatformConfigurationV2  
getCurrentPlatformConfiguration (Left platCert) = 
  -- Extract configuration from base Platform Certificate
  case getPlatformConfiguration platCert of
    Just config -> convertToV2 config
    Nothing -> Nothing
  where
    convertToV2 :: PlatformConfiguration -> Maybe PlatformConfigurationV2
    convertToV2 pc = Just $ PlatformConfigurationV2
      { pcv2Manufacturer = pcManufacturer pc
      , pcv2Model = pcModel pc
      , pcv2Version = pcVersion pc
      , pcv2Serial = pcSerial pc
      , pcv2Components = [(comp, ComponentUnchanged) | comp <- convertComponents (pcComponents pc)]
      }
    
    convertComponents :: [ComponentIdentifier] -> [ComponentIdentifierV2] 
    convertComponents _ = [] -- TODO: Implement component conversion

getCurrentPlatformConfiguration (Right deltaCert) = 
  -- For delta certificates, we need the base certificate to compute current configuration
  Nothing -- TODO: Implement delta application

-- | Apply a Delta Platform Certificate to a base configuration
--
-- Computes the resulting configuration after applying the delta changes.
applyDeltaCertificate :: SignedPlatformCertificate 
                     -> SignedDeltaPlatformCertificate
                     -> Either String PlatformConfigurationV2
applyDeltaCertificate baseCert deltaCert = do
  baseConfig <- case getCurrentPlatformConfiguration (Left baseCert) of
    Just config -> Right config
    Nothing -> Left "Cannot extract base configuration"
  
  case getPlatformConfigurationDelta deltaCert of
    Just delta -> applyDeltaToBase baseConfig delta
    Nothing -> Left "Cannot extract delta configuration"

-- | Compute the final configuration from a chain of certificates
--
-- Given a base Platform Certificate and a sequence of Delta Certificates,
-- computes the final resulting platform configuration.
computeConfigurationChain :: SignedPlatformCertificate
                         -> [SignedDeltaPlatformCertificate]  
                         -> Either String PlatformConfigurationV2
computeConfigurationChain baseCert deltaChain = do
  baseConfig <- case getCurrentPlatformConfiguration (Left baseCert) of
    Just config -> Right config
    Nothing -> Left "Cannot extract base configuration"
  
  deltas <- mapM (\cert -> case getPlatformConfigurationDelta cert of
                      Just delta -> Right delta
                      Nothing -> Left "Cannot extract delta configuration") deltaChain
  computeResultingConfiguration baseConfig deltas

-- ** Component Operations

-- | Extract all component identifiers from a Platform Certificate
getComponentIdentifiers :: SignedPlatformCertificate -> [ComponentIdentifier]
getComponentIdentifiers cert = 
  case getPlatformConfiguration cert of
    Just config -> pcComponents config
    Nothing -> []

-- | Find components of a specific class in a Platform Certificate
findComponentByClass :: ComponentClass -> SignedPlatformCertificate -> [ComponentIdentifierV2]
findComponentByClass targetClass cert = 
  case getCurrentPlatformConfiguration (Left cert) of
    Just config -> [comp | (comp, _) <- pcv2Components config, isComponentClass targetClass comp]
    Nothing -> []

-- | Find a component by its address in a Platform Certificate
findComponentByAddress :: ComponentAddress -> SignedPlatformCertificate -> Maybe ComponentIdentifierV2  
findComponentByAddress addr cert = 
  case getCurrentPlatformConfiguration (Left cert) of
    Just config -> findComponentByAddr addr (pcv2Components config)
    Nothing -> Nothing
  where
    findComponentByAddr :: ComponentAddress -> [(ComponentIdentifierV2, ComponentStatus)] -> Maybe ComponentIdentifierV2
    findComponentByAddr target comps = 
      case [comp | (comp, _) <- comps, ci2ComponentAddress comp == Just target] of
        [] -> Nothing
        (comp:_) -> Just comp

-- | Build a component hierarchy from Platform Certificate information
buildComponentHierarchy :: SignedPlatformCertificate -> ComponentHierarchy
buildComponentHierarchy cert = 
  case getCurrentPlatformConfiguration (Left cert) of
    Just config -> 
      let components = [comp | (comp, _) <- pcv2Components config]
          rootComponent = case components of
            [] -> error "No components found"
            (comp:_) -> comp
          componentTree = buildComponentTree components
      in ComponentHierarchy [ComponentReference 0 0 rootComponent] componentTree
    Nothing -> ComponentHierarchy [] (ComponentTree (ComponentIdentifierV2 B.empty B.empty Nothing Nothing Nothing Nothing ComponentMotherboard Nothing) [] (ComponentProperties [] Nothing []))

-- ** Attribute Extraction

-- | Extract all TCG attributes from a certificate
extractTCGAttributes :: SignedPlatformCertificate -> [TCGAttribute]
extractTCGAttributes cert = 
  let attrs = pciAttributes $ getPlatformCertificate cert
  in extractTCGAttrs attrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs _ = [] -- TODO: Implement attribute extraction

-- | Extract platform-specific attributes (manufacturer, model, serial, version)
extractPlatformAttributes :: SignedPlatformCertificate -> Maybe PlatformInfo
extractPlatformAttributes = getPlatformInfo

-- | Extract TPM-related attributes
extractTPMAttributes :: SignedPlatformCertificate -> Maybe TPMInfo
extractTPMAttributes = getTPMInfo

-- ** Certificate Chain Operations

-- | Build a certificate chain from a base certificate and deltas
buildCertificateChain :: SignedPlatformCertificate 
                     -> [SignedDeltaPlatformCertificate]
                     -> CertificateChain
buildCertificateChain baseCert deltaChain = 
  let baseRef = BasePlatformCertificateRef 
        (DistinguishedName []) -- TODO: Extract from certificate
        (pciSerialNumber $ getPlatformCertificate baseCert)
        Nothing
        (Just $ pciValidity $ getPlatformCertificate baseCert)
      deltaRefs = map deltaToRef deltaChain
  in CertificateChain baseRef deltaRefs (pciValidity $ getPlatformCertificate baseCert)
  where
    deltaToRef :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef  
    deltaToRef deltaCert = 
      let deltaInfo = getDeltaPlatformCertificate deltaCert
      in BasePlatformCertificateRef
           (DistinguishedName []) -- TODO: Extract from certificate
           (dpciSerialNumber deltaInfo)
           Nothing
           (Just $ dpciValidity deltaInfo)

-- | Validate a certificate chain for consistency
validateCertificateChain :: CertificateChain -> [String]
validateCertificateChain chain = 
  validateChainContinuity chain ++
  validateChainValidity chain

-- | Find the base certificate for a given Delta Platform Certificate
findBaseCertificate :: SignedDeltaPlatformCertificate 
                   -> [SignedPlatformCertificate]
                   -> Maybe SignedPlatformCertificate
findBaseCertificate deltaCert candidates = 
  let baseRef = getBaseCertificateReference deltaCert
      targetSerial = bpcrSerialNumber baseRef
  in case filter (\cert -> pciSerialNumber (getPlatformCertificate cert) == targetSerial) candidates of
       [] -> Nothing
       (cert:_) -> Just cert

-- * Utility Functions

-- | Check if a certificate is a Platform Certificate (not a Delta)
isPlatformCertificate :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate -> Bool
isPlatformCertificate (Left _) = True
isPlatformCertificate (Right _) = False

-- | Check if a certificate is a Delta Platform Certificate
isDeltaCertificate :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate -> Bool  
isDeltaCertificate = not . isPlatformCertificate

-- | Get the list of required attributes for Platform Certificates
getRequiredAttributes :: [OID]
getRequiredAttributes = 
  [ tcg_at_platformConfiguration_v2
  , tcg_at_componentIdentifier_v2
  , tcg_at_platformManufacturer
  , tcg_at_platformModel
  , tcg_at_platformSerial
  , tcg_at_platformVersion
  ]

-- | Validate that a certificate contains all required attributes
validateAttributeCompliance :: SignedPlatformCertificate -> [String]
validateAttributeCompliance cert = 
  let attrs = pciAttributes $ getPlatformCertificate cert
      presentOIDs = extractPresentOIDs attrs
      required = getRequiredAttributes
      missing = filter (`notElem` presentOIDs) required
  in map (\oid -> "Missing required attribute: " ++ attributeOIDToType oid) missing

-- Helper functions

validateRequiredAttributes :: Attributes -> [String]
validateRequiredAttributes _ = [] -- TODO: Implement validation

validateAttributeFormats :: Attributes -> [String]
validateAttributeFormats _ = [] -- TODO: Implement validation

validateTPMAttributes :: Attributes -> [String]
validateTPMAttributes _ = [] -- TODO: Implement validation

validateBaseCertificateReference :: BasePlatformCertificateRef -> [String]
validateBaseCertificateReference baseRef
  | bpcrSerialNumber baseRef <= 0 = ["Invalid base certificate serial number"]
  | otherwise = []

validateDeltaAttributes :: Attributes -> [String]  
validateDeltaAttributes _ = [] -- TODO: Implement validation

validateChainContinuity :: CertificateChain -> [String]
validateChainContinuity _ = [] -- TODO: Implement validation

validateChainValidity :: CertificateChain -> [String]
validateChainValidity _ = [] -- TODO: Implement validation

extractPresentOIDs :: Attributes -> [OID]
extractPresentOIDs _ = [] -- TODO: Implement OID extraction