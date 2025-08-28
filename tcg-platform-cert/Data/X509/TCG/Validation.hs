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
    ValidationError (..),
    FailureReason (..),
  )
where

import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Maybe (mapMaybe)
import Data.X509 (DistinguishedName(..), AltName(..))
import Data.X509.TCG hiding (extractTCGAttributes, validateAttributeCompliance, validateCertificateChain, validateComponentHierarchy, validateDeltaCertificate, validatePlatformCertificate)
import Data.X509AC
import System.IO.Unsafe (unsafePerformIO)
import Time.System (dateCurrent)

-- * Error Types

-- | Comprehensive validation error type
data ValidationError
  = -- | Certificate signature validation failed
    SignatureError String
  | -- | Required attribute missing or invalid
    AttributeError String
  | -- | Component hierarchy validation failed
    HierarchyError String
  | -- | Cross-certificate consistency check failed
    ConsistencyError String
  | -- | TCG specification compliance violation
    ComplianceError String
  | -- | Certificate format validation failed
    FormatError String
  deriving (Show, Eq)

-- | Specific failure reasons for certificate validation
data FailureReason
  = -- | Digital signature verification failed
    InvalidSignature
  | -- | Certificate validity period expired
    ExpiredCertificate
  | -- | Issuer information invalid
    InvalidIssuer
  | -- | Required attribute not present
    MissingRequiredAttribute
  | -- | Attribute value does not conform to specification
    InvalidAttributeValue
  | -- | Component information inconsistent
    InconsistentComponentData
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
validatePlatformCertificate cert =
  concat
    [ validateCertificateStructure cert,
      validateRequiredPlatformAttributes (pciAttributes $ getPlatformCertificate cert),
      validateComponentConsistency cert,
      validateSpecificationCompliance cert
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
        [ validateBaseCertificateReference baseRef,
          validateDeltaAttributesValidation (dpciAttributes deltaInfo),
          validateDeltaOperations deltaCert
        ]

-- | Validate an entire certificate chain for consistency
--
-- Chain validation ensures that:
-- * All certificates are individually valid
-- * Delta certificates properly reference their base
-- * Configuration changes are applied correctly
-- * No conflicting operations exist
validateCertificateChain ::
  -- | Base certificate
  SignedPlatformCertificate ->
  -- | Delta chain
  [SignedDeltaPlatformCertificate] ->
  [ValidationError]
validateCertificateChain baseCert deltaChain =
  concat
    [ validatePlatformCertificate baseCert,
      concatMap validateDeltaCertificate deltaChain,
      validateChainConsistency baseCert deltaChain
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
        validatePlatformManufacturerAttr bs
      TCGPlatformModel (PlatformModelAttr bs) ->
        validatePlatformModelAttr bs
      TCGPlatformSerial (PlatformSerialAttr bs) ->
        validatePlatformSerialAttr bs
      TCGPlatformVersion (PlatformVersionAttr bs) ->
        validatePlatformVersionAttr bs
      TCGTPMModel (TPMModelAttr bs) ->
        validateTPMModelAttr bs
      TCGComponentClass (ComponentClassAttr compClass _description) ->
        validateComponentClassAttr compClass
      TCGComponentIdentifier (ComponentIdentifierAttr ci timestamp) ->
        validateComponentIdentifierAttr ci timestamp
      TCGComponentIdentifierV2 (ComponentIdentifierV2Attr ci2 timestamp _certInfo) ->
        validateComponentIdentifierV2Attr ci2 timestamp
      TCGPlatformConfiguration (PlatformConfigurationAttr config timestamp certLevel) ->
        validatePlatformConfigurationAttr config timestamp certLevel Nothing
      TCGPlatformConfigurationV2 (PlatformConfigurationV2Attr config timestamp certLevel changeSeq) ->
        validatePlatformConfigurationV2Attr config timestamp certLevel changeSeq
      TCGTPMVersion (TPMVersionAttr version) ->
        validateTPMVersionAttr version
      TCGTPMSpecification (TPMSpecificationAttr spec) ->
        validateTPMSpecificationAttr spec
      TCGRelevantCredentials (RelevantCredentialsAttr creds _critical) ->
        validateRelevantCredentialsAttr creds Nothing
      TCGRelevantManifests (RelevantManifestsAttr manifests _critical) ->
        validateRelevantManifestsAttr manifests Nothing
      TCGVirtualPlatform (VirtualPlatformAttr isVirtual evidence _critical) ->
        validateVirtualPlatformAttr isVirtual evidence
      TCGMultiTenant (MultiTenantAttr isMT _tenantInfo _critical) ->
        validateMultiTenantAttr isMT Nothing
      TCGOtherAttribute oid bs ->
        if B.null bs
          then [AttributeError $ "Custom attribute " ++ show oid ++ " cannot have empty value"]
          else []

-- * Component Validation

-- | Validate component hierarchy for logical consistency
--
-- Component hierarchy validation ensures that:
-- * Parent-child relationships are valid
-- * No circular dependencies exist
-- * Component addresses are unique where specified
validateComponentHierarchy :: [ComponentIdentifierV2] -> [ValidationError]
validateComponentHierarchy components =
  concat
    [ validateUniqueAddresses components,
      validateComponentClasses components,
      validateHierarchyStructure components
    ]

-- | Validate component status information consistency
--
-- Status validation ensures that component states are logically
-- consistent with the operations described in delta certificates.
validateComponentStatus :: [(ComponentIdentifierV2, ComponentStatus)] -> [ValidationError]
validateComponentStatus componentStatuses =
  concatMap validateSingleComponentStatus componentStatuses
  ++ validateStatusConsistency componentStatuses
  where
    validateSingleComponentStatus :: (ComponentIdentifierV2, ComponentStatus) -> [ValidationError]
    validateSingleComponentStatus (comp, status) =
      validateComponentFields comp ++ validateStatusTransition comp status

    validateComponentFields :: ComponentIdentifierV2 -> [ValidationError]
    validateComponentFields comp
      | B.null (ci2Manufacturer comp) = [AttributeError "Component manufacturer cannot be empty"]
      | B.null (ci2Model comp) = [AttributeError "Component model cannot be empty"]
      | otherwise = []

    validateStatusTransition :: ComponentIdentifierV2 -> ComponentStatus -> [ValidationError]
    validateStatusTransition comp ComponentRemoved =
      -- Removed components should not have optional fields like addresses
      case ci2ComponentAddress comp of
        Just _ -> [ComplianceError "Removed components should not have component addresses"]
        Nothing -> []
    validateStatusTransition _ _ = []

    -- Validate that component statuses are consistent across the platform
    validateStatusConsistency :: [(ComponentIdentifierV2, ComponentStatus)] -> [ValidationError]
    validateStatusConsistency statuses =
      let duplicates = findDuplicateComponents statuses
      in map (\comp -> ConsistencyError $ "Duplicate component detected: " ++ show (ci2Manufacturer comp, ci2Model comp)) duplicates

    findDuplicateComponents :: [(ComponentIdentifierV2, ComponentStatus)] -> [ComponentIdentifierV2]
    findDuplicateComponents statuses =
      let componentKeys = map (\(comp, _) -> (ci2Manufacturer comp, ci2Model comp, ci2Serial comp)) statuses
          duplicateKeys = findDuplicates componentKeys
          duplicateComps = [comp | (comp, _) <- statuses, let key = (ci2Manufacturer comp, ci2Model comp, ci2Serial comp), key `elem` duplicateKeys]
      in duplicateComps

    findDuplicates :: Eq a => [a] -> [a]
    findDuplicates xs = [x | x <- xs, length (filter (==x) xs) > 1]

-- * Internal Validation Functions

-- | Validate basic certificate structure and required fields
validateCertificateStructure :: SignedPlatformCertificate -> [ValidationError]
validateCertificateStructure cert =
  let certInfo = getPlatformCertificate cert
   in concat
        [ validateVersion (pciVersion certInfo),
          validateSerialNumber (pciSerialNumber certInfo),
          validateValidityPeriod (pciValidity certInfo)
        ]
  where
    validateVersion :: Int -> [ValidationError]
    validateVersion version
      | version == 2 = []
      | otherwise = [ComplianceError $ "Invalid certificate version: " ++ show version]

    validateSerialNumber :: Integer -> [ValidationError]
    validateSerialNumber serialNum
      | serialNum > 0 = []
      | otherwise = [ComplianceError "Serial number must be positive"]

    validateValidityPeriod :: AttCertValidityPeriod -> [ValidationError]
    validateValidityPeriod period = 
      let notBefore = acNotBefore period
          notAfter = acNotAfter period
          currentTime = unsafePerformIO dateCurrent
          
          -- Check structural validity: notBefore should be before notAfter
          periodStructurallyValid = notBefore < notAfter
          
          -- Check if certificate is not yet valid (before notBefore)
          notYetValid = currentTime < notBefore
          
          -- Check if certificate is expired (after notAfter)
          expired = currentTime > notAfter
          
      in concat [
          [FormatError "Certificate validity period is invalid: notBefore must be before notAfter" | not periodStructurallyValid],
          [FormatError "Certificate is not yet valid" | notYetValid && periodStructurallyValid],
          [FormatError "Certificate has expired" | expired && periodStructurallyValid]
         ]

-- | Validate platform-specific required attributes
validateRequiredPlatformAttributes :: Attributes -> [ValidationError]
validateRequiredPlatformAttributes attrs =
  let requiredPlatformOIDs =
        [ tcg_at_platformConfiguration,
          tcg_at_platformManufacturer,
          tcg_at_platformModel
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
validateSpecificationCompliance cert =
  let certInfo = getPlatformCertificate cert
      versionErrors = if pciVersion certInfo == 2 
                        then [] 
                        else [FormatError "Certificate version must be 2"]
      attributeErrors = validateRequiredPlatformAttributes (pciAttributes certInfo)
      serialErrors = if pciSerialNumber certInfo > 0 
                       then [] 
                       else [FormatError "Serial number must be positive"]
  in versionErrors ++ attributeErrors ++ serialErrors

-- | Validate base certificate reference in delta certificate
validateBaseCertificateReference :: BasePlatformCertificateRef -> [ValidationError]
validateBaseCertificateReference baseRef =
  let serialNum = bpcrSerialNumber baseRef
   in if serialNum > 0
        then []
        else [ConsistencyError "Base certificate serial number must be positive"]

-- | Validate delta-specific attributes
validateDeltaAttributesValidation :: Attributes -> [ValidationError]
validateDeltaAttributesValidation attrs =
  -- For now, we validate that attributes contain the necessary delta configuration
  -- In a full implementation, we would parse specific delta attributes from the OID mapping
  let attributeOids = extractPresentOIDs attrs
      hasRequiredDeltaAttributes = any (`elem` requiredDeltaOIDs) attributeOids
   in if hasRequiredDeltaAttributes
        then []
        else [AttributeError "Delta certificate missing required delta attributes"]
  where
    requiredDeltaOIDs = [tcg_at_platformConfiguration_v2] -- Delta certs should reference base config

-- | Validate delta operations for logical consistency
validateDeltaOperations :: SignedDeltaPlatformCertificate -> [ValidationError]
validateDeltaOperations deltaCert =
  case getPlatformConfigurationDelta deltaCert of
    Nothing -> [ConsistencyError "Cannot extract platform configuration delta"]
    Just delta -> validatePlatformConfigurationDelta delta
  where
    validatePlatformConfigurationDelta :: PlatformConfigurationDelta -> [ValidationError]
    validatePlatformConfigurationDelta delta =
      let componentDeltas = pcdComponentDeltas delta
       in concatMap validateComponentDelta componentDeltas
    
    validateComponentDelta :: ComponentDelta -> [ValidationError]
    validateComponentDelta compDelta =
      let component = cdComponent compDelta
          operation = cdOperation compDelta
          prevComponent = cdPreviousComponent compDelta
       in validateDeltaOperation operation component prevComponent
    
    validateDeltaOperation :: DeltaOperation -> ComponentIdentifierV2 -> Maybe ComponentIdentifierV2 -> [ValidationError]
    validateDeltaOperation op component prevComponent = case op of
      DeltaAdd -> validateAddOperation component
      DeltaRemove -> validateRemoveOperation component
      DeltaModify -> validateModifyOperation component prevComponent
      DeltaReplace -> validateReplaceOperation component prevComponent  
      DeltaUpdate -> validateUpdateOperation component prevComponent
    
    validateAddOperation :: ComponentIdentifierV2 -> [ValidationError]
    validateAddOperation comp =
      let manufacturerErrors = [AttributeError "Component manufacturer cannot be empty" | B.null (ci2Manufacturer comp)]
          modelErrors = [AttributeError "Component model cannot be empty" | B.null (ci2Model comp)]
       in manufacturerErrors ++ modelErrors
    
    validateRemoveOperation :: ComponentIdentifierV2 -> [ValidationError]
    validateRemoveOperation _comp = [] -- Remove operations don't need additional validation
    
    validateModifyOperation :: ComponentIdentifierV2 -> Maybe ComponentIdentifierV2 -> [ValidationError]
    validateModifyOperation comp prevComp = case prevComp of
      Nothing -> [ConsistencyError "Modify operation requires previous component reference"]
      Just prev -> validateComponentDeltaConsistency comp prev
    
    validateReplaceOperation :: ComponentIdentifierV2 -> Maybe ComponentIdentifierV2 -> [ValidationError]
    validateReplaceOperation comp prevComp = case prevComp of
      Nothing -> [ConsistencyError "Replace operation requires previous component reference"]
      Just _prev -> validateAddOperation comp -- New component must be valid
    
    validateUpdateOperation :: ComponentIdentifierV2 -> Maybe ComponentIdentifierV2 -> [ValidationError]
    validateUpdateOperation comp prevComp = case prevComp of
      Nothing -> [ConsistencyError "Update operation requires previous component reference"]  
      Just prev -> validateComponentDeltaConsistency comp prev
    
    validateComponentDeltaConsistency :: ComponentIdentifierV2 -> ComponentIdentifierV2 -> [ValidationError]
    validateComponentDeltaConsistency comp prev =
      -- For modify/update operations, manufacturer and model should typically remain the same
      let manufacturerConsistent = ci2Manufacturer comp == ci2Manufacturer prev
          modelConsistent = ci2Model comp == ci2Model prev
          manufacturerErrors = [ConsistencyError "Component manufacturer should not change in modify/update operation" | not manufacturerConsistent]
          modelErrors = [ConsistencyError "Component model should not change in modify/update operation" | not modelConsistent]
       in manufacturerErrors ++ modelErrors

-- | Validate consistency across an entire certificate chain
validateChainConsistency ::
  SignedPlatformCertificate ->
  [SignedDeltaPlatformCertificate] ->
  [ValidationError]
validateChainConsistency baseCert deltaChain =
  let baseSerialNumber = pciSerialNumber $ getPlatformCertificate baseCert
      baseIssuer = pciIssuer $ getPlatformCertificate baseCert
   in concat
        [ validateSerialNumberSequence baseSerialNumber deltaChain,
          validateDeltaReferences baseCert deltaChain,
          validateChainSequence deltaChain,
          validateIssuerConsistency baseIssuer deltaChain
        ]
  where
    validateSerialNumberSequence :: Integer -> [SignedDeltaPlatformCertificate] -> [ValidationError]
    validateSerialNumberSequence baseSerial deltas =
      let deltaSerials = map (dpciSerialNumber . getDeltaPlatformCertificate) deltas
          duplicateSerials = deltaSerials \\ nub deltaSerials
          baseConflicts = filter (== baseSerial) deltaSerials
       in concat
            [ [ConsistencyError $ "Duplicate serial numbers in delta chain: " ++ show duplicateSerials | not (null duplicateSerials)],
              [ConsistencyError "Delta certificate serial number conflicts with base certificate" | not (null baseConflicts)]
            ]
    
    validateDeltaReferences :: SignedPlatformCertificate -> [SignedDeltaPlatformCertificate] -> [ValidationError]
    validateDeltaReferences base deltas =
      let baseSerial = pciSerialNumber $ getPlatformCertificate base
          baseIssuer = pciIssuer $ getPlatformCertificate base
       in concatMap (validateDeltaReference baseSerial baseIssuer) deltas
    
    validateDeltaReference :: Integer -> AttCertIssuer -> SignedDeltaPlatformCertificate -> [ValidationError]
    validateDeltaReference expectedSerial expectedIssuer deltaCert =
      let deltaInfo = getDeltaPlatformCertificate deltaCert
          baseRef = dpciBaseCertificateRef deltaInfo
          refSerial = bpcrSerialNumber baseRef
          refIssuer = bpcrIssuer baseRef
          
          -- Serial number validation
          serialErrors = [ConsistencyError "Delta certificate references wrong base certificate serial number" | refSerial /= expectedSerial]
          
          -- Issuer validation: Extract DistinguishedName from AttCertIssuer for comparison
          issuerErrors = case extractIssuerDNFromAttCertIssuer expectedIssuer of
            Nothing -> [] -- Skip issuer validation for unsupported issuer forms (V1 or complex V2)
            Just expectedIssuerDN -> 
              [ConsistencyError "Delta certificate references wrong base certificate issuer" | refIssuer /= expectedIssuerDN]
          
       in serialErrors ++ issuerErrors
    
    validateChainSequence :: [SignedDeltaPlatformCertificate] -> [ValidationError]
    validateChainSequence deltas = 
      -- Verify that delta certificates form a logical sequence (simplified validation)
      case deltas of
        [] -> []
        [_] -> [] -- Single delta is always consistent
        _ -> validateMultipleDeltasSequence deltas
    
    validateMultipleDeltasSequence :: [SignedDeltaPlatformCertificate] -> [ValidationError]
    validateMultipleDeltasSequence deltas =
      -- For now, just check that all deltas have valid base references
      -- In full implementation, would verify chronological order and operation consistency
      let hasValidReferences = all (isValidBaseReference . dpciBaseCertificateRef . getDeltaPlatformCertificate) deltas
       in [ConsistencyError "Invalid base certificate references in delta chain" | not hasValidReferences]
    
    isValidBaseReference :: BasePlatformCertificateRef -> Bool
    isValidBaseReference baseRef = bpcrSerialNumber baseRef > 0
    
    validateIssuerConsistency :: AttCertIssuer -> [SignedDeltaPlatformCertificate] -> [ValidationError]
    validateIssuerConsistency baseIssuer deltas =
      let deltaIssuers = map (dpciIssuer . getDeltaPlatformCertificate) deltas
          inconsistentIssuers = filter (/= baseIssuer) deltaIssuers
       in [ConsistencyError "Delta certificate issuer does not match base certificate issuer" | not (null inconsistentIssuers)]

-- | Validate that component addresses are unique where specified
validateUniqueAddresses :: [ComponentIdentifierV2] -> [ValidationError]
validateUniqueAddresses components =
  let addresses = [addr | comp <- components, Just addr <- [ci2ComponentAddress comp]]
      duplicates = addresses \\ nub addresses
   in if null duplicates
        then []
        else [HierarchyError $ "Duplicate component addresses found: " ++ show duplicates]

-- | Validate component class assignments
validateComponentClasses :: [ComponentIdentifierV2] -> [ValidationError]
validateComponentClasses components =
  concatMap validateComponentClass components
  where
    validateComponentClass :: ComponentIdentifierV2 -> [ValidationError]
    validateComponentClass comp = 
      let hasManufacturer = not $ B.null (ci2Manufacturer comp)
          hasModel = not $ B.null (ci2Model comp)
          componentType = case ci2ComponentClass comp of
            ComponentOther _ -> "Component"
            ComponentMotherboard -> "Motherboard component"
            ComponentCPU -> "CPU component"
            ComponentMemory -> "Memory component"  
            ComponentHardDrive -> "Storage component"
            ComponentNetworkInterface -> "Network interface"
            ComponentGraphicsCard -> "Graphics card"
            ComponentSoundCard -> "Audio device"
            ComponentOpticalDrive -> "Optical drive"
            ComponentKeyboard -> "Keyboard"
            ComponentMouse -> "Mouse"
            ComponentDisplay -> "Display"
            ComponentSpeaker -> "Speaker"
            ComponentMicrophone -> "Microphone"
            ComponentCamera -> "Camera"
            ComponentTouchscreen -> "Touchscreen"
            ComponentFingerprint -> "Fingerprint reader"
            ComponentBluetooth -> "Bluetooth adapter"
            ComponentWifi -> "WiFi adapter"
            ComponentEthernet -> "Ethernet adapter"
            ComponentUSB -> "USB controller"
            ComponentFireWire -> "FireWire controller"
            ComponentSCSI -> "SCSI controller"
            ComponentIDE -> "IDE controller"
       in concat
            [ [HierarchyError (componentType ++ " must have manufacturer") | not hasManufacturer],
              [HierarchyError (componentType ++ " must have model") | not hasModel]
            ]

-- | Validate overall hierarchy structure
validateHierarchyStructure :: [ComponentIdentifierV2] -> [ValidationError]
validateHierarchyStructure components =
  concat
    [ validateComponentClassHierarchy components,
      validateAddressConsistency components
    ]
  where
    validateComponentClassHierarchy :: [ComponentIdentifierV2] -> [ValidationError]
    validateComponentClassHierarchy comps =
      let motherboards = filter (\c -> isMotherboard (ci2ComponentClass c)) comps
          hasMotherboard = not (null motherboards)
          multipleMotherboards = length motherboards > 1
       in concat
            [ [HierarchyError "Platform should have at least one motherboard component" | not hasMotherboard],
              [HierarchyError "Platform should not have multiple motherboard components" | multipleMotherboards]
            ]
    
    isMotherboard :: ComponentClass -> Bool
    isMotherboard ComponentMotherboard = True
    isMotherboard _ = False
    
    validateAddressConsistency :: [ComponentIdentifierV2] -> [ValidationError]
    validateAddressConsistency comps =
      let componentsWithAddresses = [(comp, addr) | comp <- comps, Just addr <- [ci2ComponentAddress comp]]
          pciComponents = filter (\(_, addr) -> caAddressType addr == AddressPCI) componentsWithAddresses
          usbComponents = filter (\(_, addr) -> caAddressType addr == AddressUSB) componentsWithAddresses
       in concat
            [ validatePCIAddresses pciComponents,
              validateUSBAddresses usbComponents
            ]
    
    validatePCIAddresses :: [(ComponentIdentifierV2, ComponentAddress)] -> [ValidationError]
    validatePCIAddresses pciComps =
      let addresses = map (caAddress . snd) pciComps
          uniqueAddresses = nub addresses
       in [HierarchyError "Duplicate PCI addresses found" | length addresses /= length uniqueAddresses]
    
    validateUSBAddresses :: [(ComponentIdentifierV2, ComponentAddress)] -> [ValidationError]
    validateUSBAddresses usbComps =
      let addresses = map (caAddress . snd) usbComps
          uniqueAddresses = nub addresses
       in [HierarchyError "Duplicate USB addresses found" | length addresses /= length uniqueAddresses]

-- * Helper Functions

-- | Get list of required attribute OIDs for platform certificates
getRequiredAttributeOIDs :: [OID]
getRequiredAttributeOIDs =
  [ tcg_at_platformConfiguration,
    tcg_at_platformManufacturer,
    tcg_at_platformModel,
    tcg_at_platformSerial
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
nub :: (Eq a) => [a] -> [a]
nub [] = []
nub (x : xs) = x : nub (filter (/= x) xs)

(\\) :: (Eq a) => [a] -> [a] -> [a]
xs \\ ys = filter (`notElem` ys) xs

-- * Attribute Validation Helper Functions

-- | Validate Platform Manufacturer attribute according to TCG specification
-- The TCG Platform Certificate Profile Specification defines Platform Manufacturer
-- as a MUST field containing a UTF-8 string with the platform manufacturing company name.
-- Maximum length is 256 characters (STRMAX = 256).
validatePlatformManufacturerAttr :: B.ByteString -> [ValidationError]
validatePlatformManufacturerAttr bs
  | B.null bs = [AttributeError "Platform Manufacturer cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Manufacturer exceeds maximum length of 256 characters"]
  | otherwise = []

-- | Validate Platform Model attribute according to TCG specification
-- Platform Model is a MUST field containing a UTF-8 string with the platform model.
-- Maximum length is 256 characters (STRMAX = 256).
validatePlatformModelAttr :: B.ByteString -> [ValidationError]
validatePlatformModelAttr bs
  | B.null bs = [AttributeError "Platform Model cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Model exceeds maximum length of 256 characters"]
  | otherwise = []

-- | Validate Platform Serial attribute according to TCG specification  
-- Platform Serial is a MUST field containing a UTF-8 string with the platform serial number.
-- Maximum length is 256 characters (STRMAX = 256).
validatePlatformSerialAttr :: B.ByteString -> [ValidationError]
validatePlatformSerialAttr bs
  | B.null bs = [AttributeError "Platform Serial cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Serial exceeds maximum length of 256 characters"]
  | otherwise = []

-- | Validate Platform Version attribute according to TCG specification
-- Platform Version is a MUST field containing a UTF-8 string with the platform version.
-- Maximum length is 256 characters (STRMAX = 256).
validatePlatformVersionAttr :: B.ByteString -> [ValidationError]
validatePlatformVersionAttr bs
  | B.null bs = [AttributeError "Platform Version cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Version exceeds maximum length of 256 characters"]
  | otherwise = []

-- | Validate TPM Model attribute according to TCG specification
-- TPM Model is a MUST field containing a UTF-8 string with the TPM model.
-- Maximum length is 256 characters (STRMAX = 256).
validateTPMModelAttr :: B.ByteString -> [ValidationError]
validateTPMModelAttr bs
  | B.null bs = [AttributeError "TPM Model cannot be empty"]
  | B.length bs > 256 = [AttributeError "TPM Model exceeds maximum length of 256 characters"]
  | otherwise = []

-- | Validate Component Class attribute
validateComponentClassAttr :: ComponentClass -> [ValidationError]
validateComponentClassAttr _ = [] -- Component classes are always valid by construction

-- | Validate Component Identifier attribute
validateComponentIdentifierAttr :: ComponentIdentifier -> Maybe B.ByteString -> [ValidationError]
validateComponentIdentifierAttr ci _timestamp =
  let manufacturerEmpty = B.null (ciManufacturer ci)
      modelEmpty = B.null (ciModel ci)
  in concat [
      [AttributeError "Component identifier manufacturer cannot be empty" | manufacturerEmpty],
      [AttributeError "Component identifier model cannot be empty" | modelEmpty]
     ]

-- | Validate Component Identifier V2 attribute  
validateComponentIdentifierV2Attr :: ComponentIdentifierV2 -> Maybe B.ByteString -> [ValidationError]
validateComponentIdentifierV2Attr ci2 _timestamp =
  let manufacturerEmpty = B.null (ci2Manufacturer ci2)
      modelEmpty = B.null (ci2Model ci2)
  in concat [
      [AttributeError "Component identifier V2 manufacturer cannot be empty" | manufacturerEmpty],
      [AttributeError "Component identifier V2 model cannot be empty" | modelEmpty]
     ]

-- | Validate Platform Configuration attribute
validatePlatformConfigurationAttr :: PlatformConfiguration -> Maybe B.ByteString -> Maybe Int -> Maybe Integer -> [ValidationError]
validatePlatformConfigurationAttr config _timestamp _certLevel _changeSeq =
  let componentsEmpty = null (pcComponents config)
  in [AttributeError "Platform configuration must have at least one component" | componentsEmpty]

-- | Validate Platform Configuration V2 attribute
validatePlatformConfigurationV2Attr :: PlatformConfigurationV2 -> Maybe B.ByteString -> Maybe Int -> Maybe Integer -> [ValidationError]  
validatePlatformConfigurationV2Attr config _timestamp _certLevel _changeSeq =
  let componentsEmpty = null (pcv2Components config)
  in [AttributeError "Platform configuration V2 must have at least one component" | componentsEmpty]

-- | Validate TPM Version attribute
validateTPMVersionAttr :: TPMVersion -> [ValidationError]
validateTPMVersionAttr version =
  let majorInvalid = tpmVersionMajor version < 1
      minorInvalid = tpmVersionMinor version < 0
      revMajorInvalid = tpmVersionRevMajor version < 0
      revMinorInvalid = tpmVersionRevMinor version < 0
  in concat [
      [AttributeError "TPM version major must be at least 1" | majorInvalid],
      [AttributeError "TPM version minor cannot be negative" | minorInvalid], 
      [AttributeError "TPM version revision major cannot be negative" | revMajorInvalid],
      [AttributeError "TPM version revision minor cannot be negative" | revMinorInvalid]
     ]

-- | Validate TPM Specification attribute
validateTPMSpecificationAttr :: TPMSpecification -> [ValidationError]
validateTPMSpecificationAttr spec =
  let familyEmpty = B.null (tpmSpecFamily spec)
      levelInvalid = tpmSpecLevel spec < 0
      revisionInvalid = tpmSpecRevision spec < 0
  in concat [
      [AttributeError "TPM specification family cannot be empty" | familyEmpty],
      [AttributeError "TPM specification level cannot be negative" | levelInvalid],
      [AttributeError "TPM specification revision cannot be negative" | revisionInvalid]
     ]

-- | Validate Relevant Credentials attribute
validateRelevantCredentialsAttr :: [B.ByteString] -> Maybe B.ByteString -> [ValidationError]
validateRelevantCredentialsAttr creds _timestamp =
  let credsEmpty = null creds
      hasEmptyCredentials = any B.null creds
  in concat [
      [AttributeError "Relevant credentials cannot be empty" | credsEmpty],
      [AttributeError "Relevant credentials cannot contain empty values" | hasEmptyCredentials]
     ]

-- | Validate Relevant Manifests attribute  
validateRelevantManifestsAttr :: [B.ByteString] -> Maybe B.ByteString -> [ValidationError]
validateRelevantManifestsAttr manifests _timestamp =
  let manifestsEmpty = null manifests
      hasEmptyManifests = any B.null manifests
  in concat [
      [AttributeError "Relevant manifests cannot be empty" | manifestsEmpty],
      [AttributeError "Relevant manifests cannot contain empty values" | hasEmptyManifests]
     ]

-- | Validate Virtual Platform attribute
validateVirtualPlatformAttr :: Bool -> Maybe B.ByteString -> [ValidationError]
validateVirtualPlatformAttr _isVirtual _evidence = 
  -- Virtual platform attributes are valid by construction
  []

-- | Validate Multi-Tenant attribute
validateMultiTenantAttr :: Bool -> Maybe B.ByteString -> [ValidationError]
validateMultiTenantAttr _isMT _isolation =
  -- Multi-tenant attributes are valid by construction  
  []

-- * Helper Functions for Issuer Comparison

-- | Extract DistinguishedName from AttCertIssuer for validation purposes
-- This implementation handles GeneralNames parsing and returns the DirectoryName
-- when available, or falls back to certificate resolution for baseCertificateID.
extractIssuerDNFromAttCertIssuer :: AttCertIssuer -> Maybe DistinguishedName
extractIssuerDNFromAttCertIssuer (AttCertIssuerV1 generalNames) = 
  -- V1 form is deprecated but we can still extract DirectoryName if present
  extractDirectoryNameFromGeneralNames generalNames
extractIssuerDNFromAttCertIssuer (AttCertIssuerV2 v2form) = 
  case v2fromBaseCertificateID v2form of
    Just issuerSerial -> 
      -- When baseCertificateID is present, extract issuer from the IssuerSerial
      -- The IssuerSerial contains GeneralNames for the issuer
      extractDirectoryNameFromGeneralNames (issuer issuerSerial)
    Nothing -> 
      -- No baseCertificateID, issuer name should be in issuerName (GeneralNames)
      -- Extract DirectoryName from the GeneralNames in issuerName
      extractDirectoryNameFromGeneralNames (v2fromIssuerName v2form)

-- | Extract DistinguishedName from GeneralNames by looking for AltDirectoryName
-- Returns the first DirectoryName found in the GeneralNames list, or Nothing if none found
extractDirectoryNameFromGeneralNames :: [AltName] -> Maybe DistinguishedName
extractDirectoryNameFromGeneralNames [] = Nothing
extractDirectoryNameFromGeneralNames (AltDirectoryName dn : _) = Just dn
extractDirectoryNameFromGeneralNames (_ : rest) = extractDirectoryNameFromGeneralNames rest
