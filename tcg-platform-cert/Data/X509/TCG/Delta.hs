{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Delta
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Delta Platform Certificate support.
--
-- This module implements Delta Platform Certificates as defined in the IWG Platform
-- Certificate Profile v1.1. Delta Platform Certificates track changes in platform
-- configuration over time by referencing a base Platform Certificate.
module Data.X509.TCG.Delta
  ( -- * Delta Platform Certificate Types
    DeltaPlatformCertificateInfo (..),
    SignedDeltaPlatformCertificate,

    -- * Delta Configuration
    DeltaPlatformConfiguration (..),
    PlatformConfigurationDelta (..),
    ComponentDelta (..),
    DeltaOperation (..),

    -- * Base Certificate References
    BasePlatformCertificateRef (..),
    CertificateChain (..),

    -- * Change Tracking
    ChangeRecord (..),
    ChangeType (..),
    ChangeMetadata (..),

    -- * Marshalling Operations
    encodeSignedDeltaPlatformCertificate,
    decodeSignedDeltaPlatformCertificate,

    -- * Accessor Functions
    getDeltaPlatformCertificate,
    getBaseCertificateReference,
    getPlatformConfigurationDelta,
    getComponentDeltas,
    getChangeRecords,

    -- * Validation Functions
    validateDeltaCertificate,
    applyDeltaToBase,
    computeResultingConfiguration,
  )
where

import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Hourglass (DateTime)
import Data.X509 (DistinguishedName, Extensions, SignatureALG, SignedExact, decodeSignedObject, encodeSignedObject, getSigned, signedObject)
import Data.X509.AttCert (AttCertIssuer, AttCertValidityPeriod, Holder, UniqueID)
import Data.X509.Attribute (Attributes)
import Data.X509.TCG.Component (ComponentIdentifier, ComponentIdentifierV2)
import Data.X509.TCG.Platform (ComponentStatus (..), PlatformConfigurationV2 (..))

-- | Delta Platform Certificate Information structure
--
-- Similar to PlatformCertificateInfo but specifically for Delta Platform Certificates
-- that track changes from a base Platform Certificate.
data DeltaPlatformCertificateInfo = DeltaPlatformCertificateInfo
  { dpciVersion :: Int, -- Must be 2 (v2)
    dpciHolder :: Holder,
    dpciIssuer :: AttCertIssuer,
    dpciSignature :: SignatureALG,
    dpciSerialNumber :: Integer,
    dpciValidity :: AttCertValidityPeriod,
    dpciAttributes :: Attributes,
    dpciIssuerUniqueID :: Maybe UniqueID,
    dpciExtensions :: Extensions,
    dpciBaseCertificateRef :: BasePlatformCertificateRef
  }
  deriving (Show, Eq)

-- | ASN1Object instance for DeltaPlatformCertificateInfo
instance ASN1Object DeltaPlatformCertificateInfo where
  toASN1 (DeltaPlatformCertificateInfo dciVer dciHolder dciIssuer dciSig dciSn dciValid dciAttrs dciUid dciExts dciBase) xs =
    ( [Start Sequence]
        ++ [IntVal $ fromIntegral dciVer]
        ++ toASN1 dciHolder []
        ++ toASN1 dciIssuer []
        ++ toASN1 dciSig []
        ++ [IntVal dciSn]
        ++ toASN1 dciValid []
        ++ toASN1 dciAttrs []
        ++ maybe [] (\u -> [BitString u]) dciUid
        ++ toASN1 dciExts []
        ++ toASN1 dciBase []
        ++ [End Sequence]
    )
      ++ xs
  fromASN1 _ = Left "Delta platform certificate parsing not implemented"

-- | A Signed Delta Platform Certificate
type SignedDeltaPlatformCertificate = SignedExact DeltaPlatformCertificateInfo

-- | Delta Platform Configuration structure
--
-- Contains the changes to be applied to a base platform configuration.
data DeltaPlatformConfiguration = DeltaPlatformConfiguration
  { dpcBaseCertificateSerial :: Integer,
    dpcConfigurationDelta :: PlatformConfigurationDelta,
    dpcChangeTimestamp :: DateTime,
    dpcChangeReason :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Configuration Delta structure
--
-- Represents the specific changes to platform configuration.
data PlatformConfigurationDelta = PlatformConfigurationDelta
  { pcdPlatformInfoChanges :: Maybe PlatformInfoDelta,
    pcdComponentDeltas :: [ComponentDelta],
    pcdChangeRecords :: [ChangeRecord]
  }
  deriving (Show, Eq)

-- | Platform Information Delta structure
data PlatformInfoDelta = PlatformInfoDelta
  { pidManufacturerChange :: Maybe B.ByteString,
    pidModelChange :: Maybe B.ByteString,
    pidSerialChange :: Maybe B.ByteString,
    pidVersionChange :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Delta structure
--
-- Represents changes to individual components in the platform.
data ComponentDelta = ComponentDelta
  { cdOperation :: DeltaOperation,
    cdComponent :: ComponentIdentifierV2,
    cdPreviousComponent :: Maybe ComponentIdentifierV2,
    cdChangeMetadata :: ChangeMetadata
  }
  deriving (Show, Eq)

-- | Delta Operation enumeration
--
-- Types of operations that can be performed on components.
data DeltaOperation
  = -- | Component was added to the platform
    DeltaAdd
  | -- | Component was removed from the platform
    DeltaRemove
  | -- | Component was modified (firmware update, etc.)
    DeltaModify
  | -- | Component was replaced with another component
    DeltaReplace
  | -- | Component configuration or properties were updated
    DeltaUpdate
  deriving (Show, Eq, Enum)

-- | Base Platform Certificate Reference structure
--
-- References the base Platform Certificate that this Delta applies to.
data BasePlatformCertificateRef = BasePlatformCertificateRef
  { bpcrIssuer :: DistinguishedName,
    bpcrSerialNumber :: Integer,
    bpcrCertificateHash :: Maybe B.ByteString,
    bpcrValidityPeriod :: Maybe AttCertValidityPeriod
  }
  deriving (Show, Eq)

-- | ASN1Object instance for BasePlatformCertificateRef
instance ASN1Object BasePlatformCertificateRef where
  toASN1 (BasePlatformCertificateRef issuer serial hash validity) xs =
    ( [Start Sequence]
        ++ toASN1 issuer []
        ++ [IntVal serial]
        ++ maybe [] (\h -> [OctetString h]) hash
        ++ maybe [] (\v -> toASN1 v []) validity
        ++ [End Sequence]
    )
      ++ xs
  fromASN1 _ = Left "BasePlatformCertificateRef parsing not implemented"

-- | Certificate Chain structure
--
-- Represents a chain of Platform Certificates leading to this Delta.
data CertificateChain = CertificateChain
  { ccBaseCertificate :: BasePlatformCertificateRef,
    ccIntermediateCertificates :: [BasePlatformCertificateRef],
    ccChainValidityPeriod :: AttCertValidityPeriod
  }
  deriving (Show, Eq)

-- | Change Record structure
--
-- Records information about specific changes made to the platform.
data ChangeRecord = ChangeRecord
  { crChangeId :: B.ByteString,
    crChangeType :: ChangeType,
    crTimestamp :: DateTime,
    crDescription :: Maybe B.ByteString,
    crAffectedComponents :: [ComponentIdentifier],
    crChangeMetadata :: ChangeMetadata
  }
  deriving (Show, Eq)

-- | Change Type enumeration
data ChangeType
  = ChangeHardwareAddition
  | ChangeHardwareRemoval
  | ChangeHardwareReplacement
  | ChangeFirmwareUpdate
  | ChangeSoftwareInstallation
  | ChangeSoftwareRemoval
  | ChangeConfigurationUpdate
  | ChangeSecurityUpdate
  | ChangeMaintenance
  | ChangeOther B.ByteString
  deriving (Show, Eq)

-- | Change Metadata structure
--
-- Additional metadata about changes.
data ChangeMetadata = ChangeMetadata
  { -- | Who initiated the change
    cmInitiator :: Maybe B.ByteString,
    -- | Who approved the change
    cmApprover :: Maybe B.ByteString,
    -- | Reference to change management system
    cmChangeTicket :: Maybe B.ByteString,
    -- | Information for rolling back the change
    cmRollbackInfo :: Maybe B.ByteString,
    -- | Additional key-value pairs
    cmAdditionalInfo :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- * Marshalling Operations

-- | Encode a SignedDeltaPlatformCertificate to a DER-encoded bytestring
encodeSignedDeltaPlatformCertificate :: SignedDeltaPlatformCertificate -> B.ByteString
encodeSignedDeltaPlatformCertificate = encodeSignedObject

-- | Decode a DER-encoded bytestring to a SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificate :: B.ByteString -> Either String SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificate = decodeSignedObject

-- * Accessor Functions

-- | Extract the DeltaPlatformCertificateInfo from a SignedDeltaPlatformCertificate
getDeltaPlatformCertificate :: SignedDeltaPlatformCertificate -> DeltaPlatformCertificateInfo
getDeltaPlatformCertificate = signedObject . getSigned

-- | Extract the base certificate reference from a Delta Platform Certificate
--
-- This function retrieves the reference to the base Platform Certificate
-- that this Delta Certificate applies to. The base certificate reference
-- includes the issuer DN, serial number, and optionally a certificate hash
-- and validity period for additional verification.
--
-- The base certificate reference is essential for:
-- * Validating that the Delta Certificate applies to the correct base certificate
-- * Building certificate chains from base to current state
-- * Ensuring continuity in platform configuration tracking
--
-- Parameters:
-- * @cert@ - The signed Delta Platform Certificate
--
-- Returns:
-- * @BasePlatformCertificateRef@ containing issuer, serial number, and optional hash/validity
--
-- Example:
-- @
-- let baseRef = getBaseCertificateReference deltaCert
-- case validateBaseCertificate baseRef of
--   [] -> putStrLn $ \"Base certificate serial: \" ++ show (bpcrSerialNumber baseRef)
--   errors -> putStrLn $ \"Invalid base reference: \" ++ unlines errors
-- @
getBaseCertificateReference :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef
getBaseCertificateReference cert = dpciBaseCertificateRef $ getDeltaPlatformCertificate cert

-- | Extract Platform Configuration Delta from a Delta Platform Certificate
--
-- This function searches for the tcg-at-deltaConfiguration attribute
-- (OID 2.23.133.2.23) and parses it into a structured PlatformConfigurationDelta.
--
-- The platform configuration delta provides detailed information about:
-- * Changes to platform information (manufacturer, model, etc.)
-- * Component additions, removals, modifications, and updates
-- * Change records with timestamps and metadata
-- * Affected component lists and change tracking
--
-- This information is essential for:
-- * Applying delta changes to a base platform configuration
-- * Tracking platform evolution over time
-- * Validating that changes are authorized and properly documented
-- * Building audit trails of platform modifications
--
-- Parameters:
-- * @cert@ - The signed Delta Platform Certificate to extract delta from
--
-- Returns:
-- * @Just PlatformConfigurationDelta@ if the delta configuration is found and valid
-- * @Nothing@ if the delta configuration attribute is missing or malformed
--
-- Example:
-- @
-- case getPlatformConfigurationDelta deltaCert of
--   Just delta -> do
--     putStrLn $ \"Component changes: \" ++ show (length $ pcdComponentDeltas delta)
--     putStrLn $ \"Change records: \" ++ show (length $ pcdChangeRecords delta)
--   Nothing -> putStrLn \"No delta configuration found in certificate\"
-- @
getPlatformConfigurationDelta :: SignedDeltaPlatformCertificate -> Maybe PlatformConfigurationDelta
getPlatformConfigurationDelta cert =
  case lookupDeltaAttribute "2.23.133.2.23" (dpciAttributes $ getDeltaPlatformCertificate cert) of
    Just deltaConfig -> parseDeltaPlatformConfiguration deltaConfig
    Nothing -> Nothing

-- | Extract Component Deltas from a Delta Platform Certificate
getComponentDeltas :: SignedDeltaPlatformCertificate -> [ComponentDelta]
getComponentDeltas cert =
  case getPlatformConfigurationDelta cert of
    Just delta -> pcdComponentDeltas delta
    Nothing -> []

-- | Extract Change Records from a Delta Platform Certificate
getChangeRecords :: SignedDeltaPlatformCertificate -> [ChangeRecord]
getChangeRecords cert =
  case getPlatformConfigurationDelta cert of
    Just delta -> pcdChangeRecords delta
    Nothing -> []

-- * Validation Functions

-- | Validate a Delta Platform Certificate
--
-- Checks that the certificate is properly formed and references a valid base certificate.
validateDeltaCertificate :: SignedDeltaPlatformCertificate -> [String]
validateDeltaCertificate cert =
  let deltaInfo = getDeltaPlatformCertificate cert
      baseRef = dpciBaseCertificateRef deltaInfo
   in validateBaseCertificateRef baseRef
        ++ validateDeltaAttributes (dpciAttributes deltaInfo)

-- | Apply a Delta Platform Certificate to a base configuration
--
-- This function computes the resulting platform configuration after applying
-- all component deltas from a Delta Platform Certificate to a base configuration.
-- It processes each component delta operation in sequence to produce the final state.
--
-- The function handles the following delta operations:
-- * @DeltaAdd@ - Adds new components to the platform
-- * @DeltaRemove@ - Removes existing components from the platform
-- * @DeltaModify@ - Updates existing components (firmware updates, etc.)
-- * @DeltaReplace@ - Replaces one component with another
-- * @DeltaUpdate@ - Updates component configuration or properties
--
-- The operations are applied atomically - either all succeed or the function
-- returns an error. This ensures platform configuration consistency.
--
-- Parameters:
-- * @baseConfig@ - The base platform configuration to apply changes to
-- * @delta@ - The platform configuration delta containing the changes
--
-- Returns:
-- * @Right PlatformConfigurationV2@ - The resulting configuration after applying all changes
-- * @Left String@ - An error message if any delta operation fails or is invalid
--
-- Example:
-- @
-- case applyDeltaToBase baseConfig platformDelta of
--   Right newConfig -> do
--     putStrLn $ \"Applied \" ++ show (length $ pcdComponentDeltas platformDelta) ++ \" changes\"
--     putStrLn $ \"Final components: \" ++ show (length $ pcv2Components newConfig)
--   Left error -> putStrLn $ \"Failed to apply delta: \" ++ error
-- @
applyDeltaToBase :: PlatformConfigurationV2 -> PlatformConfigurationDelta -> Either String PlatformConfigurationV2
applyDeltaToBase baseConfig delta =
  Right $ foldl applyComponentDelta baseConfig (pcdComponentDeltas delta)
  where
    applyComponentDelta :: PlatformConfigurationV2 -> ComponentDelta -> PlatformConfigurationV2
    applyComponentDelta config compDelta =
      case cdOperation compDelta of
        DeltaAdd -> addComponent config (cdComponent compDelta)
        DeltaRemove -> removeComponent config (cdComponent compDelta)
        DeltaModify -> modifyComponent config (cdComponent compDelta)
        DeltaReplace -> replaceComponent config (cdPreviousComponent compDelta) (cdComponent compDelta)
        DeltaUpdate -> updateComponent config (cdComponent compDelta)

-- | Compute the resulting configuration after applying delta certificates
computeResultingConfiguration :: PlatformConfigurationV2 -> [PlatformConfigurationDelta] -> Either String PlatformConfigurationV2
computeResultingConfiguration baseConfig deltas =
  foldl (\acc delta -> acc >>= \config -> applyDeltaToBase config delta) (Right baseConfig) deltas

-- Helper functions

-- | Lookup delta-specific attribute by OID string
lookupDeltaAttribute :: String -> Attributes -> Maybe B.ByteString
lookupDeltaAttribute _ _ = Nothing -- TODO: Implement attribute lookup

-- | Parse Delta Platform Configuration from attribute value
parseDeltaPlatformConfiguration :: B.ByteString -> Maybe PlatformConfigurationDelta
parseDeltaPlatformConfiguration _ = Nothing -- TODO: Implement ASN.1 parsing

-- | Validate base certificate reference
validateBaseCertificateRef :: BasePlatformCertificateRef -> [String]
validateBaseCertificateRef baseRef
  | bpcrSerialNumber baseRef <= 0 = ["Invalid base certificate serial number"]
  | otherwise = []

-- | Validate delta attributes
validateDeltaAttributes :: Attributes -> [String]
validateDeltaAttributes _ = [] -- TODO: Implement validation

-- Component manipulation helper functions
addComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
addComponent config component =
  config {pcv2Components = pcv2Components config ++ [(component, ComponentAdded)]}

removeComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
removeComponent config component =
  config {pcv2Components = filter ((/= component) . fst) (pcv2Components config)}

modifyComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
modifyComponent config component =
  config {pcv2Components = map updateStatus (pcv2Components config)}
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

replaceComponent :: PlatformConfigurationV2 -> Maybe ComponentIdentifierV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
replaceComponent config Nothing newComp = addComponent config newComp
replaceComponent config (Just oldComp) newComp =
  addComponent (removeComponent config oldComp) newComp

updateComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
updateComponent config component =
  config {pcv2Components = map updateStatus (pcv2Components config)}
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

-- ASN.1 instances for basic types

instance ASN1Object DeltaOperation where
  toASN1 op xs = [IntVal (fromIntegral $ fromEnum op)] ++ xs
  fromASN1 (IntVal n : xs)
    | n >= 0 && n <= 4 = Right (toEnum (fromIntegral n), xs)
    | otherwise = Left "DeltaOperation: Invalid enum value"
  fromASN1 _ = Left "DeltaOperation: Invalid ASN1 structure"

instance ASN1Object ChangeType where
  toASN1 ct xs = case ct of
    ChangeHardwareAddition -> [IntVal 0] ++ xs
    ChangeHardwareRemoval -> [IntVal 1] ++ xs
    ChangeHardwareReplacement -> [IntVal 2] ++ xs
    ChangeFirmwareUpdate -> [IntVal 3] ++ xs
    ChangeSoftwareInstallation -> [IntVal 4] ++ xs
    ChangeSoftwareRemoval -> [IntVal 5] ++ xs
    ChangeConfigurationUpdate -> [IntVal 6] ++ xs
    ChangeSecurityUpdate -> [IntVal 7] ++ xs
    ChangeMaintenance -> [IntVal 8] ++ xs
    ChangeOther desc -> [IntVal 99, OctetString desc] ++ xs
  
  fromASN1 (IntVal n : xs) = case n of
    0 -> Right (ChangeHardwareAddition, xs)
    1 -> Right (ChangeHardwareRemoval, xs)
    2 -> Right (ChangeHardwareReplacement, xs)
    3 -> Right (ChangeFirmwareUpdate, xs)
    4 -> Right (ChangeSoftwareInstallation, xs)
    5 -> Right (ChangeSoftwareRemoval, xs)
    6 -> Right (ChangeConfigurationUpdate, xs)
    7 -> Right (ChangeSecurityUpdate, xs)
    8 -> Right (ChangeMaintenance, xs)
    99 -> Left "ChangeType: ChangeOther requires additional OctetString"
    _ -> Left "ChangeType: Invalid enum value"
  fromASN1 (IntVal 99 : OctetString desc : xs) = Right (ChangeOther desc, xs)
  fromASN1 _ = Left "ChangeType: Invalid ASN1 structure"