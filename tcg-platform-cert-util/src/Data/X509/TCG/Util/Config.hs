{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.Config
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- Configuration management for TCG Platform Certificate utility.
-- This module provides YAML-based configuration loading and default value management.

module Data.X509.TCG.Util.Config
  ( -- * Configuration Types
    PlatformCertConfig(..)
  , DeltaCertConfig(..)
  , ComponentConfig(..)
  , ComponentChangeConfig(..)
  , AddressConfig(..)
  , URIReferenceConfig(..)
  , SecurityAssertionsConfig(..)

  -- * Configuration Loading
  , loadConfig
  , loadDeltaConfig
  , createExampleConfig

  -- * Default Values
  , createDefaultTPMInfo
  , yamlComponentToComponentIdentifier
  , configToExtendedAttrs
  ) where

import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import Data.Maybe (fromMaybe)
import Data.X509.TCG
import Data.Aeson (Options(..), defaultOptions, genericParseJSON, genericToJSON)
import Data.Yaml (FromJSON (..), ToJSON (..), decodeFileEither, encodeFile)
import GHC.Generics (Generic)

-- | Custom JSON options to strip field prefixes
-- This allows YAML files to use simpler field names like "manufacturer" instead of "pccManufacturer"
componentOptions :: Options
componentOptions = defaultOptions { fieldLabelModifier = dropPrefix "cc" }

platformOptions :: Options
platformOptions = defaultOptions { fieldLabelModifier = dropPrefix "pcc" }

securityOptions :: Options
securityOptions = defaultOptions { fieldLabelModifier = dropPrefix "sac" }

deltaOptions :: Options
deltaOptions = defaultOptions { fieldLabelModifier = dropPrefix "dcc" }

changeOptions :: Options
changeOptions = defaultOptions { fieldLabelModifier = dropPrefix "chg" }

-- | Drop a prefix from field name and lowercase the first character
dropPrefix :: String -> String -> String
dropPrefix prefix field
  | prefix `isPrefixOf` field = lowercaseFirst (drop (length prefix) field)
  | otherwise = field
  where
    isPrefixOf :: String -> String -> Bool
    isPrefixOf [] _ = True
    isPrefixOf _ [] = False
    isPrefixOf (x:xs) (y:ys) = x == y && isPrefixOf xs ys

    lowercaseFirst :: String -> String
    lowercaseFirst [] = []
    lowercaseFirst (c:cs) = toLower c : cs

    toLower :: Char -> Char
    toLower c
      | c >= 'A' && c <= 'Z' = toEnum (fromEnum c + 32)
      | otherwise = c

-- | Address configuration for network components
data AddressConfig = AddressConfig
  { addrEthernetMac :: Maybe String    -- IEEE 802 MAC Address
  , addrWlanMac :: Maybe String        -- IEEE 802.11 Wireless MAC
  , addrBluetoothMac :: Maybe String   -- Bluetooth Device Address
  } deriving (Show, Eq, Generic)

addressOptions :: Options
addressOptions = defaultOptions { fieldLabelModifier = dropPrefix "addr" }

instance FromJSON AddressConfig where
  parseJSON = genericParseJSON addressOptions
instance ToJSON AddressConfig where
  toJSON = genericToJSON addressOptions

-- | URI Reference configuration with optional hash for integrity verification
-- Per TCG Platform Certificate Profile, URIReference allows specifying
-- a hash of the referenced document to ensure integrity.
data URIReferenceConfig = URIReferenceConfig
  { uriUri :: String                     -- Uniform Resource Identifier
  , uriHashAlgorithm :: Maybe String     -- Hash algorithm: "sha256", "sha384", "sha512"
  , uriHashValue :: Maybe String         -- Base64-encoded hash value of the document
  } deriving (Show, Eq, Generic)

uriOptions :: Options
uriOptions = defaultOptions { fieldLabelModifier = dropPrefix "uri" }

instance FromJSON URIReferenceConfig where
  parseJSON = genericParseJSON uriOptions
instance ToJSON URIReferenceConfig where
  toJSON = genericToJSON uriOptions

-- | YAML Configuration for Platform Certificate components
data ComponentConfig = ComponentConfig
  { ccClass :: String
  , ccManufacturer :: String
  , ccModel :: String
  , ccSerial :: Maybe String           -- Optional per TCG spec
  , ccRevision :: Maybe String         -- Optional per TCG spec
  , ccAddresses :: Maybe [AddressConfig]  -- Network addresses (MAC, etc.)
  } deriving (Show, Eq, Generic)

instance FromJSON ComponentConfig where
  parseJSON = genericParseJSON componentOptions
instance ToJSON ComponentConfig where
  toJSON = genericToJSON componentOptions

-- | YAML Configuration for Platform Certificates
data PlatformCertConfig = PlatformCertConfig
  { pccManufacturer :: String
  , pccModel :: String
  , pccVersion :: String
  , pccSerial :: String
  , pccValidityDays :: Maybe Int
  , pccKeySize :: Maybe Int
  , pccComponents :: [ComponentConfig]
  -- Extended fields
  , pccPlatformConfigUri :: Maybe URIReferenceConfig  -- Platform Config URI with optional hash
  , pccPlatformClass :: Maybe String
  , pccSpecificationVersion :: Maybe String
  , pccMajorVersion :: Maybe Int
  , pccMinorVersion :: Maybe Int
  , pccPatchVersion :: Maybe Int
  , pccPlatformQualifier :: Maybe String
  -- TCG Credential fields (IWG v1.1)
  , pccCredentialSpecMajor :: Maybe Int   -- TCG Credential Specification major version
  , pccCredentialSpecMinor :: Maybe Int   -- TCG Credential Specification minor version
  , pccCredentialSpecRevision :: Maybe Int -- TCG Credential Specification revision
  -- Platform Specification fields (IWG v1.1)
  , pccPlatformSpecMajor :: Maybe Int     -- Platform specification major version
  , pccPlatformSpecMinor :: Maybe Int     -- Platform specification minor version
  , pccPlatformSpecRevision :: Maybe Int   -- Platform specification revision
  -- TBB Security Assertions (2.23.133.2.19)
  , pccSecurityAssertions :: Maybe SecurityAssertionsConfig
  } deriving (Show, Eq, Generic)

-- | Security Assertions Configuration for TBB Security Assertions attribute
data SecurityAssertionsConfig = SecurityAssertionsConfig
  { sacVersion :: Maybe Int                    -- Security assertions version (default: 0)
  -- Common Criteria fields
  , sacCCVersion :: Maybe String               -- CC Version (e.g., "3.1")
  , sacEvalAssuranceLevel :: Maybe Int         -- EAL1-7
  , sacEvalStatus :: Maybe String              -- "evaluationInProgress", "evaluationCompleted", etc.
  , sacPlus :: Maybe Bool                      -- Plus indicator
  , sacStrengthOfFunction :: Maybe String      -- "basic", "medium", "high"
  , sacProtectionProfileOID :: Maybe String    -- Protection Profile OID
  , sacProtectionProfileURI :: Maybe String    -- Protection Profile URI
  , sacSecurityTargetOID :: Maybe String       -- Security Target OID
  , sacSecurityTargetURI :: Maybe String       -- Security Target URI
  -- FIPS Level fields
  , sacFIPSVersion :: Maybe String             -- FIPS version (e.g., "140-2")
  , sacFIPSSecurityLevel :: Maybe Int          -- Security Level 1-4
  , sacFIPSPlus :: Maybe Bool                  -- FIPS Plus indicator
  -- RTM Type
  , sacRTMType :: Maybe String                 -- "static", "dynamic", "hybrid"
  -- ISO 9000
  , sacISO9000Certified :: Maybe Bool          -- ISO 9000 Certified
  , sacISO9000URI :: Maybe String              -- ISO 9000 URI
  } deriving (Show, Eq, Generic)

instance FromJSON SecurityAssertionsConfig where
  parseJSON = genericParseJSON securityOptions
instance ToJSON SecurityAssertionsConfig where
  toJSON = genericToJSON securityOptions

instance FromJSON PlatformCertConfig where
  parseJSON = genericParseJSON platformOptions
instance ToJSON PlatformCertConfig where
  toJSON = genericToJSON platformOptions

-- | YAML Configuration for Delta Platform Certificates
data DeltaCertConfig = DeltaCertConfig
  { dccManufacturer :: String
  , dccModel :: String
  , dccVersion :: String
  , dccSerial :: String
  , dccValidityDays :: Maybe Int
  , dccKeySize :: Maybe Int
  , dccComponents :: [ComponentConfig]
  -- Extended fields
  , dccPlatformConfigUri :: Maybe URIReferenceConfig  -- Platform Config URI with optional hash
  , dccPlatformClass :: Maybe String
  , dccSpecificationVersion :: Maybe String
  , dccMajorVersion :: Maybe Int
  , dccMinorVersion :: Maybe Int
  , dccPatchVersion :: Maybe Int
  , dccPlatformQualifier :: Maybe String
  -- Delta-specific fields
  , dccBaseCertificateSerial :: Maybe String
  , dccDeltaSequenceNumber :: Maybe Int
  , dccChangeDescription :: Maybe String
  } deriving (Show, Eq, Generic)

instance FromJSON DeltaCertConfig where
  parseJSON = genericParseJSON deltaOptions
instance ToJSON DeltaCertConfig where
  toJSON = genericToJSON deltaOptions

-- | Component Change Configuration for Delta certificates
data ComponentChangeConfig = ComponentChangeConfig
  { chgChangeType :: String
  , chgClass :: String
  , chgManufacturer :: String
  , chgModel :: String
  , chgSerial :: String
  , chgRevision :: String
  , chgPreviousRevision :: Maybe String
  } deriving (Show, Eq, Generic)

instance FromJSON ComponentChangeConfig where
  parseJSON = genericParseJSON changeOptions
instance ToJSON ComponentChangeConfig where
  toJSON = genericToJSON changeOptions

-- | Load YAML configuration file
loadConfig :: FilePath -> IO (Either String PlatformCertConfig)
loadConfig file = do
  result <- decodeFileEither file
  return $ case result of
    Left err -> Left (show err)
    Right config -> Right config

-- | Load Delta YAML configuration file
loadDeltaConfig :: FilePath -> IO (Either String DeltaCertConfig)
loadDeltaConfig file = do
  result <- decodeFileEither file
  return $ case result of
    Left err -> Left (show err)
    Right config -> Right config

-- | Create example YAML configuration file
createExampleConfig :: FilePath -> IO ()
createExampleConfig file = do
  let exampleConfig = PlatformCertConfig
        { pccManufacturer = "Test Corporation"
        , pccModel = "Test Platform"
        , pccVersion = "1.0"
        , pccSerial = "TEST001"
        , pccValidityDays = Just 365
        , pccKeySize = Just 2048
        -- Platform Config URI with optional hash for integrity verification
        -- Per TCG Platform Certificate Profile v1.1, URIReference includes hashAlgorithm and hashValue
        , pccPlatformConfigUri = Just URIReferenceConfig
            { uriUri = "https://example.com/platform-config/pcr-values"
            , uriHashAlgorithm = Just "sha256"
            -- Example: SHA-256 hash of the referenced document (base64-encoded)
            , uriHashValue = Just "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
            }
        , pccPlatformClass = Just "00000001"
        , pccSpecificationVersion = Just "1.1"
        , pccMajorVersion = Just 1
        , pccMinorVersion = Just 0
        , pccPatchVersion = Just 0
        , pccPlatformQualifier = Just "Enterprise"
        , pccCredentialSpecMajor = Just 1
        , pccCredentialSpecMinor = Just 1
        , pccCredentialSpecRevision = Just 13
        , pccPlatformSpecMajor = Just 2
        , pccPlatformSpecMinor = Just 0
        , pccPlatformSpecRevision = Just 164
        , pccSecurityAssertions = Just SecurityAssertionsConfig
            { sacVersion = Just 0
            , sacCCVersion = Just "3.1"
            , sacEvalAssuranceLevel = Just 4
            , sacEvalStatus = Just "evaluationCompleted"
            , sacPlus = Just False
            , sacStrengthOfFunction = Just "medium"
            , sacProtectionProfileOID = Nothing
            , sacProtectionProfileURI = Nothing
            , sacSecurityTargetOID = Nothing
            , sacSecurityTargetURI = Nothing
            , sacFIPSVersion = Just "140-2"
            , sacFIPSSecurityLevel = Just 2
            , sacFIPSPlus = Just False
            , sacRTMType = Just "hybrid"
            , sacISO9000Certified = Just False
            , sacISO9000URI = Nothing
            }
        , pccComponents =
            [ ComponentConfig
                { ccClass = "00030003"  -- TCG Registry: Motherboard
                , ccManufacturer = "Test Corporation"
                , ccModel = "Test Platform Motherboard"
                , ccSerial = Just "MB-TEST001"
                , ccRevision = Just "1.0"
                , ccAddresses = Nothing
                }
            , ComponentConfig
                { ccClass = "00010002"  -- TCG Registry: CPU
                , ccManufacturer = "Intel Corporation"
                , ccModel = "Xeon E5-2680"
                , ccSerial = Just "CPU-TEST001"
                , ccRevision = Just "Rev C0"
                , ccAddresses = Nothing
                }
            , ComponentConfig
                { ccClass = "00060004"  -- TCG Registry: DRAM Memory
                , ccManufacturer = "Samsung"
                , ccModel = "DDR4-3200"
                , ccSerial = Just "MEM-TEST001"
                , ccRevision = Just "1.35V"
                , ccAddresses = Nothing
                }
            ]
        }
  encodeFile file exampleConfig
  putStrLn $ "Example configuration created: " ++ file

-- | Create default TPM 2.0 information based on standard specification
createDefaultTPMInfo :: TPMInfo
createDefaultTPMInfo = TPMInfo
  { tpmModel = BC.pack "TPM 2.0"
  , tpmVersion = TPMVersion
      { tpmVersionMajor = 2
      , tpmVersionMinor = 0
      , tpmVersionRevMajor = 1
      , tpmVersionRevMinor = 59  -- Current TPM 2.0 revision as of 2023
      }
  , tpmSpecification = TPMSpecification
      { tpmSpecFamily = BC.pack "2.0"
      , tpmSpecLevel = 0
      , tpmSpecRevision = 164  -- TPM 2.0 Library Specification revision 164
      }
  }

-- | Convert YAML ComponentConfig to TCG ComponentIdentifier
yamlComponentToComponentIdentifier :: ComponentConfig -> ComponentIdentifier
yamlComponentToComponentIdentifier config =
  ComponentIdentifier
    { ciManufacturer = BC.pack (ccManufacturer config)
    , ciModel = BC.pack (ccModel config)
    , ciSerial = fmap BC.pack (ccSerial config)
    , ciRevision = fmap BC.pack (ccRevision config)
    , ciManufacturerSerial = Nothing
    , ciManufacturerRevision = Nothing
    }

-- | Convert PlatformCertConfig to ExtendedTCGAttributes
configToExtendedAttrs :: PlatformCertConfig -> ExtendedTCGAttributes
configToExtendedAttrs config =
  ExtendedTCGAttributes
    { etaPlatformConfigUri = fmap convertUriConfig (pccPlatformConfigUri config)
    , etaPlatformClass = fmap parseHexClass (pccPlatformClass config)
    , etaCredentialSpecVersion = buildVersion (pccCredentialSpecMajor config)
                                              (pccCredentialSpecMinor config)
                                              (pccCredentialSpecRevision config)
    , etaPlatformSpecVersion = buildVersion (pccPlatformSpecMajor config)
                                            (pccPlatformSpecMinor config)
                                            (pccPlatformSpecRevision config)
    , etaSecurityAssertions = fmap convertSecurityAssertions (pccSecurityAssertions config)
    , etaComponentsV2 = case pccComponents config of
        [] -> Nothing
        comps -> Just (map convertComponentToV2 comps)
    }
  where
    -- Convert URIReferenceConfig to PlatformConfigUri
    -- Per TCG Platform Certificate Profile v1.1, URIReference includes optional hash fields
    convertUriConfig :: URIReferenceConfig -> PlatformConfigUri
    convertUriConfig uriCfg = PlatformConfigUri
      { pcUri = BC.pack (uriUri uriCfg)
      , pcHashAlgorithm = fmap BC.pack (uriHashAlgorithm uriCfg)
      , pcHashValue = case uriHashValue uriCfg of
          Just b64Str -> case B64.decode (BC.pack b64Str) of
            Right decoded -> Just decoded
            Left _ -> Nothing  -- Invalid base64, ignore
          Nothing -> Nothing
      }

    -- Convert ComponentConfig to ComponentConfigV2 for platformConfiguration-v2 encoding
    convertComponentToV2 :: ComponentConfig -> ComponentConfigV2
    convertComponentToV2 comp = ComponentConfigV2
      { ccv2Class = parseHexClass (ccClass comp)
      , ccv2Manufacturer = BC.pack (ccManufacturer comp)
      , ccv2Model = BC.pack (ccModel comp)
      , ccv2Serial = fmap BC.pack (ccSerial comp)
      , ccv2Revision = fmap BC.pack (ccRevision comp)
      }

    -- Parse hex class string to ByteString (e.g., "00000001" -> "\x00\x00\x00\x01")
    parseHexClass :: String -> BC.ByteString
    parseHexClass hexStr =
      let -- Remove any spaces and group by 2 characters
          hexBytes = groupsOf 2 hexStr
          -- Convert each pair of hex digits to a Word8
          bytes = map (read . ("0x" ++)) hexBytes :: [Int]
      in BC.pack $ map (toEnum :: Int -> Char) bytes

    -- Convert SecurityAssertionsConfig to TBBSecurityAssertions
    convertSecurityAssertions :: SecurityAssertionsConfig -> TBBSecurityAssertions
    convertSecurityAssertions sac = TBBSecurityAssertions
      { tbbVersion = fromMaybe 0 (sacVersion sac)
      , tbbCCVersion = fmap BC.pack (sacCCVersion sac)
      , tbbEvalAssuranceLevel = sacEvalAssuranceLevel sac
      , tbbEvalStatus = fmap parseEvalStatus (sacEvalStatus sac)
      , tbbPlus = sacPlus sac
      , tbbStrengthOfFunction = fmap parseStrengthOfFunction (sacStrengthOfFunction sac)
      , tbbProtectionProfileOID = fmap BC.pack (sacProtectionProfileOID sac)
      , tbbProtectionProfileURI = fmap BC.pack (sacProtectionProfileURI sac)
      , tbbSecurityTargetOID = fmap BC.pack (sacSecurityTargetOID sac)
      , tbbSecurityTargetURI = fmap BC.pack (sacSecurityTargetURI sac)
      , tbbFIPSVersion = fmap BC.pack (sacFIPSVersion sac)
      , tbbFIPSSecurityLevel = sacFIPSSecurityLevel sac
      , tbbFIPSPlus = sacFIPSPlus sac
      , tbbRTMType = fmap parseRTMType (sacRTMType sac)
      , tbbISO9000Certified = sacISO9000Certified sac
      , tbbISO9000URI = fmap BC.pack (sacISO9000URI sac)
      }

    -- Parse evaluation status string to integer
    parseEvalStatus :: String -> Int
    parseEvalStatus "evaluationInProgress" = 0
    parseEvalStatus "evaluationCompleted" = 1
    parseEvalStatus "evaluationWithdrawn" = 2
    parseEvalStatus _ = 1 -- default to completed

    -- Parse strength of function string to integer
    parseStrengthOfFunction :: String -> Int
    parseStrengthOfFunction "basic" = 0
    parseStrengthOfFunction "medium" = 1
    parseStrengthOfFunction "high" = 2
    parseStrengthOfFunction _ = 1 -- default to medium

    -- Parse RTM type string to integer
    parseRTMType :: String -> Int
    parseRTMType "static" = 0
    parseRTMType "dynamic" = 1
    parseRTMType "nonHosted" = 2
    parseRTMType "hybrid" = 3
    parseRTMType _ = 0 -- default to static

    groupsOf :: Int -> [a] -> [[a]]
    groupsOf _ [] = []
    groupsOf n xs = take n xs : groupsOf n (drop n xs)

    buildVersion :: Maybe Int -> Maybe Int -> Maybe Int -> Maybe (Int, Int, Int)
    buildVersion (Just maj) (Just min) (Just rev) = Just (maj, min, rev)
    buildVersion _ _ _ = Nothing