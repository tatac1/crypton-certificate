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
  
  -- * Configuration Loading
  , loadConfig
  , loadDeltaConfig
  , createExampleConfig
  
  -- * Default Values
  , createDefaultTPMInfo
  , yamlComponentToComponentIdentifier
  ) where

import qualified Data.ByteString.Char8 as BC
import Data.X509.TCG
import Data.Yaml (FromJSON (..), ToJSON (..), decodeFileEither, encodeFile)
import GHC.Generics (Generic)

-- | YAML Configuration for Platform Certificate components
data ComponentConfig = ComponentConfig
  { ccClass :: String
  , ccManufacturer :: String
  , ccModel :: String
  , ccSerial :: String
  , ccRevision :: String
  } deriving (Show, Eq, Generic)

instance FromJSON ComponentConfig
instance ToJSON ComponentConfig

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
  , pccPlatformConfigUri :: Maybe String
  , pccPlatformClass :: Maybe String
  , pccSpecificationVersion :: Maybe String
  , pccMajorVersion :: Maybe Int
  , pccMinorVersion :: Maybe Int
  , pccPatchVersion :: Maybe Int
  , pccPlatformQualifier :: Maybe String
  } deriving (Show, Eq, Generic)

instance FromJSON PlatformCertConfig
instance ToJSON PlatformCertConfig

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
  , dccPlatformConfigUri :: Maybe String
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

instance FromJSON DeltaCertConfig
instance ToJSON DeltaCertConfig

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

instance FromJSON ComponentChangeConfig
instance ToJSON ComponentChangeConfig

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
        , pccPlatformConfigUri = Just "https://example.com/platform-config/pcr-values"
        , pccPlatformClass = Just "00000001"
        , pccSpecificationVersion = Just "1.1"
        , pccMajorVersion = Just 1
        , pccMinorVersion = Just 0
        , pccPatchVersion = Just 0
        , pccPlatformQualifier = Just "Enterprise"
        , pccComponents =
            [ ComponentConfig
                { ccClass = "00030003"  -- TCG Registry: Motherboard
                , ccManufacturer = "Test Corporation"
                , ccModel = "Test Platform Motherboard"
                , ccSerial = "MB-TEST001"
                , ccRevision = "1.0"
                }
            , ComponentConfig
                { ccClass = "00010002"  -- TCG Registry: CPU
                , ccManufacturer = "Intel Corporation"
                , ccModel = "Xeon E5-2680"
                , ccSerial = "CPU-TEST001"
                , ccRevision = "Rev C0"
                }
            , ComponentConfig
                { ccClass = "00060004"  -- TCG Registry: DRAM Memory
                , ccManufacturer = "Samsung"
                , ccModel = "DDR4-3200"
                , ccSerial = "MEM-TEST001"
                , ccRevision = "1.35V"
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
    , ciSerial = Just (BC.pack (ccSerial config)) 
    , ciRevision = Just (BC.pack (ccRevision config))
    , ciManufacturerSerial = Nothing
    , ciManufacturerRevision = Nothing
    }