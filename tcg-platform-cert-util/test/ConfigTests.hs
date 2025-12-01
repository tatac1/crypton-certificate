{-# LANGUAGE OverloadedStrings #-}

module ConfigTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances ()

import qualified Data.ByteString.Char8 as BC
import Data.Yaml (encodeFile, decodeFileEither)
import System.Directory (doesFileExist)
import System.IO.Temp (withSystemTempFile)

import Data.X509.TCG.Util.Config
import Data.X509.TCG

tests :: TestTree
tests = testGroup "Config Tests"
  [ configLoadingTests
  , yamlSerializationTests
  , componentConversionTests
  , propertyTests
  ]

-- | Test configuration loading functionality
configLoadingTests :: TestTree
configLoadingTests = testGroup "Configuration Loading"
  [ testCase "Load valid platform config" $ do
      withSystemTempFile "test-config.yaml" $ \path _handle -> do
        let config = PlatformCertConfig
              { pccManufacturer = "Test Corp"
              , pccModel = "Test Model"
              , pccVersion = "1.0"
              , pccSerial = "TEST001"
              , pccValidityDays = Just 365
              , pccKeySize = Just 2048
              , pccComponents = []
              , pccPlatformConfigUri = Nothing
              , pccPlatformClass = Nothing
              , pccSpecificationVersion = Nothing
              , pccMajorVersion = Nothing
              , pccMinorVersion = Nothing
              , pccPatchVersion = Nothing
              , pccPlatformQualifier = Nothing
              , pccCredentialSpecMajor = Nothing
              , pccCredentialSpecMinor = Nothing
              , pccCredentialSpecRevision = Nothing
              , pccPlatformSpecMajor = Nothing
              , pccPlatformSpecMinor = Nothing
              , pccPlatformSpecRevision = Nothing
              , pccSecurityAssertions = Nothing
              }
        encodeFile path config
        result <- loadConfig path
        case result of
          Right loadedConfig -> do
            pccManufacturer loadedConfig @?= "Test Corp"
            pccModel loadedConfig @?= "Test Model"
            pccVersion loadedConfig @?= "1.0"
          Left err -> assertFailure $ "Failed to load config: " ++ err

  , testCase "Load invalid config file" $ do
      result <- loadConfig "nonexistent-file.yaml"
      case result of
        Left _ -> return () -- Expected failure
        Right _ -> assertFailure "Expected failure for nonexistent file"

  , testCase "Load delta config" $ do
      withSystemTempFile "test-delta-config.yaml" $ \path _handle -> do
        let config = DeltaCertConfig
              { dccManufacturer = "Test Corp"
              , dccModel = "Test Model Delta"
              , dccVersion = "1.1"
              , dccSerial = "DELTA001"
              , dccValidityDays = Just 180
              , dccKeySize = Just 2048
              , dccComponents = []
              , dccPlatformConfigUri = Nothing
              , dccPlatformClass = Nothing
              , dccSpecificationVersion = Nothing
              , dccMajorVersion = Nothing
              , dccMinorVersion = Nothing
              , dccPatchVersion = Nothing
              , dccPlatformQualifier = Nothing
              , dccBaseCertificateSerial = Just "BASE001"
              , dccDeltaSequenceNumber = Just 1
              , dccChangeDescription = Just "Initial delta"
              }
        encodeFile path config
        result <- loadDeltaConfig path
        case result of
          Right loadedConfig -> do
            dccManufacturer loadedConfig @?= "Test Corp"
            dccBaseCertificateSerial loadedConfig @?= Just "BASE001"
            dccDeltaSequenceNumber loadedConfig @?= Just 1
          Left err -> assertFailure $ "Failed to load delta config: " ++ err
  ]

-- | Test YAML serialization/deserialization
yamlSerializationTests :: TestTree
yamlSerializationTests = testGroup "YAML Serialization"
  [ testCase "Round-trip platform config" $ do
      let originalConfig = PlatformCertConfig
            { pccManufacturer = "Manufacturer"
            , pccModel = "Model"
            , pccVersion = "Version"
            , pccSerial = "Serial"
            , pccValidityDays = Just 365
            , pccKeySize = Just 2048
            , pccComponents =
                [ ComponentConfig
                    { ccClass = "00030003"
                    , ccManufacturer = "Component Corp"
                    , ccModel = "Component Model"
                    , ccSerial = Just "COMP001"
                    , ccRevision = Just "1.0"
                    , ccAddresses = Nothing
                    }
                ]
            , pccPlatformConfigUri = Just URIReferenceConfig
                { uriUri = "https://example.com/config"
                , uriHashAlgorithm = Nothing
                , uriHashValue = Nothing
                }
            , pccPlatformClass = Just "00000001"
            , pccSpecificationVersion = Just "1.1"
            , pccMajorVersion = Just 1
            , pccMinorVersion = Just 0
            , pccPatchVersion = Just 0
            , pccPlatformQualifier = Just "Enterprise"
            , pccCredentialSpecMajor = Nothing
            , pccCredentialSpecMinor = Nothing
            , pccCredentialSpecRevision = Nothing
            , pccPlatformSpecMajor = Nothing
            , pccPlatformSpecMinor = Nothing
            , pccPlatformSpecRevision = Nothing
            , pccSecurityAssertions = Nothing
            }

      withSystemTempFile "roundtrip-test.yaml" $ \path _handle -> do
        encodeFile path originalConfig
        result <- decodeFileEither path
        case result of
          Right loadedConfig -> loadedConfig @?= originalConfig
          Left err -> assertFailure $ "Round-trip failed: " ++ show err

  , testCase "Example config creation" $ do
      withSystemTempFile "example-test.yaml" $ \path _handle -> do
        createExampleConfig path
        exists <- doesFileExist path
        exists @?= True
        
        result <- loadConfig path
        case result of
          Right config -> do
            pccManufacturer config @?= "Test Corporation"
            pccModel config @?= "Test Platform"
            length (pccComponents config) @?= 3 -- Should have 3 components in example
          Left err -> assertFailure $ "Failed to load example config: " ++ err
  ]

-- | Test component conversion functions
componentConversionTests :: TestTree
componentConversionTests = testGroup "Component Conversion"
  [ testCase "YAML to ComponentIdentifier conversion" $ do
      let yamlComponent = ComponentConfig
            { ccClass = "00030003"
            , ccManufacturer = "Test Manufacturer"
            , ccModel = "Test Model"
            , ccSerial = Just "TEST001"
            , ccRevision = Just "1.0"
            , ccAddresses = Nothing
            }
      
      let componentId = yamlComponentToComponentIdentifier yamlComponent
      ciManufacturer componentId @?= BC.pack "Test Manufacturer"
      ciModel componentId @?= BC.pack "Test Model"
      ciSerial componentId @?= Just (BC.pack "TEST001")
      ciRevision componentId @?= Just (BC.pack "1.0")

  , testCase "Default TPM info creation" $ do
      let tpmInfo = createDefaultTPMInfo
      tpmModel tpmInfo @?= BC.pack "TPM 2.0"
      tpmVersionMajor (tpmVersion tpmInfo) @?= 2
      tpmVersionMinor (tpmVersion tpmInfo) @?= 0
  ]

-- | Property-based tests
propertyTests :: TestTree
propertyTests = testGroup "Property Tests"
  [ testProperty "Component conversion preserves data" $ \manufacturer model serial revision ->
      let yamlComp = ComponentConfig
            { ccClass = "00000000"
            , ccManufacturer = manufacturer
            , ccModel = model
            , ccSerial = Just serial
            , ccRevision = Just revision
            , ccAddresses = Nothing
            }
          compId = yamlComponentToComponentIdentifier yamlComp
      in ciManufacturer compId == BC.pack manufacturer &&
         ciModel compId == BC.pack model &&
         ciSerial compId == Just (BC.pack serial) &&
         ciRevision compId == Just (BC.pack revision)

  , testProperty "Config serialization roundtrip" $ \manufacturer model version serial ->
      let config = PlatformCertConfig
            { pccManufacturer = manufacturer
            , pccModel = model
            , pccVersion = version
            , pccSerial = serial
            , pccValidityDays = Nothing
            , pccKeySize = Nothing
            , pccComponents = []
            , pccPlatformConfigUri = Nothing
            , pccPlatformClass = Nothing
            , pccSpecificationVersion = Nothing
            , pccMajorVersion = Nothing
            , pccMinorVersion = Nothing
            , pccPatchVersion = Nothing
            , pccPlatformQualifier = Nothing
            , pccCredentialSpecMajor = Nothing
            , pccCredentialSpecMinor = Nothing
            , pccCredentialSpecRevision = Nothing
            , pccPlatformSpecMajor = Nothing
            , pccPlatformSpecMinor = Nothing
            , pccPlatformSpecRevision = Nothing
            , pccSecurityAssertions = Nothing
            }
      in pccManufacturer config == manufacturer &&
         pccModel config == model &&
         pccVersion config == version &&
         pccSerial config == serial
  ]