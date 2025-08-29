{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.Display
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- Display and formatting utilities for TCG Platform Certificates.
-- This module provides functions for pretty-printing certificate information,
-- components, and attributes in human-readable format.

module Data.X509.TCG.Util.Display
  ( -- * Certificate Display
    showPlatformCert
  , showPlatformCertSmall
  , showComponentInformation
  , showSingleComponent
  
  -- * Attribute Display
  , showTCGAttribute
  , showExtendedPlatformAttributes
  , isExtendedAttribute
  
  -- * Utility Functions
  , certificationLevelName
  , rtmTypeName
  ) where

import Control.Monad (forM_, unless, when)
import qualified Data.ByteString as B
import Data.Hourglass (timePrint)
import Data.X509.AttCert (AttCertValidityPeriod(..))
import Data.X509.Attribute (unAttributes)
import Data.X509.TCG
import Data.X509.TCG.Util.ASN1 (hexdump)

-- | Show detailed platform certificate information
showPlatformCert :: SignedPlatformCertificate -> IO ()
showPlatformCert signedCert = do
  let certInfo = getPlatformCertificate signedCert
      validity = pciValidity certInfo

  putStrLn $ "Platform Certificate Information:"
  putStrLn $ "Version: v" ++ show (pciVersion certInfo)
  putStrLn $ "Serial Number: " ++ show (pciSerialNumber certInfo)
  putStrLn $ "Signature Algorithm: " ++ show (pciSignature certInfo)

  -- Show validity period
  putStrLn $ "Validity: " ++ formatValidityPeriod validity

  -- Show platform information
  case getPlatformInfo signedCert of
    Just info -> do
      putStrLn "Platform Information:"
      putStrLn $ "  Manufacturer: " ++ show (piManufacturer info)
      putStrLn $ "  Model: " ++ show (piModel info)
      putStrLn $ "  Version: " ++ show (piVersion info)
      putStrLn $ "  Serial: " ++ show (piSerial info)
    Nothing -> putStrLn "No platform information found"

  -- Show TPM information
  case getTPMInfo signedCert of
    Just tpmInfo -> do
      putStrLn "TPM Information:"
      putStrLn $ "  Model: " ++ show (tpmModel tpmInfo)
      putStrLn $ "  Version: " ++ show (tpmVersion tpmInfo)
    Nothing -> putStrLn "No TPM information found"

  -- Show component information
  let components = getComponentIdentifiers signedCert
  putStrLn $ "Components (" ++ show (length components) ++ "):"
  forM_ (take 5 components) $ \comp -> do
    putStrLn $ "  - " ++ show (ciManufacturer comp) ++ " " ++ show (ciModel comp)
  when (length components > 5) $
    putStrLn $
      "  ... and " ++ show (length components - 5) ++ " more"

  -- Show attributes
  let attrs = pciAttributes certInfo
      tcgAttrs = extractTCGAttributes signedCert
  let attrList = unAttributes attrs
  putStrLn $ "Certificate Attributes (" ++ show (length attrList) ++ "):"
  forM_ (take 3 attrList) $ \attr ->
    putStrLn $ "  " ++ show attr
  when (length attrList > 3) $
    putStrLn $ "  ... and " ++ show (length attrList - 3) ++ " more"
  
  putStrLn $ "TCG Specific Attributes (" ++ show (length tcgAttrs) ++ "):"
  forM_ tcgAttrs $ \attr -> do
    showTCGAttribute attr
  
  -- Show extended platform attributes specifically
  showExtendedPlatformAttributes tcgAttrs
  where
    formatValidityPeriod (AttCertValidityPeriod start end) =
      timePrint ("YYYY-MM-DD H:MI:S" :: String) start
        ++ " to "
        ++ timePrint ("YYYY-MM-DD H:MI:S" :: String) end

-- | Show platform certificate information in a compact format
showPlatformCertSmall :: SignedPlatformCertificate -> IO ()
showPlatformCertSmall signedCert = do
  let certInfo = getPlatformCertificate signedCert
      validity = pciValidity certInfo
  putStrLn $ "Serial: " ++ show (pciSerialNumber certInfo)
  putStrLn $ "Version: v" ++ show (pciVersion certInfo)
  putStrLn $ "Valid: " ++ formatValidityPeriod validity
  case getPlatformInfo signedCert of
    Just info -> do
      putStrLn $ "Manufacturer: " ++ show (piManufacturer info)
      putStrLn $ "Model: " ++ show (piModel info)
      putStrLn $ "Serial: " ++ show (piSerial info)
    Nothing -> putStrLn "No platform info found"
  where
    formatValidityPeriod (AttCertValidityPeriod start end) =
      timePrint ("YYYY-MM-DD H:MI:S" :: String) start
        ++ " to "
        ++ timePrint ("YYYY-MM-DD H:MI:S" :: String) end

-- | Show component information from a parsed Platform Certificate
showComponentInformation :: SignedPlatformCertificate -> Bool -> IO ()
showComponentInformation signedCert verbose = do
  putStrLn "Platform Certificate Components:"
  putStrLn ""

  -- Extract basic platform information
  putStrLn "=== Platform Information ==="
  case getPlatformInfo signedCert of
    Just info -> do
      putStrLn $ "Manufacturer: " ++ show (piManufacturer info)
      putStrLn $ "Model: " ++ show (piModel info)
      putStrLn $ "Version: " ++ show (piVersion info)
      putStrLn $ "Serial Number: " ++ show (piSerial info)
    Nothing -> putStrLn "No platform information found"

  putStrLn ""

  -- Extract TPM information
  putStrLn "=== TPM Information ==="
  case getTPMInfo signedCert of
    Just tpmInfo -> do
      putStrLn $ "Model: " ++ show (tpmModel tpmInfo)
      putStrLn $ "Version: " ++ show (tpmVersion tpmInfo)
      when verbose $ do
        putStrLn $ "Specification: " ++ show (tpmSpecification tpmInfo)
    Nothing -> putStrLn "No TPM information found"

  putStrLn ""

  -- Extract component identifiers
  putStrLn "=== Component Identifiers ==="
  let components = getComponentIdentifiers signedCert
  if null components
    then putStrLn "No component identifiers found"
    else do
      putStrLn $ "Found " ++ show (length components) ++ " component(s):"
      mapM_ (showSingleComponent verbose) (zip [1 ..] components)

  putStrLn ""

  -- Extract additional attributes
  when verbose $ do
    putStrLn "=== Additional TCG Attributes ==="
    let tcgAttrs = extractTCGAttributes signedCert
    if null tcgAttrs
      then putStrLn "No additional TCG attributes found"
      else do
        putStrLn $ "Found " ++ show (length tcgAttrs) ++ " attribute(s):"
        mapM_
          (\(i, attr) -> putStrLn $ "  [" ++ show (i :: Int) ++ "] " ++ show attr)
          (zip [1 ..] tcgAttrs)

-- | Show a single component with details
showSingleComponent :: Bool -> (Int, ComponentIdentifier) -> IO ()
showSingleComponent verbose (index, comp) = do
  putStrLn $ "  [" ++ show index ++ "] Component:"
  putStrLn $ "      Manufacturer: " ++ show (ciManufacturer comp)
  putStrLn $ "      Model: " ++ show (ciModel comp)
  when verbose $ do
    putStrLn $ "      Serial: " ++ show (ciSerial comp)
    putStrLn $ "      Revision: " ++ show (ciRevision comp)

-- | Show detailed information for TCG attributes
showTCGAttribute :: TCGAttribute -> IO ()
showTCGAttribute attr = case attr of
  TCGPlatformManufacturer (PlatformManufacturerAttr mfg) ->
    putStrLn $ "  Platform Manufacturer: " ++ show mfg
  TCGPlatformModel (PlatformModelAttr model) ->
    putStrLn $ "  Platform Model: " ++ show model
  TCGPlatformSerial (PlatformSerialAttr serial) ->
    putStrLn $ "  Platform Serial: " ++ show serial
  TCGPlatformVersion (PlatformVersionAttr version) ->
    putStrLn $ "  Platform Version: " ++ show version
  TCGTPMModel (TPMModelAttr model) ->
    putStrLn $ "  TPM Model: " ++ show model
  TCGComponentIdentifier (ComponentIdentifierAttr comp _) ->
    putStrLn $ "  Component: " ++ show (ciManufacturer comp) ++ " " ++ show (ciModel comp)
  TCGComponentIdentifierV2 (ComponentIdentifierV2Attr comp _ _) ->
    putStrLn $ "  Component v2: " ++ show (ci2Manufacturer comp) ++ " " ++ show (ci2Model comp)
  -- Extended platform attributes with detailed display
  TCGPlatformConfigUri (PlatformConfigUriAttr uri desc) -> do
    putStrLn $ "  Platform Configuration URI: " ++ show uri
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGPlatformClass (PlatformClassAttr cls desc) -> do
    putStrLn $ "  Platform Class: " ++ show cls
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGCertificationLevel (CertificationLevelAttr lvl desc) -> do
    putStrLn $ "  Certification Level: " ++ show lvl ++ " (" ++ certificationLevelName lvl ++ ")"
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGPlatformQualifiers (PlatformQualifiersAttr quals desc) -> do
    putStrLn $ "  Platform Qualifiers (" ++ show (length quals) ++ "):"
    forM_ quals $ \qual -> putStrLn $ "    - " ++ show qual
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGRootOfTrust (RootOfTrustAttr measure alg desc) -> do
    putStrLn $ "  Root of Trust:"
    putStrLn $ "    Measurement: " ++ hexdump measure
    putStrLn $ "    Algorithm: " ++ show alg
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGRTMType (RTMTypeAttr typ desc) -> do
    putStrLn $ "  RTM Type: " ++ show typ ++ " (" ++ rtmTypeName typ ++ ")"
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGBootMode (BootModeAttr mode desc) -> do
    putStrLn $ "  Boot Mode: " ++ show mode
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGFirmwareVersion (FirmwareVersionAttr ver desc) -> do
    putStrLn $ "  Firmware Version: " ++ show ver
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGPolicyReference (PolicyReferenceAttr uri desc) -> do
    putStrLn $ "  Policy Reference URI: " ++ show uri
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  other -> putStrLn $ "  " ++ show other

-- | Show extended platform attributes summary
showExtendedPlatformAttributes :: [TCGAttribute] -> IO ()
showExtendedPlatformAttributes attrs = do
  let extendedAttrs = filter isExtendedAttribute attrs
  unless (null extendedAttrs) $ do
    putStrLn ""
    putStrLn "Extended Platform Attributes Summary:"
    forM_ extendedAttrs $ \attr -> case attr of
      TCGPlatformConfigUri (PlatformConfigUriAttr uri _) ->
        putStrLn $ "  ✓ Platform Configuration URI: " ++ show uri
      TCGPlatformClass (PlatformClassAttr cls _) ->
        putStrLn $ "  ✓ Platform Class: " ++ show cls
      TCGCertificationLevel (CertificationLevelAttr lvl _) ->
        putStrLn $ "  ✓ Certification Level: " ++ show lvl ++ " (" ++ certificationLevelName lvl ++ ")"
      TCGRootOfTrust (RootOfTrustAttr _ alg _) ->
        putStrLn $ "  ✓ Root of Trust (Algorithm: " ++ show alg ++ ")"
      TCGRTMType (RTMTypeAttr typ _) ->
        putStrLn $ "  ✓ RTM Type: " ++ rtmTypeName typ
      TCGBootMode (BootModeAttr mode _) ->
        putStrLn $ "  ✓ Boot Mode: " ++ show mode
      TCGFirmwareVersion (FirmwareVersionAttr ver _) ->
        putStrLn $ "  ✓ Firmware Version: " ++ show ver
      TCGPolicyReference (PolicyReferenceAttr uri _) ->
        putStrLn $ "  ✓ Policy Reference: " ++ show uri
      _ -> return ()

-- | Check if attribute is an extended platform attribute
isExtendedAttribute :: TCGAttribute -> Bool
isExtendedAttribute attr = case attr of
  TCGPlatformConfigUri _ -> True
  TCGPlatformClass _ -> True
  TCGCertificationLevel _ -> True
  TCGPlatformQualifiers _ -> True
  TCGRootOfTrust _ -> True
  TCGRTMType _ -> True
  TCGBootMode _ -> True
  TCGFirmwareVersion _ -> True
  TCGPolicyReference _ -> True
  _ -> False

-- | Get certification level name
certificationLevelName :: Int -> String
certificationLevelName lvl = case lvl of
  1 -> "Basic"
  2 -> "Standard"
  3 -> "Enhanced"
  4 -> "High"
  5 -> "Very High"
  6 -> "Critical"
  7 -> "Ultra"
  _ -> "Unknown"

-- | Get RTM type name
rtmTypeName :: Int -> String
rtmTypeName typ = case typ of
  1 -> "BIOS"
  2 -> "UEFI"
  3 -> "Other"
  _ -> "Unknown"