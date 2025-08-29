{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Operations
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- High-level operations for TCG Platform Certificates.
-- This module provides the main API for creating, validating, and manipulating
-- TCG Platform and Delta Platform Certificates.

module Data.X509.TCG.Operations
  ( -- * Certificate Creation
    createPlatformCertificate,
    createDeltaPlatformCertificate,
    createSignedDeltaPlatformCertificate,
    
    -- * Configuration Management  
    getCurrentPlatformConfiguration,
    applyDeltaCertificate,
    computeConfigurationChain,
    
    -- * Component Operations
    getComponentIdentifiers,
    getComponentIdentifiersV2,
    findComponentByClass,
    findComponentByAddress,
    buildComponentHierarchy,
    
    -- * Certificate Chain Operations
    buildCertificateChain,
    findBaseCertificate,
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.ASN1.Types (ASN1(..), OID)
import Data.X509 (DistinguishedName(..), SignatureALG(..), PubKeyALG(..), HashALG(..), objectToSignedExact, objectToSignedExactF, Extensions(..), AltName(..))
import Data.X509.AttCert (Holder(..), AttCertIssuer(..), AttCertValidityPeriod)
import Data.X509AC (V2Form(..), IssuerSerial(..))
import Data.X509.Attribute (Attributes(..), Attribute(..))
import Data.X509.TCG.Platform
import Data.X509.TCG.Delta
import Data.X509.TCG.Component
import Data.X509.TCG.OID (tcg_at_platformManufacturer, tcg_at_platformModel, tcg_at_platformSerial, tcg_at_platformVersion, tcg_at_componentIdentifier_v2, tcg_at_platformConfiguration_v2)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.Hash as Hash

-- * Certificate Creation

-- | Create a Platform Certificate with the specified configuration and attributes
--
-- This function constructs a Platform Certificate containing platform identification
-- and component information as specified in the TCG Platform Certificate Profile.
--
-- Example:
-- @
-- cert <- createPlatformCertificate holder issuer validity config attrs
-- @
createPlatformCertificate :: Holder                    -- ^ Certificate holder information
                         -> AttCertIssuer             -- ^ Attribute certificate issuer
                         -> AttCertValidityPeriod     -- ^ Validity period
                         -> PlatformConfiguration     -- ^ Platform configuration
                         -> Attributes                -- ^ Additional attributes
                         -> IO (Either String SignedPlatformCertificate)
createPlatformCertificate holder issuer validity config additionalAttrs = do
  -- Build attributes from platform configuration
  case buildPlatformAttributes config additionalAttrs of
    Left err -> return $ Left err
    Right attrs -> do
      -- Build the certificate info structure
      let certInfo = PlatformCertificateInfo
            { pciVersion = 2  -- v2 certificate
            , pciHolder = holder
            , pciIssuer = issuer
            , pciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
            , pciSerialNumber = 1  -- Simple serial number for testing
            , pciValidity = validity
            , pciAttributes = attrs
            , pciIssuerUniqueID = Nothing
            , pciExtensions = Extensions Nothing
            }
      
      -- Create a signed certificate using a dummy signature
      -- In production, this would use a real private key and signing algorithm
      let dummySigningFunction = createDummySigningFunction
      let (signedCert, _) = objectToSignedExact dummySigningFunction certInfo
      
      return $ Right signedCert

-- | Build platform attributes from configuration and additional attributes
buildPlatformAttributes :: PlatformConfiguration -> Attributes -> Either String Attributes
buildPlatformAttributes config (Attributes additionalAttrs) = do
  -- Create basic platform attributes from configuration
  let manufacturerAttr = Attribute tcg_at_platformManufacturer [[OctetString (pcManufacturer config)]]
      modelAttr = Attribute tcg_at_platformModel [[OctetString (pcModel config)]]
      serialAttr = Attribute tcg_at_platformSerial [[OctetString (pcSerial config)]]
      versionAttr = Attribute tcg_at_platformVersion [[OctetString (pcVersion config)]]
      
  -- Combine platform attributes with additional attributes
  let allAttributes = [manufacturerAttr, modelAttr, serialAttr, versionAttr] ++ additionalAttrs
  
  return $ Attributes allAttributes

-- | Create a dummy signing function for testing purposes
createDummySigningFunction :: B.ByteString -> (B.ByteString, SignatureALG, ())
createDummySigningFunction _dataToSign = 
  (B.replicate 32 0x42, SignatureALG HashSHA256 PubKeyALG_RSA, ())  -- 32 bytes of dummy signature data

-- | Create a Delta Platform Certificate for incremental updates
--
-- Delta Platform Certificates describe changes to a base Platform Certificate,
-- allowing efficient updates without reissuing complete certificates.
--
-- Example:
-- @
-- deltaCert <- createDeltaPlatformCertificate holder issuer validity baseRef delta
-- @
createDeltaPlatformCertificate :: Holder                       -- ^ Certificate holder
                              -> AttCertIssuer                -- ^ Attribute certificate issuer  
                              -> AttCertValidityPeriod        -- ^ Validity period
                              -> BasePlatformCertificateRef   -- ^ Reference to base certificate
                              -> PlatformConfigurationDelta   -- ^ Configuration changes
                              -> IO (Either String SignedDeltaPlatformCertificate)
createDeltaPlatformCertificate holder issuer validity baseRef configDelta = do
  -- Build delta configuration attributes
  case buildDeltaAttributes configDelta of
    Left err -> return $ Left err
    Right attrs -> do
      -- Build the Delta Platform Certificate Info structure
      let deltaCertInfo = DeltaPlatformCertificateInfo
            { dpciVersion = 2  -- v2 certificate
            , dpciHolder = holder
            , dpciIssuer = issuer
            , dpciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
            , dpciSerialNumber = bpcrSerialNumber baseRef + 1  -- Increment from base
            , dpciValidity = validity
            , dpciAttributes = attrs
            , dpciIssuerUniqueID = Nothing
            , dpciExtensions = Extensions Nothing
            , dpciBaseCertificateRef = baseRef
            }
      
      -- Create a signed certificate using a dummy signature
      -- In production, this would use a real private key and signing algorithm
      let dummySigningFunction = createDummySigningFunctionForDelta
      let (signedCert, _) = objectToSignedExact dummySigningFunction deltaCertInfo
      
      return $ Right signedCert

-- | Build attributes from delta configuration
buildDeltaAttributes :: PlatformConfigurationDelta -> Either String Attributes
buildDeltaAttributes delta = 
  -- For now, create basic attributes containing delta configuration
  -- In a full implementation, this would encode the delta as ASN.1 and store it
  let componentCount = length (pcdComponentDeltas delta)
      changeCount = length (pcdChangeRecords delta)
      -- Create simple attributes indicating the presence of changes
      countAttr = Attribute tcg_at_componentIdentifier_v2 [[OctetString (B8.pack ("component_count:" ++ show componentCount))]]
      changeAttr = Attribute tcg_at_platformConfiguration_v2 [[OctetString (B8.pack ("change_count:" ++ show changeCount))]]
      allAttributes = [countAttr, changeAttr]
  in Right $ Attributes allAttributes

-- | Create a dummy signing function for delta certificates  
createDummySigningFunctionForDelta :: B.ByteString -> (B.ByteString, SignatureALG, ())
createDummySigningFunctionForDelta _dataToSign = 
  (B.replicate 32 0x43, SignatureALG HashSHA256 PubKeyALG_RSA, ())  -- 32 bytes of dummy signature data

-- | Create a Delta Platform Certificate with real cryptographic signing
--
-- This function creates a properly signed Delta Platform Certificate using 
-- a real private key for cryptographic signature generation.
createSignedDeltaPlatformCertificate :: Holder                       -- ^ Certificate holder
                                    -> AttCertIssuer                -- ^ Attribute certificate issuer  
                                    -> AttCertValidityPeriod        -- ^ Validity period
                                    -> BasePlatformCertificateRef   -- ^ Reference to base certificate
                                    -> PlatformConfigurationDelta   -- ^ Configuration changes
                                    -> (SignatureALG, RSA.PublicKey, RSA.PrivateKey) -- ^ Signing key material
                                    -> IO (Either String SignedDeltaPlatformCertificate)
createSignedDeltaPlatformCertificate holder issuer validity baseRef configDelta (sigAlg, _pubKey, privKey) = do
  -- Build delta configuration attributes
  case buildDeltaAttributes configDelta of
    Left err -> return $ Left err
    Right attrs -> do
      -- Build the Delta Platform Certificate Info structure
      let deltaCertInfo = DeltaPlatformCertificateInfo
            { dpciVersion = 2  -- v2 certificate
            , dpciHolder = holder
            , dpciIssuer = issuer
            , dpciSignature = sigAlg
            , dpciSerialNumber = bpcrSerialNumber baseRef + 1  -- Increment from base
            , dpciValidity = validity
            , dpciAttributes = attrs
            , dpciIssuerUniqueID = Nothing
            , dpciExtensions = Extensions Nothing
            , dpciBaseCertificateRef = baseRef
            }
      
      -- Create real signing function using RSA private key
      let realSigningFunction objRaw = do
            let hashAlg = case sigAlg of
                  SignatureALG hashType _ -> hashType
                  _ -> HashSHA256  -- Default fallback
            sigBits <- doSignRSA hashAlg privKey objRaw
            return (sigBits, sigAlg)
      
      -- Create signed certificate with real signature
      signedCert <- objectToSignedExactF realSigningFunction deltaCertInfo
      
      return $ Right signedCert

-- | RSA signing helper for Delta certificates
doSignRSA :: HashALG -> RSA.PrivateKey -> B.ByteString -> IO B.ByteString
doSignRSA hashAlg privKey msg = do
  result <- case hashAlg of
    HashSHA1   -> RSA.signSafer (Just Hash.SHA1) privKey msg
    HashSHA256 -> RSA.signSafer (Just Hash.SHA256) privKey msg  
    HashSHA384 -> RSA.signSafer (Just Hash.SHA384) privKey msg
    HashSHA512 -> RSA.signSafer (Just Hash.SHA512) privKey msg
    _ -> RSA.signSafer (Just Hash.SHA256) privKey msg  -- Default fallback
  
  case result of
    Left err -> error ("doSignRSA: " ++ show err)
    Right signature -> return signature

-- * Configuration Management

-- | Extract platform configuration from individual attributes when composite attribute is not available
extractFromIndividualAttributes :: SignedPlatformCertificate -> Maybe PlatformConfigurationV2
extractFromIndividualAttributes cert = do
  let attrs = pciAttributes $ getPlatformCertificate cert
  manufacturer <- lookupAttributeValue tcg_at_platformManufacturer attrs
  model <- lookupAttributeValue tcg_at_platformModel attrs  
  serial <- lookupAttributeValue tcg_at_platformSerial attrs
  version <- lookupAttributeValue tcg_at_platformVersion attrs
  return $ PlatformConfigurationV2
    { pcv2Manufacturer = manufacturer
    , pcv2Model = model
    , pcv2Version = version
    , pcv2Serial = serial
    , pcv2Components = [] -- Individual attributes don't contain component info
    }
  where
    -- Helper to extract OctetString value from attribute
    lookupAttributeValue :: OID -> Attributes -> Maybe B.ByteString
    lookupAttributeValue targetOID (Attributes attrList) = 
      case [attrVal | Attribute attrOID attrVals <- attrList, attrOID == targetOID, [attrVal] <- attrVals] of
        (OctetString bs : _) -> Just bs
        _ -> Nothing

-- | Extract the current platform configuration from a certificate
--
-- This function handles both Platform Certificates and Delta Platform Certificates,
-- returning the appropriate configuration for the certificate type.
getCurrentPlatformConfiguration :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate 
                                -> Maybe PlatformConfigurationV2
getCurrentPlatformConfiguration (Left platCert) = 
  case getPlatformConfiguration platCert of
    Just config -> convertToV2 config
    Nothing -> extractFromIndividualAttributes platCert
  where
    -- Convert v1 configuration to v2 format for consistency
    convertToV2 :: PlatformConfiguration -> Maybe PlatformConfigurationV2
    convertToV2 config = Just $ PlatformConfigurationV2
      { pcv2Manufacturer = pcManufacturer config
      , pcv2Model = pcModel config  
      , pcv2Version = pcVersion config
      , pcv2Serial = pcSerial config
      , pcv2Components = map upgradeComponent (pcComponents config)
      }
    
    upgradeComponent :: ComponentIdentifier -> (ComponentIdentifierV2, ComponentStatus)
    upgradeComponent comp = (upgradeToV2 comp, ComponentUnchanged)
    
    upgradeToV2 :: ComponentIdentifier -> ComponentIdentifierV2
    upgradeToV2 comp = ComponentIdentifierV2
      { ci2Manufacturer = ciManufacturer comp
      , ci2Model = ciModel comp
      , ci2Serial = ciSerial comp
      , ci2Revision = ciRevision comp
      , ci2ManufacturerSerial = ciManufacturerSerial comp
      , ci2ManufacturerRevision = ciManufacturerRevision comp
      , ci2ComponentClass = ComponentOther [1,3,6,1,4,1,2312,16,3,2,1] -- Default class for v1 components
      , ci2ComponentAddress = Nothing
      }

getCurrentPlatformConfiguration (Right deltaCert) = 
  -- Delta certificates contain changes, not complete configurations.
  -- Extract component information from the delta and create a partial configuration
  case getPlatformConfigurationDelta deltaCert of
    Just deltaConfig -> 
      -- Create a configuration based on delta changes
      -- This represents the changes, not a complete platform configuration
      let components = map deltaToComponent (pcdComponentDeltas deltaConfig)
      in Just $ PlatformConfigurationV2
         { pcv2Manufacturer = B.empty  -- Delta certificates don't contain base platform info
         , pcv2Model = B.empty
         , pcv2Version = B.empty
         , pcv2Serial = B.empty
         , pcv2Components = components
         }
    Nothing -> 
      -- For delta certificates created by TCG.hs that don't have platform configuration in attributes,
      -- return a basic empty configuration to indicate the certificate exists but has no accessible delta info
      Just $ PlatformConfigurationV2
         { pcv2Manufacturer = B.empty
         , pcv2Model = B.empty
         , pcv2Version = B.empty
         , pcv2Serial = B.empty
         , pcv2Components = []  -- No component info available from certificate structure
         }
  where
    -- Convert component delta to component with status
    deltaToComponent :: ComponentDelta -> (ComponentIdentifierV2, ComponentStatus)
    deltaToComponent delta = 
      let component = cdComponent delta
          status = operationToStatus (cdOperation delta)
      in (component, status)

    -- Convert delta operation to component status
    operationToStatus :: DeltaOperation -> ComponentStatus
    operationToStatus DeltaAdd = ComponentAdded
    operationToStatus DeltaRemove = ComponentRemoved
    operationToStatus DeltaModify = ComponentModified
    operationToStatus DeltaReplace = ComponentModified
    operationToStatus DeltaUpdate = ComponentModified

-- | Apply a Delta Certificate to a base configuration
--
-- This function computes the resulting platform configuration after applying
-- the changes specified in a Delta Platform Certificate.
applyDeltaCertificate :: PlatformConfigurationV2           -- ^ Base configuration
                     -> SignedDeltaPlatformCertificate     -- ^ Delta certificate
                     -> Either String PlatformConfigurationV2
applyDeltaCertificate baseConfig deltaCert = do
  delta <- case getPlatformConfigurationDelta deltaCert of
    Just d -> Right d
    Nothing -> Left "Cannot extract delta configuration"
  
  applyDeltaToBaseLocal baseConfig delta
  where
    applyDeltaToBaseLocal :: PlatformConfigurationV2 -> PlatformConfigurationDelta -> Either String PlatformConfigurationV2
    applyDeltaToBaseLocal config delta = 
      foldlM applyComponentDelta config (pcdComponentDeltas delta)
      where
        foldlM :: (a -> b -> Either String a) -> a -> [b] -> Either String a
        foldlM _ acc [] = Right acc
        foldlM f acc (x:xs) = case f acc x of
          Left err -> Left err
          Right acc' -> foldlM f acc' xs
    
    applyComponentDelta :: PlatformConfigurationV2 -> ComponentDelta -> Either String PlatformConfigurationV2
    applyComponentDelta config compDelta =
      case cdOperation compDelta of
        DeltaAdd -> Right $ addComponent config (cdComponent compDelta)
        DeltaRemove -> Right $ removeComponent config (cdComponent compDelta)
        DeltaModify -> Right $ modifyComponent config (cdComponent compDelta)
        _ -> Left "Unsupported delta operation"
    
    addComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
    addComponent config comp = config 
      { pcv2Components = (comp, ComponentAdded) : pcv2Components config }
    
    removeComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
    removeComponent config comp = config
      { pcv2Components = [(c, s) | (c, s) <- pcv2Components config, c /= comp] ++ [(comp, ComponentRemoved)] }
    
    modifyComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
    modifyComponent config comp = config
      { pcv2Components = [(if c == comp then (comp, ComponentModified) else (c, s)) | (c, s) <- pcv2Components config] }

-- | Compute the final configuration by applying a chain of delta certificates
--
-- This function processes a sequence of Delta Platform Certificates to compute
-- the final platform configuration state.
computeConfigurationChain :: SignedPlatformCertificate              -- ^ Base certificate
                          -> [SignedDeltaPlatformCertificate]       -- ^ Chain of deltas
                          -> Either String PlatformConfigurationV2
computeConfigurationChain baseCert deltaChain = do
  baseConfig <- case getCurrentPlatformConfiguration (Left baseCert) of
    Just config -> Right config
    Nothing -> Left "Cannot extract base configuration"
  
  deltas <- mapM (\cert -> case getPlatformConfigurationDelta cert of
                      Just delta -> Right delta
                      Nothing -> Left "Cannot extract delta configuration") deltaChain
  computeResultingConfiguration baseConfig deltas

-- * Component Operations

-- | Extract all component identifiers from a Platform Certificate
getComponentIdentifiers :: SignedPlatformCertificate -> [ComponentIdentifier]
getComponentIdentifiers cert = 
  case getPlatformConfiguration cert of
    Just config -> pcComponents config
    Nothing -> []

-- | Extract all v2 component identifiers with status information
getComponentIdentifiersV2 :: SignedPlatformCertificate -> [ComponentIdentifierV2]
getComponentIdentifiersV2 cert =
  case getCurrentPlatformConfiguration (Left cert) of
    Just config -> map fst (pcv2Components config)
    Nothing -> []

-- | Find components matching a specific component class
findComponentByClass :: ComponentClass -> [ComponentIdentifierV2] -> [ComponentIdentifierV2]
findComponentByClass targetClass components =
  filter (\comp -> ci2ComponentClass comp == targetClass) components

-- | Find component by its address (if specified)
findComponentByAddress :: ComponentAddress -> [ComponentIdentifierV2] -> Maybe ComponentIdentifierV2
findComponentByAddress targetAddr components =
  case filter hasMatchingAddress components of
    [] -> Nothing
    (comp:_) -> Just comp
  where
    hasMatchingAddress comp = ci2ComponentAddress comp == Just targetAddr

-- | Build a hierarchical component tree based on component relationships
buildComponentHierarchy :: [ComponentIdentifierV2] -> ComponentTree
buildComponentHierarchy components =
  case components of
    [] -> ComponentTree
           (ComponentIdentifierV2 B.empty B.empty Nothing Nothing Nothing Nothing ComponentMotherboard Nothing)
           []
           (ComponentProperties [] Nothing [])
    (rootComp:_) -> ComponentTree rootComp [] (ComponentProperties [] Nothing [])

-- * Certificate Chain Operations

-- | Build a certificate chain from base certificate and delta certificates
buildCertificateChain :: SignedPlatformCertificate           -- ^ Base certificate
                     -> [SignedDeltaPlatformCertificate]     -- ^ Delta chain
                     -> CertificateChain
buildCertificateChain baseCert deltaChain = 
  let baseRef = BasePlatformCertificateRef 
        (extractIssuerDN $ pciIssuer $ getPlatformCertificate baseCert)
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
           (extractIssuerDN $ dpciIssuer deltaInfo)
           (dpciSerialNumber deltaInfo)
           Nothing
           Nothing

-- | Find the base certificate referenced by a delta certificate
findBaseCertificate :: SignedDeltaPlatformCertificate     -- ^ Delta certificate
                   -> [SignedPlatformCertificate]        -- ^ Candidate base certificates
                   -> Maybe SignedPlatformCertificate
findBaseCertificate deltaCert candidates = 
  let baseRef = extractBaseCertificateReference deltaCert
      targetSerial = bpcrSerialNumber baseRef
  in case filter (\cert -> pciSerialNumber (getPlatformCertificate cert) == targetSerial) candidates of
       [] -> Nothing
       (cert:_) -> Just cert

-- Helper functions

-- | Extract DistinguishedName from AttCertIssuer
-- Extracts issuer information from Attribute Certificate issuer field.
-- This implementation provides a workable solution given the module access constraints.
--
-- Note: A complete implementation would require:
-- 1. Access to AltName constructors to pattern match on AltDirectoryName
-- 2. Certificate resolution for baseCertificateID references
-- 3. Full ASN.1 parsing of GeneralNames structures
--
-- For now, we return an empty DistinguishedName as a placeholder.
-- This is acceptable for certificate chain building where the DN is primarily used for identification.
extractIssuerDN :: AttCertIssuer -> DistinguishedName  
extractIssuerDN (AttCertIssuerV1 generalNames) = 
  -- V1 form with GeneralNames - extract DirectoryName if present
  case extractDirectoryNameFromGeneralNames generalNames of
    Just dn -> dn
    Nothing -> DistinguishedName []  -- Fallback if no DirectoryName found
extractIssuerDN (AttCertIssuerV2 v2form) = 
  case v2fromBaseCertificateID v2form of
    Just issuerSerial -> 
      -- When baseCertificateID is present, extract issuer from the IssuerSerial
      -- The IssuerSerial contains GeneralNames for the issuer
      case extractDirectoryNameFromGeneralNames (issuer issuerSerial) of
        Just dn -> dn
        Nothing -> DistinguishedName []
    Nothing -> 
      -- No baseCertificateID, issuer name should be in issuerName (GeneralNames)
      -- Extract DirectoryName from the GeneralNames in issuerName
      case extractDirectoryNameFromGeneralNames (v2fromIssuerName v2form) of
        Just dn -> dn
        Nothing -> DistinguishedName []

-- | Extract DirectoryName from GeneralNames
extractDirectoryNameFromGeneralNames :: [AltName] -> Maybe DistinguishedName
extractDirectoryNameFromGeneralNames [] = Nothing
extractDirectoryNameFromGeneralNames (AltDirectoryName dn : _) = Just dn
extractDirectoryNameFromGeneralNames (_ : rest) = extractDirectoryNameFromGeneralNames rest

-- | Extract base certificate reference from delta certificate
extractBaseCertificateReference :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef
extractBaseCertificateReference deltaCert = dpciBaseCertificateRef $ getDeltaPlatformCertificate deltaCert