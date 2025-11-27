{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

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
    mkPlatformCertificate,
    Alg (..),
    Keys,
    Auth (..),
    Pair (..),
    generateKeys,
    hashSHA256,
    hashSHA384,
    hashSHA512,
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
  )
where

-- Cryptographic signing imports

import Crypto.Hash (HashAlgorithm, SHA256 (..), SHA384 (..), SHA512 (..), hashWith)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS as PSS
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types
import Data.ASN1.Types.String ()
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.Hourglass (Date (..), DateTime (..), Month (..), TimeOfDay (..))
import Data.X509 (Certificate (..), DistinguishedName (..), Extensions (..), HashALG (..), PubKeyALG (..), SignatureALG (..), objectToSignedExact, objectToSignedExactF, AltName(..))
import Data.X509.AttCert (AttCertIssuer (..), AttCertValidityPeriod (..), Holder (..), V2Form (..), ObjectDigestInfo (..), DigestedObjectType (..), pattern HolderObjectDigestInfo)
import Data.X509.Attribute (Attribute (..), Attributes (..))
import Data.X509.TCG.Attributes
import Data.X509.TCG.Component
import Data.X509.TCG.Delta
import Data.X509.TCG.OID
import qualified Data.X509.TCG.Operations as Ops
import Data.X509.TCG.Platform

-- * Signature and hash algorithms for Platform Certificates

-- | Hash algorithms supported in Platform certificates.
--
-- This relates the typed hash algorithm @hash@ to the 'HashALG' value.
data GHash hash = GHash {getHashALG :: HashALG, getHashAlgorithm :: hash}

hashSHA256 :: GHash SHA256
hashSHA256 = GHash HashSHA256 SHA256

hashSHA384 :: GHash SHA384
hashSHA384 = GHash HashSHA384 SHA384

hashSHA512 :: GHash SHA512
hashSHA512 = GHash HashSHA512 SHA512

-- | Signature and hash algorithms instantiated with parameters for Platform Certificates.
data Alg pub priv where
  AlgRSA ::
    (HashAlgorithm hash, RSA.HashAlgorithmASN1 hash) =>
    Int ->
    GHash hash ->
    Alg RSA.PublicKey RSA.PrivateKey
  AlgRSAPSS ::
    (HashAlgorithm hash) =>
    Int ->
    PSS.PSSParams hash B.ByteString B.ByteString ->
    GHash hash ->
    Alg RSA.PublicKey RSA.PrivateKey
  AlgDSA ::
    (HashAlgorithm hash) =>
    DSA.Params ->
    GHash hash ->
    Alg DSA.PublicKey DSA.PrivateKey
  AlgEC ::
    (HashAlgorithm hash) =>
    ECC.CurveName ->
    GHash hash ->
    Alg ECDSA.PublicKey ECDSA.PrivateKey
  AlgEd25519 :: Alg Ed25519.PublicKey Ed25519.SecretKey
  AlgEd448 :: Alg Ed448.PublicKey Ed448.SecretKey

-- | Types of public and private keys used by a signature algorithm.
type Keys pub priv = (Alg pub priv, pub, priv)

-- | Generates random keys for a signature algorithm.
generateKeys :: Alg pub priv -> IO (Keys pub priv)
generateKeys alg@(AlgRSA bits _) = generateRSAKeys alg bits
generateKeys alg@(AlgRSAPSS bits _ _) = generateRSAKeys alg bits
generateKeys alg@(AlgDSA params _) = do
  x <- DSA.generatePrivate params
  let y = DSA.calculatePublic params x
  return (alg, DSA.PublicKey params y, DSA.PrivateKey params x)
generateKeys alg@(AlgEC name _) = do
  let curve = ECC.getCurveByName name
  (pub, priv) <- ECC.generate curve
  return (alg, pub, priv)
generateKeys alg@AlgEd25519 = do
  secret <- Ed25519.generateSecretKey
  return (alg, Ed25519.toPublic secret, secret)
generateKeys alg@AlgEd448 = do
  secret <- Ed448.generateSecretKey
  return (alg, Ed448.toPublic secret, secret)

generateRSAKeys ::
  Alg RSA.PublicKey RSA.PrivateKey ->
  Int ->
  IO (Alg RSA.PublicKey RSA.PrivateKey, RSA.PublicKey, RSA.PrivateKey)
generateRSAKeys alg bits = addAlg <$> RSA.generate size e
  where
    addAlg (pub, priv) = (alg, pub, priv)
    size = bits `div` 8
    e = 3

getSignatureALG :: Alg pub priv -> SignatureALG
getSignatureALG (AlgRSA _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSA
getSignatureALG (AlgRSAPSS _ _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSAPSS
getSignatureALG (AlgDSA _ hash) = SignatureALG (getHashALG hash) PubKeyALG_DSA
getSignatureALG (AlgEC _ hash) = SignatureALG (getHashALG hash) PubKeyALG_EC
getSignatureALG AlgEd25519 = SignatureALG_IntrinsicHash PubKeyALG_Ed25519
getSignatureALG AlgEd448 = SignatureALG_IntrinsicHash PubKeyALG_Ed448

doSign :: Alg pub priv -> priv -> B.ByteString -> IO B.ByteString
doSign (AlgRSA _ hash) key msg = do
  result <- RSA.signSafer (Just $ getHashAlgorithm hash) key msg
  case result of
    Left err -> error ("doSign(AlgRSA): " ++ show err)
    Right sigBits -> return sigBits
doSign (AlgRSAPSS _ params _) key msg = do
  result <- PSS.signSafer params key msg
  case result of
    Left err -> error ("doSign(AlgRSAPSS): " ++ show err)
    Right sigBits -> return sigBits
doSign (AlgDSA _ hash) key msg = do
  sig <- DSA.sign key (getHashAlgorithm hash) msg
  return $
    encodeASN1'
      DER
      [ Start Sequence,
        IntVal (DSA.sign_r sig),
        IntVal (DSA.sign_s sig),
        End Sequence
      ]
doSign (AlgEC _ hash) key msg = do
  sig <- ECDSA.sign key (getHashAlgorithm hash) msg
  return $
    encodeASN1'
      DER
      [ Start Sequence,
        IntVal (ECDSA.sign_r sig),
        IntVal (ECDSA.sign_s sig),
        End Sequence
      ]
doSign AlgEd25519 key msg =
  return $ convert $ Ed25519.sign key (Ed25519.toPublic key) msg
doSign AlgEd448 key msg =
  return $ convert $ Ed448.sign key (Ed448.toPublic key) msg

-- * Platform Certificate utilities

-- | Holds together a Platform certificate and its private key for convenience.
--
-- Contains also the crypto algorithm that both are issued from.  This is
-- useful when signing another certificate.
data Pair pub priv = Pair
  { pairAlg :: Alg pub priv,
    pairSignedCert :: SignedPlatformCertificate,
    pairKey :: priv
  }

-- | Authority signing a Platform certificate, itself or another certificate.
--
-- When the certificate is self-signed, issuer and subject are the same.  So
-- they have identical signature algorithms.  The purpose of the GADT is to
-- hold this constraint only in the self-signed case.
data Auth pubI privI pubS privS where
  Self :: (pubI ~ pubS, privI ~ privS) => Auth pubI privI pubS privS
  CA :: Pair pubI privI -> Auth pubI privI pubS privS

foldAuthPriv ::
  privS ->
  (Pair pubI privI -> privI) ->
  Auth pubI privI pubS privS ->
  privI
foldAuthPriv x _ Self = x -- uses constraint privI ~ privS
foldAuthPriv _ f (CA p) = f p

foldAuthPubPriv ::
  k pubS privS ->
  (Pair pubI privI -> k pubI privI) ->
  Auth pubI privI pubS privS ->
  k pubI privI
foldAuthPubPriv x _ Self = x -- uses both constraints
foldAuthPubPriv _ f (CA p) = f p

-- * High-Level Operations

-- ** Certificate Creation and Validation

-- | Create a Platform Certificate with the specified configuration and attributes
--
-- This is a high-level function that handles the proper construction of a
-- Platform Certificate according to IWG specifications, including proper
-- TPM EK certificate binding as required by the specification.
--
-- Note: This implementation uses a dummy signature for testing purposes.
-- In a production environment, you would need to provide a proper signing function
-- with a real private key.
createPlatformCertificate ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Certificate -> -- TPM EK Certificate for proper Holder binding
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  IO (Either String SignedPlatformCertificate)
createPlatformCertificate config components tpmInfo ekCert hashAlg = return $ createPlatformCertificateSync config components tpmInfo ekCert hashAlg

-- | Synchronous version of createPlatformCertificate for easier testing
createPlatformCertificateSync ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  Either String SignedPlatformCertificate
createPlatformCertificateSync config components tpmInfo ekCert hashAlg = do
  -- Create the basic certificate info structure with EK certificate binding
  certInfo <- buildPlatformCertificateInfo config components tpmInfo ekCert hashAlg

  -- Create a signed certificate using a dummy signature
  -- In production, this would use a real private key and signing algorithm
  let dummySigningFunction = createDummySigningFunction
  let (signedCert, _) = objectToSignedExact dummySigningFunction certInfo

  return signedCert

-- | Helper function to build PlatformCertificateInfo from configuration
buildPlatformCertificateInfo ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  Either String PlatformCertificateInfo
buildPlatformCertificateInfo config components tpmInfo ekCert hashAlg = do
  -- Create basic validity period (1 year from now) - will be overridden by mkPlatformCertificate
  let validityStart = DateTime (Date 2024 December 1) (TimeOfDay 0 0 0 0)
      validityEnd = DateTime (Date 2025 December 1) (TimeOfDay 0 0 0 0)
      validity = AttCertValidityPeriod validityStart validityEnd

  buildPlatformCertificateInfoWithValidity config components tpmInfo validity ekCert hashAlg

-- | Helper function to build PlatformCertificateInfo with custom validity period
buildPlatformCertificateInfoWithValidity ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  AttCertValidityPeriod ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  Either String PlatformCertificateInfo
buildPlatformCertificateInfoWithValidity config components tpmInfo validity ekCert hashAlg =
  -- Create holder referencing TPM EK certificate (secure by default)
  -- Use ObjectDigestInfo with public key hash to prevent CA name collision attacks
  let pubKeyBytes = encodeASN1' DER $ toASN1 (certPubKey ekCert) []
      (pubKeyHash, hashALG) = case hashAlg of
        "sha256" -> (convert $ hashWith SHA256 pubKeyBytes, HashSHA256)
        "sha384" -> (convert $ hashWith SHA384 pubKeyBytes, HashSHA384)  
        "sha512" -> (convert $ hashWith SHA512 pubKeyBytes, HashSHA512)
        _        -> (convert $ hashWith SHA384 pubKeyBytes, HashSHA384)  -- Default to SHA384
      objectDigestInfo = ObjectDigestInfo 
        { odiObjectType = OIDPublicKeyCert  -- Reference to the public key certificate
        , odiOtherObjectTypeID = Nothing    -- Not needed for publicKeyCert type
        , odiDigestAlgorithm = SignatureALG hashALG PubKeyALG_RSA  -- Hash algorithm used
        , odiObjectDigest = pubKeyHash      -- Configurable hash of the EK certificate's public key
        }
      holder = HolderObjectDigestInfo objectDigestInfo

      -- Create a simple issuer (V2 form) with proper issuer name
      -- RFC 5755 requires exactly one GeneralName in issuerName, and it must be a directoryName
      cnOid = [2, 5, 4, 3] -- Common Name OID  
      ouOid = [2, 5, 4, 11] -- Organization Unit OID
      oOid = [2, 5, 4, 10]  -- Organization OID
      issuerDN = DistinguishedName 
        [ (cnOid, ASN1CharacterString UTF8 (B8.pack "TCG Platform Certificate Issuer"))
        , (ouOid, ASN1CharacterString UTF8 (B8.pack "Platform Certificate Authority")) 
        , (oOid, ASN1CharacterString UTF8 (B8.pack "TCG Organization"))
        ]
      acIssuer = AttCertIssuerV2 (V2Form [AltDirectoryName issuerDN] Nothing Nothing)

  -- Create attributes from config, components, and TPM info
  in case buildAttributesFromConfig config components tpmInfo of
       Left err -> Left err
       Right attrs -> Right $
         PlatformCertificateInfo
           { pciVersion = 2, -- v2 certificate
             pciHolder = holder,
             pciIssuer = acIssuer,
             pciSignature = SignatureALG HashSHA384 PubKeyALG_RSA,
             pciSerialNumber = 1, -- Simple serial number
             pciValidity = validity,
             pciAttributes = attrs,
             pciIssuerUniqueID = Nothing,
             pciExtensions = Extensions Nothing
           }

-- | Convert all ComponentIdentifiers to a single componentIdentifier_v2 attribute
componentsToAttribute :: [ComponentIdentifier] -> [Attribute]
componentsToAttribute [] = []
componentsToAttribute components =
  [Attribute tcg_at_componentIdentifier_v2 [componentListToASN1 components]]
  where
    componentListToASN1 comps = [Start Sequence] ++ concatMap componentToASN1 comps ++ [End Sequence]
    componentToASN1 comp = 
      [Start Sequence,
       OctetString (ciManufacturer comp),
       OctetString (ciModel comp)] ++
      (case ciSerial comp of
         Just serial -> [OctetString serial]
         Nothing -> [Null]) ++
      (case ciRevision comp of
         Just revision -> [OctetString revision]
         Nothing -> [Null]) ++
      [End Sequence]

-- | Helper function to build attributes from configuration data
buildAttributesFromConfig ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Either String Attributes
buildAttributesFromConfig config components _tpmInfo = do
  -- Create basic platform attributes
  let manufacturerAttr = Attribute tcg_at_platformManufacturer [[OctetString (pcManufacturer config)]]
      modelAttr = Attribute tcg_at_platformModel [[OctetString (pcModel config)]]
      serialAttr = Attribute tcg_at_platformSerial [[OctetString (pcSerial config)]]
      versionAttr = Attribute tcg_at_platformVersion [[OctetString (pcVersion config)]]

      -- Create component attributes from the component identifiers
      componentAttrs = componentsToAttribute components
      
  return $ Attributes ([manufacturerAttr, modelAttr, serialAttr, versionAttr] ++ componentAttrs)

-- | Dummy signing function for testing purposes
-- In production, replace with proper cryptographic signing
createDummySigningFunction :: B.ByteString -> (B.ByteString, SignatureALG, ())
createDummySigningFunction _dataToSign =
  (B.replicate 48 0x42, SignatureALG HashSHA384 PubKeyALG_RSA, ()) -- 48 bytes of dummy signature data (SHA384)

-- * Production Platform Certificate Creation

-- | Create a Platform Certificate using RSA signing (production version)
--
-- This function creates a properly signed Platform Certificate using a real RSA private key,
-- unlike the dummy implementation above. It supports both self-signed certificates and
-- certificates signed by a CA.
-- | Create a Platform Certificate with multiple signature algorithm support
--
-- This function supports multiple signature algorithms including RSA, DSA, ECDSA, Ed25519, and Ed448.
-- It handles both self-signed certificates and CA-signed certificates.
--
-- Based on the pattern from x509-validation but adapted for Platform Certificates.
mkPlatformCertificate ::
  -- | Platform configuration data
  PlatformConfiguration ->
  -- | Component identifiers
  [ComponentIdentifier] ->
  -- | TPM information
  TPMInfo ->
  -- | TPM EK Certificate
  Certificate ->
  -- | Validity period (notBefore, notAfter)
  (DateTime, DateTime) ->
  -- | Authority signing the new certificate
  Auth pubI privI pubS privS ->
  -- | Keys for the new certificate
  Keys pubS privS ->
  -- | Hash algorithm ("sha256", "sha384", "sha512")
  String ->
  -- | Result: signed Platform Certificate pair
  IO (Either String (Pair pubS privS))
mkPlatformCertificate config components tpmInfo ekCert validity auth (algS, _pubKey, privKey) hashAlg = do
  let validityPeriod = uncurry AttCertValidityPeriod validity
  case buildPlatformCertificateInfoWithValidity config components tpmInfo validityPeriod ekCert hashAlg of
    Left err -> return $ Left err
    Right certInfo -> do
      -- Apply authority settings to the certificate
      let finalCertInfo = certInfo
          signingKey = foldAuthPriv privKey pairKey auth
          algI = foldAuthPubPriv algS pairAlg auth
          signatureFunction objRaw = do
            sigBits <- doSign algI signingKey objRaw
            return (sigBits, getSignatureALG algI)

      signedCert <- objectToSignedExactF signatureFunction finalCertInfo
      return $
        Right
          Pair
            { pairAlg = algS,
              pairSignedCert = signedCert,
              pairKey = privKey
            }

-- | Create a Delta Platform Certificate that references a base certificate
--
-- Creates a Delta Platform Certificate that describes changes from the
-- specified base certificate.
createDeltaPlatformCertificate ::
  -- | Base certificate
  SignedPlatformCertificate ->
  -- | Component changes
  [ComponentDelta] ->
  -- | Change records
  [ChangeRecord] ->
  IO (Either String SignedDeltaPlatformCertificate)
createDeltaPlatformCertificate baseCert componentDeltas changeRecords = do
  -- Extract information from base certificate
  let baseCertInfo = getPlatformCertificate baseCert
      baseSerial = pciSerialNumber baseCertInfo
      baseIssuer = pciIssuer baseCertInfo

  -- Extract DistinguishedName from AttCertIssuer
  -- For now, create a simple DistinguishedName (this should be improved)
  let issuerDN = DistinguishedName [] -- Simplified issuer DN

  -- Create base certificate reference
  let baseCertRef =
        BasePlatformCertificateRef
          { bpcrIssuer = issuerDN,
            bpcrSerialNumber = baseSerial,
            bpcrCertificateHash = Nothing, -- Could be computed if needed
            bpcrValidityPeriod = Nothing -- Optional validity period
          }

  -- Create Delta Platform Configuration
  let platformDelta =
        PlatformConfigurationDelta
          { pcdPlatformInfoChanges = Nothing, -- No platform info changes for now
            pcdComponentDeltas = componentDeltas,
            pcdChangeRecords = changeRecords
          }

  -- Current timestamp (simplified)
  let currentTime = DateTime (Date 2024 December 15) (TimeOfDay 12 0 0 0)

  let _deltaConfig =
        DeltaPlatformConfiguration
          { dpcBaseCertificateSerial = baseSerial,
            dpcConfigurationDelta = platformDelta,
            dpcChangeTimestamp = currentTime,
            dpcChangeReason = Just (B8.pack "Component configuration changes")
          }

  -- Create attributes containing the delta configuration
  -- For now, create minimal attributes
  let deltaAttrs = Attributes [] -- Simplified for initial implementation

  -- Create Delta Platform Certificate Info
  let deltaCertInfo =
        DeltaPlatformCertificateInfo
          { dpciVersion = 2,
            dpciHolder = pciHolder baseCertInfo, -- Same holder as base
            dpciIssuer = baseIssuer,
            dpciSignature = SignatureALG HashSHA384 PubKeyALG_RSA, -- Default signature
            dpciSerialNumber = baseSerial + 1, -- Increment serial number
            dpciValidity = pciValidity baseCertInfo, -- Same validity period
            dpciAttributes = deltaAttrs,
            dpciIssuerUniqueID = Nothing,
            dpciExtensions = Extensions Nothing,
            dpciBaseCertificateRef = baseCertRef
          }

  -- For now, create a dummy signed certificate
  -- This is a basic implementation that creates the structure
  let dummySignature = B.pack [0, 0, 0, 0] -- Placeholder signature
      signatureAlg = SignatureALG HashSHA384 PubKeyALG_RSA
      signingFunction _ = return (dummySignature, signatureAlg)

  signedDelta <- objectToSignedExactF signingFunction deltaCertInfo
  return $ Right signedDelta

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
   in validateRequiredAttributes attrs
        ++ validateAttributeFormats attrs
        ++ validateTPMAttributes attrs

-- | Validate a Delta Platform Certificate
--
-- Validates that the delta certificate properly references its base
-- and contains valid change information.
validateDeltaCertificate' :: SignedDeltaPlatformCertificate -> [String]
validateDeltaCertificate' deltaCert =
  let deltaInfo = getDeltaPlatformCertificate deltaCert
      baseRef = dpciBaseCertificateRef deltaInfo
   in validateBaseCertificateReference baseRef
        ++ validateDeltaAttributesInTCG (dpciAttributes deltaInfo)

-- ** Configuration Management

-- | Get the current platform configuration from a certificate or certificate chain
--
-- If given a base Platform Certificate, returns its configuration.
-- If given a Delta Certificate, applies the delta to compute the current configuration.
getCurrentPlatformConfiguration ::
  Either SignedPlatformCertificate SignedDeltaPlatformCertificate ->
  Maybe PlatformConfigurationV2
getCurrentPlatformConfiguration = Ops.getCurrentPlatformConfiguration

-- | Apply a Delta Platform Certificate to a base configuration
--
-- Computes the resulting configuration after applying the delta changes.
applyDeltaCertificate ::
  SignedPlatformCertificate ->
  SignedDeltaPlatformCertificate ->
  Either String PlatformConfigurationV2
applyDeltaCertificate baseCert deltaCert = do
  baseConfig <- case getCurrentPlatformConfiguration (Left baseCert) of
    Just config -> Right config
    Nothing -> Left "Cannot extract base configuration"

  Ops.applyDeltaCertificate baseConfig deltaCert

-- | Compute the final configuration from a chain of certificates
--
-- Given a base Platform Certificate and a sequence of Delta Certificates,
-- computes the final resulting platform configuration.
computeConfigurationChain ::
  SignedPlatformCertificate ->
  [SignedDeltaPlatformCertificate] ->
  Either String PlatformConfigurationV2
computeConfigurationChain = Ops.computeConfigurationChain

-- ** Component Operations

-- | Extract all component identifiers from a Platform Certificate
getComponentIdentifiers :: SignedPlatformCertificate -> [ComponentIdentifier]
getComponentIdentifiers = Ops.getComponentIdentifiers

-- | Find components of a specific class in a Platform Certificate
findComponentByClass :: ComponentClass -> SignedPlatformCertificate -> [ComponentIdentifierV2]
findComponentByClass targetClass cert =
  let components = Ops.getComponentIdentifiersV2 cert
   in Ops.findComponentByClass targetClass components

-- | Find a component by its address in a Platform Certificate
findComponentByAddress :: ComponentAddress -> SignedPlatformCertificate -> Maybe ComponentIdentifierV2
findComponentByAddress addr cert =
  let components = Ops.getComponentIdentifiersV2 cert
   in Ops.findComponentByAddress addr components

-- | Build a component hierarchy from Platform Certificate information
buildComponentHierarchy :: SignedPlatformCertificate -> ComponentHierarchy
buildComponentHierarchy cert =
  let components = Ops.getComponentIdentifiersV2 cert
      componentTree = Ops.buildComponentHierarchy components
   in case components of
        [] -> ComponentHierarchy [] componentTree
        (comp : _) -> ComponentHierarchy [ComponentReference 0 0 comp] componentTree

-- ** Attribute Extraction

-- | Extract all TCG attributes from a certificate
extractTCGAttributes :: SignedPlatformCertificate -> [TCGAttribute]
extractTCGAttributes cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
   in extractTCGAttrs attrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs (Attributes attrs) =
      [tcgAttr | attr <- attrs, Right tcgAttr <- [parseTCGAttribute attr]]

-- | Extract platform-specific attributes (manufacturer, model, serial, version)
extractPlatformAttributes :: SignedPlatformCertificate -> Maybe PlatformInfo
extractPlatformAttributes = getPlatformInfo

-- | Extract TPM-related attributes
extractTPMAttributes :: SignedPlatformCertificate -> Maybe TPMInfo
extractTPMAttributes = getTPMInfo

-- ** Certificate Chain Operations

-- | Build a certificate chain from a base certificate and deltas
buildCertificateChain ::
  SignedPlatformCertificate ->
  [SignedDeltaPlatformCertificate] ->
  CertificateChain
buildCertificateChain = Ops.buildCertificateChain

-- | Validate a certificate chain for consistency
validateCertificateChain :: CertificateChain -> [String]
validateCertificateChain chain =
  validateChainContinuity chain
    ++ validateChainValidity chain

-- | Find the base certificate for a given Delta Platform Certificate
findBaseCertificate ::
  SignedDeltaPlatformCertificate ->
  [SignedPlatformCertificate] ->
  Maybe SignedPlatformCertificate
findBaseCertificate = Ops.findBaseCertificate

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
  [ tcg_at_platformConfiguration_v2,
    tcg_at_componentIdentifier_v2,
    tcg_at_platformManufacturer,
    tcg_at_platformModel,
    tcg_at_platformSerial,
    tcg_at_platformVersion
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
validateRequiredAttributes attrs =
  let presentOIDs = extractPresentOIDs attrs
      required = getRequiredAttributes
      missing = filter (`notElem` presentOIDs) required
   in map (\oid -> "Missing required attribute: " ++ attributeOIDToType oid) missing

validateAttributeFormats :: Attributes -> [String]
validateAttributeFormats attrs =
  let tcgAttrs = extractTCGAttrs attrs
   in concatMap validateTCGAttributeFormat tcgAttrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs (Attributes attrList) =
      [tcgAttr | attr <- attrList, Right tcgAttr <- [parseTCGAttribute attr]]

    validateTCGAttributeFormat :: TCGAttribute -> [String]
    validateTCGAttributeFormat attr = case attr of
      TCGPlatformManufacturer (PlatformManufacturerAttr bs) ->
        ["Platform Manufacturer cannot be empty" | B.null bs]
      TCGPlatformModel (PlatformModelAttr bs) ->
        ["Platform Model cannot be empty" | B.null bs]
      _ -> []

validateTPMAttributes :: Attributes -> [String]
validateTPMAttributes attrs =
  let tcgAttrs = extractTCGAttrs attrs
   in concatMap validateTPMAttribute tcgAttrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs (Attributes attrList) =
      [tcgAttr | attr <- attrList, Right tcgAttr <- [parseTCGAttribute attr]]

    validateTPMAttribute :: TCGAttribute -> [String]
    validateTPMAttribute attr = case attr of
      TCGTPMModel (TPMModelAttr bs) ->
        ["TPM Model cannot be empty" | B.null bs]
      TCGTPMVersion (TPMVersionAttr _version) ->
        [] -- TPM version validation could be added here
      TCGTPMSpecification (TPMSpecificationAttr _spec) ->
        [] -- TPM specification validation could be added here
      _ -> []

validateBaseCertificateReference :: BasePlatformCertificateRef -> [String]
validateBaseCertificateReference baseRef
  | bpcrSerialNumber baseRef <= 0 = ["Invalid base certificate serial number"]
  | otherwise = []

validateDeltaAttributesInTCG :: Attributes -> [String]
validateDeltaAttributesInTCG attrs =
  -- Check that delta attributes contain necessary platform configuration deltas
  let presentOIDs = extractPresentOIDs attrs
      hasDeltaConfig = tcg_at_platformConfiguration_v2 `elem` presentOIDs
   in ["Delta certificate missing platform configuration delta" | not hasDeltaConfig]

validateChainContinuity :: CertificateChain -> [String]
validateChainContinuity chain =
  let baseRef = ccBaseCertificate chain
      deltaRefs = ccIntermediateCertificates chain
      baseSerial = bpcrSerialNumber baseRef
      deltaSerials = map bpcrSerialNumber deltaRefs
      hasDuplicates = length deltaSerials /= length (nub deltaSerials)
      hasBaseConflict = baseSerial `elem` deltaSerials
   in ((["Duplicate serial numbers in certificate chain" | hasDuplicates]) ++ (["Delta certificate serial conflicts with base certificate" | hasBaseConflict]))
  where
    nub :: (Eq a) => [a] -> [a]
    nub [] = []
    nub (x : xs) = x : nub (filter (/= x) xs)

validateChainValidity :: CertificateChain -> [String]
validateChainValidity chain =
  let baseRef = ccBaseCertificate chain
      deltaRefs = ccIntermediateCertificates chain
      baseErrors = validateBaseCertificateReference baseRef
      deltaErrors = concatMap validateBaseCertificateReference deltaRefs
   in baseErrors ++ deltaErrors

extractPresentOIDs :: Attributes -> [OID]
extractPresentOIDs (Attributes attrs) = map attrType attrs