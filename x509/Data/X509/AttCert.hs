{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}

-- |
-- Module      : Data.X509.AttCert
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Internal X.509 Attribute Certificate data structures and ASN.1 processing.
--
-- This module contains the core data types and ASN.1 parsing/encoding logic
-- for Attribute Certificates as defined in RFC 5755. These are low-level
-- building blocks used by the higher-level "Data.X509AC" module.
module Data.X509.AttCert where

import Control.Monad (when)
import Data.ASN1.BitArray
import Data.ASN1.Parse
import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Hourglass (DateTime)
import Data.Maybe (isJust)
import Data.X509.AlgorithmIdentifier
import Data.X509.Attribute
import Data.X509.DistinguishedName (DistinguishedName (..))
import Data.X509.Ext (AltName (..))
import Data.X509.ExtensionRaw
import Data.X509.Internal (asn1Container)

type GeneralNames = [AltName]

-- | AttributeCertificateInfo as defined in RFC 5755 section 4.1
data AttributeCertificateInfo = AttributeCertificateInfo
  { aciVersion :: Int, -- AttCertVersion, MUST be 1 for v2
    aciHolder :: Holder,
    aciIssuer :: AttCertIssuer,
    aciSignature :: SignatureALG,
    aciSerialNumber :: Integer, -- CertificateSerialNumber
    aciValidity :: AttCertValidityPeriod,
    aciAttributes :: Attributes,
    aciIssuerUniqueID :: Maybe UniqueID,
    aciExtensions :: Extensions
  }
  deriving (Show, Eq)

-- | Holder as defined in RFC 5755 section 4.1
data Holder
  = HolderBaseCertificateID IssuerSerial
  | HolderEntityName GeneralNames
  | HolderObjectDigestInfo ObjectDigestInfo
  deriving (Show, Eq)

-- | AttCertIssuer as defined in RFC 5755 section 4.1
data AttCertIssuer
  = AttCertIssuerV1 GeneralNames -- v1Form, MUST NOT be used in this profile
  | AttCertIssuerV2 V2Form
  deriving (Show, Eq)

-- | V2Form for AttCertIssuer
data V2Form = V2Form
  { v2fromIssuerName :: GeneralNames,
    v2fromBaseCertificateID :: Maybe IssuerSerial,
    v2fromObjectDigestInfo :: Maybe ObjectDigestInfo
  }
  deriving (Show, Eq)

-- | IssuerSerial from RFC 5755
data IssuerSerial = IssuerSerial
  { issuer :: GeneralNames,
    serial :: Integer, -- CertificateSerialNumber
    issuerUID :: Maybe UniqueID
  }
  deriving (Show, Eq)

-- | ObjectDigestInfo as defined in RFC 5755 section 4.1
data ObjectDigestInfo = ObjectDigestInfo
  { odiObjectType :: DigestedObjectType,
    odiOtherObjectTypeID :: Maybe OID,
    odiDigestAlgorithm :: SignatureALG,
    odiObjectDigest :: B.ByteString
  }
  deriving (Show, Eq)

-- | DigestedObjectType from RFC 5755
data DigestedObjectType
  = OIDPublicKey
  | OIDPublicKeyCert
  | OIDOtherObjectTypes
  deriving (Show, Eq, Enum)

-- | AttCertValidityPeriod from RFC 5755
data AttCertValidityPeriod = AttCertValidityPeriod
  { acNotBefore :: DateTime,
    acNotAfter :: DateTime
  }
  deriving (Show, Eq)

-- | UniqueID from X.509
type UniqueID = BitArray

instance ASN1Object AttCertValidityPeriod where
  toASN1 (AttCertValidityPeriod notBefore notAfter) xs =
    [Start Sequence, ASN1Time TimeUTC notBefore Nothing, ASN1Time TimeUTC notAfter Nothing, End Sequence] ++ xs
  fromASN1 (Start Sequence : ASN1Time TimeUTC nb Nothing : ASN1Time TimeUTC na Nothing : End Sequence : rest) =
    Right (AttCertValidityPeriod nb na, rest)
  fromASN1 _ = Left "AttCertValidityPeriod: unexpected format"

parseIssuerSerial :: ParseASN1 IssuerSerial
parseIssuerSerial = onNextContainer Sequence $ do
  gns <- parseGeneralNames
  s <-
    getNext >>= \case
      IntVal i -> return i
      _ -> throwParseError "invalid serial number"
  uid <- getNextMaybe $ \case
    BitString bs -> Just bs
    _ -> Nothing
  return $ IssuerSerial gns s uid

parseObjectDigestInfo :: ParseASN1 ObjectDigestInfo
parseObjectDigestInfo = onNextContainer Sequence $ do
  dot <-
    getNext >>= \case
      IntVal i ->
        if i >= 0 && i <= 2
          then return $ toEnum (fromIntegral i)
          else throwParseError "ObjectDigestInfo: invalid digestedObjectType enum"
      _ -> throwParseError "ObjectDigestInfo: expected IntVal for digestedObjectType"

  moid <- getNextMaybe $ \case
    OID oid -> Just oid
    _ -> Nothing

  alg <- getObject
  digestBs <-
    getNext >>= \case
      BitString bs -> return $ bitArrayGetData bs
      _ -> throwParseError "ObjectDigestInfo: expected BitString for objectDigest"

  case (dot, moid) of
    (OIDOtherObjectTypes, Nothing) -> throwParseError "ObjectDigestInfo: otherObjectTypeID must be present for otherObjectTypes"
    (OIDOtherObjectTypes, Just _) -> return ()
    (OIDPublicKey, Just _) -> throwParseError "ObjectDigestInfo: otherObjectTypeID must be absent for publicKey"
    (OIDPublicKeyCert, Just _) -> throwParseError "ObjectDigestInfo: otherObjectTypeID must be absent for publicKeyCert"
    (_, Nothing) -> return ()

  return $ ObjectDigestInfo dot moid alg digestBs

parseV2Form :: ParseASN1 V2Form
parseV2Form = onNextContainer Sequence $ do
  issuerName <- parseGeneralNames
  case issuerName of
    [AltDirectoryName (DistinguishedName dn)] ->
      when (null dn) $
        throwParseError "V2Form: issuerName's directoryName MUST NOT be empty"
    [_] -> throwParseError "V2Form: issuerName MUST contain a directoryName"
    _ -> throwParseError "V2Form: issuerName MUST contain one and only one GeneralName"

  baseCertID <- onNextContainerMaybe (Container Context 0) parseIssuerSerial
  when (isJust baseCertID) $
    throwParseError "V2Form: baseCertificateID MUST be omitted"

  objDigestInfo <- onNextContainerMaybe (Container Context 1) parseObjectDigestInfo
  when (isJust objDigestInfo) $
    throwParseError "V2Form: objectDigestInfo MUST be omitted"

  return $ V2Form issuerName baseCertID objDigestInfo

parseHolder :: ParseASN1 Holder
parseHolder = do
  mBaseCertID <- onNextContainerMaybe (Container Context 0) parseIssuerSerial
  mEntityName <- onNextContainerMaybe (Container Context 1) parseGeneralNames
  mObjectDigestInfo <- onNextContainerMaybe (Container Context 2) parseObjectDigestInfo

  case (mBaseCertID, mEntityName, mObjectDigestInfo) of
    (Just is, Nothing, Nothing) -> return $ HolderBaseCertificateID is
    (Nothing, Just gn, Nothing) -> return $ HolderEntityName gn
    (Nothing, Nothing, Just odi) -> return $ HolderObjectDigestInfo odi
    (Nothing, Nothing, Nothing) -> throwParseError "Holder: one of baseCertificateID, entityName, or objectDigestInfo must be present"
    _ -> throwParseError "Holder: only one of baseCertificateID, entityName, or objectDigestInfo must be used"

parseAttCertIssuer :: ParseASN1 AttCertIssuer
parseAttCertIssuer = do
  mV2Form <- onNextContainerMaybe (Container Context 0) parseV2Form
  case mV2Form of
    Just v2 -> return $ AttCertIssuerV2 v2
    Nothing -> do
      mGeneralNames <- onNextContainerMaybe Sequence parseGeneralNames
      case mGeneralNames of
        Just gn -> return $ AttCertIssuerV1 gn
        Nothing -> throwParseError "AttCertIssuer: unknown choice"

parseAttributeCertificateInfo :: ParseASN1 AttributeCertificateInfo
parseAttributeCertificateInfo = onNextContainer Sequence $ do
  ver <-
    getNext >>= \case
      IntVal 1 -> return 1
      IntVal v -> throwParseError ("AttributeCertificateInfo: unexpected version " ++ show v)
      _ -> throwParseError "AttributeCertificateInfo: expecting version"
  holder <- getObject
  acIssuer <- getObject
  sig <- getObject
  sn <-
    getNext >>= \case
      IntVal i -> do
        when (i <= 0) $ throwParseError "AttributeCertificateInfo: serialNumber MUST be positive"
        return i
      _ -> throwParseError "AttributeCertificateInfo: expecting serial number"
  validity <- getObject
  attrs <- getObject
  uid <- getNextMaybe $ \case
    BitString bs -> Just bs
    _ -> Nothing
  AttributeCertificateInfo ver holder acIssuer sig sn validity attrs uid <$> getObject

instance ASN1Object IssuerSerial where
  toASN1 (IssuerSerial issuer' serial' issuerUID') xs =
    [Start Sequence]
      ++ encodeGeneralNames issuer'
      ++ [IntVal serial']
      ++ maybe [] (\uid -> [BitString uid]) issuerUID'
      ++ [End Sequence]
      ++ xs
  fromASN1 = runParseASN1State parseIssuerSerial

instance ASN1Object ObjectDigestInfo where
  toASN1 (ObjectDigestInfo objType otherObjType alg objDigest) xs =
    [Start Sequence]
      ++ [IntVal $ fromIntegral $ fromEnum objType]
      ++ maybe [] (\oid -> [OID oid]) otherObjType
      ++ toASN1 alg []
      ++ [BitString $ toBitArray objDigest 0]
      ++ [End Sequence]
      ++ xs
  fromASN1 = runParseASN1State parseObjectDigestInfo

instance ASN1Object V2Form where
  toASN1 (V2Form issuerName baseCertID objDigestInfo) xs =
    [Start Sequence]
      ++ encodeGeneralNames issuerName
      ++ maybe [] (\x -> asn1Container (Container Context 0) (toASN1 x [])) baseCertID
      ++ maybe [] (\x -> asn1Container (Container Context 1) (toASN1 x [])) objDigestInfo
      ++ [End Sequence]
      ++ xs
  fromASN1 = runParseASN1State parseV2Form

instance ASN1Object Holder where
  toASN1 (HolderBaseCertificateID issuerSerial) xs = asn1Container (Container Context 0) (toASN1 issuerSerial []) ++ xs
  toASN1 (HolderEntityName generalNames) xs = asn1Container (Container Context 1) (encodeGeneralNames generalNames) ++ xs
  toASN1 (HolderObjectDigestInfo objDigestInfo) xs = asn1Container (Container Context 2) (toASN1 objDigestInfo []) ++ xs
  fromASN1 = runParseASN1State parseHolder

instance ASN1Object AttCertIssuer where
  toASN1 (AttCertIssuerV1 generalNames) xs = encodeGeneralNames generalNames ++ xs
  toASN1 (AttCertIssuerV2 v2Form) xs = asn1Container (Container Context 0) (toASN1 v2Form []) ++ xs
  fromASN1 = runParseASN1State parseAttCertIssuer

instance ASN1Object AttributeCertificateInfo where
  toASN1 (AttributeCertificateInfo acVer acHolder acIssuer acSig acSn acValid acAttrs acUid acExts) xs =
    ( [Start Sequence]
        ++ [IntVal $ fromIntegral acVer]
        ++ toASN1 acHolder []
        ++ toASN1 acIssuer []
        ++ toASN1 acSig []
        ++ [IntVal acSn]
        ++ toASN1 acValid []
        ++ toASN1 acAttrs []
        ++ maybe [] (\u -> [BitString u]) acUid
        ++ toASN1 acExts []
        ++ [End Sequence]
    )
      ++ xs
  fromASN1 = runParseASN1State parseAttributeCertificateInfo