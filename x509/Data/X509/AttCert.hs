{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}

module Data.X509.AttCert where

import Data.ASN1.BitArray
import Data.ASN1.Parse
import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Hourglass (DateTime)
import Data.X509.AlgorithmIdentifier
import Data.X509.Attribute (Attributes)
import Data.X509.Ext (AltName, encodeGeneralNames, parseGeneralNames)
import Data.X509.ExtensionRaw

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
-- | https://datatracker.ietf.org/doc/html/rfc5755#section-4.2.2
-- | this specification RECOMMENDS that only one of the options be used in any given AC.
-- | For any environment where the AC is passed in an authenticated
-- | message or session and where the authentication is based on the use
-- | of an X.509 PKC, the Holder field SHOULD use the baseCertificateID
data Holder
  = HolderBaseCertificateID IssuerSerial
  | HolderEntityName GeneralNames
  | HolderObjectDigestInfo ObjectDigestInfo
  deriving (Show, Eq)

-- | AttCertIssuer as defined in RFC 5755 section 4.1
-- | https://datatracker.ietf.org/doc/html/rfc5755#section-4.2.3
data AttCertIssuer
  = AttCertIssuerV1 GeneralNames -- v1Form, MUST NOT be used in this profile
  | AttCertIssuerV2 V2Form
  deriving (Show, Eq)

-- | V2Form for AttCertIssuer
-- | ACs conforming to this profile MUST use the v2Form choice, which MUST
-- | contain one and only one GeneralName in the issuerName, which MUST
-- | contain a non-empty distinguished name in the directoryName field.
-- | This means that all AC issuers MUST have non-empty distinguished
-- | names.  ACs conforming to this profile MUST omit the
-- | baseCertificateID and objectDigestInfo fields.
data V2Form = V2Form
  { v2fromIssuerName :: GeneralNames,
    v2fromBaseCertificateID :: Maybe IssuerSerial,
    v2fromObjectDigestInfo :: Maybe ObjectDigestInfo
  }
  deriving (Show, Eq)

-- | IssuerSerial from RFC 5755
-- | https://datatracker.ietf.org/doc/html/rfc5755#section-4.2.5
-- | he issuer/serialNumber pair MUST form a unique combination
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
-- | https://datatracker.ietf.org/doc/html/rfc5755#section-4.2.8
type UniqueID = BitArray

-- | A signature is just a bit string, as defined in X.509.
-- type Signature = BitArray
instance ASN1Object AttCertValidityPeriod where
  toASN1 (AttCertValidityPeriod notBefore notAfter) =
    ([Start Sequence, ASN1Time TimeUTC notBefore Nothing, ASN1Time TimeUTC notAfter Nothing, End Sequence] ++)
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
  baseCertID <- onNextContainerMaybe (Container Context 0) parseIssuerSerial
  objDigestInfo <- onNextContainerMaybe (Container Context 1) parseObjectDigestInfo
  return $ V2Form issuerName baseCertID objDigestInfo

parseHolder :: ParseASN1 Holder
parseHolder = do
  mBaseCertID <- onNextContainerMaybe (Container Context 0) parseIssuerSerial
  case mBaseCertID of
    Just is -> return $ HolderBaseCertificateID is
    Nothing -> do
      mEntityName <- onNextContainerMaybe (Container Context 1) parseGeneralNames
      case mEntityName of
        Just gn -> return $ HolderEntityName gn
        Nothing -> do
          mObjectDigestInfo <- onNextContainerMaybe (Container Context 2) parseObjectDigestInfo
          case mObjectDigestInfo of
            Just odi -> return $ HolderObjectDigestInfo odi
            Nothing -> throwParseError "Holder: unknown choice"

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
  holder <- parseHolder
  acIssuer <- parseAttCertIssuer
  sig <- getObject
  sn <-
    getNext >>= \case
      IntVal i -> return i
      _ -> throwParseError "AttributeCertificateInfo: expecting serial number"
  validity <- getObject
  attrs <- getObject
  uid <- getNextMaybe $ \case
    BitString bs -> Just bs
    _ -> Nothing
  AttributeCertificateInfo ver holder acIssuer sig sn validity attrs uid <$> getObject

encodeAttributeCertificateInfo :: AttributeCertificateInfo -> [ASN1]
encodeAttributeCertificateInfo attCert = undefined

instance ASN1Object IssuerSerial where
  toASN1 :: IssuerSerial -> ASN1S
  toASN1 (IssuerSerial issuer' serial' issuerUID') =
    ([Start Sequence] ++)
      . (encodeGeneralNames issuer' ++)
      . ([IntVal serial'] ++)
      . maybe id (\uid -> ([BitString uid] ++)) issuerUID'
      . ([End Sequence] ++)
  fromASN1 = runParseASN1State parseIssuerSerial

instance ASN1Object ObjectDigestInfo where
  toASN1 :: ObjectDigestInfo -> ASN1S
  toASN1 (ObjectDigestInfo objType otherObjType alg objDigest) =
    ([Start Sequence] ++)
      . ([IntVal $ fromIntegral $ fromEnum objType] ++)
      . maybe id (\oid -> ([OID oid] ++)) otherObjType
      . toASN1 alg
      . ([BitString $ toBitArray objDigest 0] ++)
      . ([End Sequence] ++)
  fromASN1 = runParseASN1State parseObjectDigestInfo

instance ASN1Object V2Form where
  toASN1 :: V2Form -> ASN1S
  toASN1 (V2Form issuerName baseCertID objDigestInfo) =
    ([Start Sequence] ++)
      . (encodeGeneralNames issuerName ++)
      . maybe id toASN1 baseCertID
      . maybe id toASN1 objDigestInfo
      . ([End Sequence] ++)
  fromASN1 = runParseASN1State parseV2Form

instance ASN1Object Holder where
  toASN1 :: Holder -> ASN1S
  toASN1 (HolderBaseCertificateID issuerSerial) = toASN1 issuerSerial
  toASN1 (HolderEntityName generalNames) = (encodeGeneralNames generalNames ++)
  toASN1 (HolderObjectDigestInfo objDigestInfo) = toASN1 objDigestInfo
  fromASN1 = runParseASN1State parseHolder

instance ASN1Object AttCertIssuer where
  toASN1 :: AttCertIssuer -> ASN1S
  toASN1 (AttCertIssuerV1 generalNames) = (encodeGeneralNames generalNames ++)
  toASN1 (AttCertIssuerV2 v2Form) = toASN1 v2Form
  fromASN1 = runParseASN1State parseAttCertIssuer

instance ASN1Object AttributeCertificateInfo where
  toASN1 :: AttributeCertificateInfo -> ASN1S
  toASN1 (AttributeCertificateInfo ver' holder' issuer' sig' sn' valid' attrs' uid' exts') =
    ([Start Sequence] ++)
      . ([IntVal $ fromIntegral ver'] ++)
      . toASN1 holder'
      . toASN1 issuer'
      . toASN1 sig'
      . ([IntVal sn'] ++)
      . toASN1 valid'
      . toASN1 attrs'
      . maybe id (\u -> ([BitString u] ++)) uid'
      . toASN1 exts'
      . ([End Sequence] ++)
  fromASN1 = runParseASN1State parseAttributeCertificateInfo
