{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE PatternSynonyms #-}

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
module Data.X509.AttCert (
    -- * Core types
    AttributeCertificateInfo (..),
    AttCertValidityPeriod (..),
    UniqueID,
    GeneralNames,

    -- * Holder
    Holder (..),
    pattern HolderBaseCertificateID,
    pattern HolderEntityName,
    pattern HolderObjectDigestInfo,

    -- * Issuer
    AttCertIssuer (..),
    V2Form (..),
    IssuerSerial (..),

    -- * ObjectDigestInfo
    ObjectDigestInfo (..),
    DigestedObjectType (..),
) where

import Control.Monad (when)
import Data.ASN1.BitArray
import Data.ASN1.Parse
import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Hourglass (DateTime, TimezoneOffset (..))
import Data.X509.AlgorithmIdentifier
import Data.X509.Attribute hiding (GeneralName)
import Data.X509.Ext (AltName (..))
import Data.X509.ExtensionRaw
import Data.X509.Internal (asn1Container)

type GeneralNames = [AltName]

-- | AttributeCertificateInfo as defined in RFC 5755 section 4.1
data AttributeCertificateInfo = AttributeCertificateInfo
    { aciVersion :: Int -- AttCertVersion, MUST be 1 for v2
    , aciHolder :: Holder
    , aciIssuer :: AttCertIssuer
    , aciSignature :: SignatureALG
    , aciSerialNumber :: Integer -- CertificateSerialNumber
    , aciValidity :: AttCertValidityPeriod
    , aciAttributes :: Attributes
    , aciIssuerUniqueID :: Maybe UniqueID
    , aciExtensions :: Extensions
    }
    deriving (Show, Eq)

-- | Holder as defined in RFC 5755 section 4.1
--
-- RFC 5755 ASN.1:
-- @
-- Holder ::= SEQUENCE {
--     baseCertificateID   [0] IssuerSerial OPTIONAL,
--     entityName          [1] GeneralNames OPTIONAL,
--     objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
-- }
-- @
--
-- All fields are optional, but at least one SHOULD be present.
-- Multiple fields can be present simultaneously.
data Holder = Holder
    { holderBaseCertificateID :: Maybe IssuerSerial
    , holderEntityName :: Maybe GeneralNames
    , holderObjectDigestInfo :: Maybe ObjectDigestInfo
    }
    deriving (Show, Eq)

-- | Pattern synonym for backward compatibility - Holder with only baseCertificateID
pattern HolderBaseCertificateID :: IssuerSerial -> Holder
pattern HolderBaseCertificateID is = Holder (Just is) Nothing Nothing

-- | Pattern synonym for backward compatibility - Holder with only entityName
pattern HolderEntityName :: GeneralNames -> Holder
pattern HolderEntityName gns = Holder Nothing (Just gns) Nothing

-- | Pattern synonym for backward compatibility - Holder with only objectDigestInfo
pattern HolderObjectDigestInfo :: ObjectDigestInfo -> Holder
pattern HolderObjectDigestInfo odi = Holder Nothing Nothing (Just odi)

-- | AttCertIssuer as defined in RFC 5755 section 4.1
data AttCertIssuer
    = AttCertIssuerV1 GeneralNames -- v1Form, MUST NOT be used in this profile
    | AttCertIssuerV2 V2Form
    deriving (Show, Eq)

-- | V2Form for AttCertIssuer
data V2Form = V2Form
    { v2formIssuerName :: GeneralNames
    , v2formBaseCertificateID :: Maybe IssuerSerial
    , v2formObjectDigestInfo :: Maybe ObjectDigestInfo
    }
    deriving (Show, Eq)

-- | IssuerSerial from RFC 5755
data IssuerSerial = IssuerSerial
    { issuer :: GeneralNames
    , serial :: Integer -- CertificateSerialNumber
    , issuerUID :: Maybe UniqueID
    }
    deriving (Show, Eq)

-- | ObjectDigestInfo as defined in RFC 5755 section 4.1
data ObjectDigestInfo = ObjectDigestInfo
    { odiObjectType :: DigestedObjectType
    , odiOtherObjectTypeID :: Maybe OID
    , odiDigestAlgorithm :: SignatureALG
    , odiObjectDigest :: B.ByteString
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
    { acNotBefore :: DateTime
    , acNotAfter :: DateTime
    }
    deriving (Show, Eq)

-- | UniqueID from X.509
type UniqueID = BitArray

instance ASN1Object AttCertValidityPeriod where
    -- RFC 5755 §4.2.6: GeneralizedTime MUST be in UTC (YYYYMMDDHHMMSSZ)
    toASN1 (AttCertValidityPeriod notBefore notAfter) xs =
        [ Start Sequence
        , ASN1Time TimeGeneralized notBefore (Just (TimezoneOffset 0))
        , ASN1Time TimeGeneralized notAfter (Just (TimezoneOffset 0))
        , End Sequence
        ]
            ++ xs
    fromASN1 (Start Sequence : ASN1Time _ nb _ : ASN1Time _ na _ : End Sequence : rest) =
        Right (AttCertValidityPeriod nb na, rest)
    fromASN1 _ = Left "AttCertValidityPeriod: unexpected format"

-- | Parse IssuerSerial content (without outer SEQUENCE)
-- RFC 5755 defines IssuerSerial as:
--   IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial INTEGER, issuerUID [OPTIONAL] }
-- This parser handles the content inside the SEQUENCE.
parseIssuerSerialContent :: ParseASN1 IssuerSerial
parseIssuerSerialContent = do
    -- GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    gns <- parseGeneralNames
    -- Then parse serial number
    s <-
        getNext >>= \case
            IntVal i -> return i
            other -> throwParseError $ "IssuerSerial: expected serial number, got " ++ show other
    -- Optional issuerUID
    uid <- getNextMaybe $ \case
        BitString bs -> Just bs
        _ -> Nothing
    return $ IssuerSerial gns s uid

-- | Parse IssuerSerial with outer SEQUENCE
-- Used by fromASN1 for standalone IssuerSerial parsing
parseIssuerSerial :: ParseASN1 IssuerSerial
parseIssuerSerial = onNextContainer Sequence parseIssuerSerialContent

-- | Parse ObjectDigestInfo content (without outer SEQUENCE)
-- Used for IMPLICIT tagged context where the tag replaces the SEQUENCE
parseObjectDigestInfoContent :: ParseASN1 ObjectDigestInfo
parseObjectDigestInfoContent = do
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
        (OIDOtherObjectTypes, Nothing) ->
            throwParseError
                "ObjectDigestInfo: otherObjectTypeID must be present for otherObjectTypes"
        (OIDOtherObjectTypes, Just _) -> return ()
        (OIDPublicKey, Just _) ->
            throwParseError
                "ObjectDigestInfo: otherObjectTypeID must be absent for publicKey"
        (OIDPublicKeyCert, Just _) ->
            throwParseError
                "ObjectDigestInfo: otherObjectTypeID must be absent for publicKeyCert"
        (_, Nothing) -> return ()

    return $ ObjectDigestInfo dot moid alg digestBs

-- | Parse ObjectDigestInfo with outer SEQUENCE
-- Used by fromASN1 for standalone ObjectDigestInfo parsing
parseObjectDigestInfo :: ParseASN1 ObjectDigestInfo
parseObjectDigestInfo = onNextContainer Sequence parseObjectDigestInfoContent

-- | Parse V2Form content (without outer SEQUENCE wrapper).
-- Used for IMPLICIT tagged context where [0] replaces V2Form's SEQUENCE.
parseV2FormContent :: ParseASN1 V2Form
parseV2FormContent = do
    -- issuerName: GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    issuerName <- parseGeneralNames

    -- baseCertificateID and objectDigestInfo are OPTIONAL per RFC 5755 ASN.1.
    -- Profile constraints (e.g., MUST be omitted) are validated separately.
    -- Note: Context tags use IMPLICIT tagging, which replaces the outermost SEQUENCE,
    -- so we use content parsers (without SEQUENCE wrapper) inside the context tags.
    baseCertID <-
        onNextContainerMaybe (Container Context 0) parseIssuerSerialContent
    objDigestInfo <-
        onNextContainerMaybe (Container Context 1) parseObjectDigestInfoContent

    return $ V2Form issuerName baseCertID objDigestInfo

-- | Parse V2Form with outer SEQUENCE wrapper (for standalone use)
parseV2Form :: ParseASN1 V2Form
parseV2Form = onNextContainer Sequence parseV2FormContent

-- | Parse Holder from ASN.1
-- RFC 5755 allows multiple optional fields to be present simultaneously
-- Note: Context tags use IMPLICIT tagging, which replaces the outermost SEQUENCE
-- of the tagged type. So we use content parsers (without SEQUENCE wrapper) inside
-- the context tags.
parseHolder :: ParseASN1 Holder
parseHolder = onNextContainer Sequence $ do
    -- [0] IMPLICIT replaces IssuerSerial's SEQUENCE, so parse content directly
    mBaseCertID <-
        onNextContainerMaybe (Container Context 0) parseIssuerSerialContent
    -- [1] IMPLICIT replaces GeneralNames' SEQUENCE, so parse GeneralName(s) directly
    mEntityName <-
        onNextContainerMaybe (Container Context 1) (getMany parseGeneralName)
    -- [2] IMPLICIT replaces ObjectDigestInfo's SEQUENCE, so parse content directly
    mObjectDigestInfo <-
        onNextContainerMaybe (Container Context 2) parseObjectDigestInfoContent
    -- RFC 5755: at least one SHOULD be present, but we don't enforce this strictly
    -- Handle empty GeneralNames case - convert empty list to Nothing
    let mEntityNameFinal = case mEntityName of
            Just [] -> Nothing
            other -> other
    return $ Holder mBaseCertID mEntityNameFinal mObjectDigestInfo

parseAttCertIssuer :: ParseASN1 AttCertIssuer
parseAttCertIssuer = do
    -- IMPLICIT [0] replaces V2Form's SEQUENCE, so parse content directly
    mV2Form <- onNextContainerMaybe (Container Context 0) parseV2FormContent
    case mV2Form of
        Just v2 -> return $ AttCertIssuerV2 v2
        -- v1Form: GeneralNames (SEQUENCE OF GeneralName) appears directly
        Nothing -> AttCertIssuerV1 <$> parseGeneralNames

-- | Parse AttributeCertificateInfo content (without outer SEQUENCE)
-- This matches the pattern used by Certificate in Data.X509.Cert
parseAttributeCertificateInfoContent :: ParseASN1 AttributeCertificateInfo
parseAttributeCertificateInfoContent = do
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
                when (i <= 0) $
                    throwParseError "AttributeCertificateInfo: serialNumber MUST be positive"
                return i
            _ -> throwParseError "AttributeCertificateInfo: expecting serial number"
    validity <- getObject
    attrs <- getObject
    uid <- getNextMaybe $ \case
        BitString bs -> Just bs
        _ -> Nothing
    AttributeCertificateInfo ver holder acIssuer sig sn validity attrs uid
        <$> getObject

-- | Parse AttributeCertificateInfo with outer SEQUENCE
-- Used when parsing from raw ASN.1 (e.g., for testing)
parseAttributeCertificateInfo :: ParseASN1 AttributeCertificateInfo
parseAttributeCertificateInfo = onNextContainer Sequence parseAttributeCertificateInfoContent

-- | Encode V2Form content (without outer SEQUENCE)
-- Used for IMPLICIT tagged context where [0] replaces V2Form's SEQUENCE
encodeV2FormContent :: V2Form -> [ASN1]
encodeV2FormContent (V2Form issuerName baseCertID objDigestInfo) =
    encodeGeneralNames issuerName
        ++ maybe
            []
            (\x -> asn1Container (Container Context 0) (encodeIssuerSerialContent x))
            baseCertID
        ++ maybe
            []
            (\x -> asn1Container (Container Context 1) (encodeObjectDigestInfoContent x))
            objDigestInfo

-- | Encode IssuerSerial content (without outer SEQUENCE)
-- Used for IMPLICIT tagged context where the tag replaces the SEQUENCE
encodeIssuerSerialContent :: IssuerSerial -> [ASN1]
encodeIssuerSerialContent (IssuerSerial issuer' serial' issuerUID') =
    encodeGeneralNames issuer'
        ++ [IntVal serial']
        ++ maybe [] (\uid -> [BitString uid]) issuerUID'

-- | Encode ObjectDigestInfo content (without outer SEQUENCE)
-- Used for IMPLICIT tagged context where the tag replaces the SEQUENCE
encodeObjectDigestInfoContent :: ObjectDigestInfo -> [ASN1]
encodeObjectDigestInfoContent (ObjectDigestInfo objType otherObjType alg objDigest) =
    [IntVal $ fromIntegral $ fromEnum objType]
        ++ maybe [] (\oid -> [OID oid]) otherObjType
        ++ toASN1 alg []
        ++ [BitString $ toBitArray objDigest 0]

instance ASN1Object IssuerSerial where
    toASN1 (IssuerSerial issuer' serial' issuerUID') xs =
        [Start Sequence]
            ++ encodeIssuerSerialContent (IssuerSerial issuer' serial' issuerUID')
            ++ [End Sequence]
            ++ xs
    fromASN1 = runParseASN1State parseIssuerSerial

instance ASN1Object ObjectDigestInfo where
    toASN1 odi xs =
        [Start Sequence]
            ++ encodeObjectDigestInfoContent odi
            ++ [End Sequence]
            ++ xs
    fromASN1 = runParseASN1State parseObjectDigestInfo

instance ASN1Object V2Form where
    -- Note: Context tags use IMPLICIT tagging, so we encode content without SEQUENCE wrapper
    toASN1 (V2Form issuerName baseCertID objDigestInfo) xs =
        [Start Sequence]
            ++ encodeGeneralNames issuerName
            ++ maybe
                []
                (\x -> asn1Container (Container Context 0) (encodeIssuerSerialContent x))
                baseCertID
            ++ maybe
                []
                (\x -> asn1Container (Container Context 1) (encodeObjectDigestInfoContent x))
                objDigestInfo
            ++ [End Sequence]
            ++ xs
    fromASN1 = runParseASN1State parseV2Form

instance ASN1Object Holder where
    -- Note: Context tags use IMPLICIT tagging, so we encode content without SEQUENCE wrapper
    toASN1 (Holder mBaseCertID mEntityName mObjDigestInfo) xs =
        [Start Sequence]
            ++ maybe
                []
                (\is -> asn1Container (Container Context 0) (encodeIssuerSerialContent is))
                mBaseCertID
            ++ maybe
                []
                (\gns -> asn1Container (Container Context 1) (concatMap encodeGeneralName gns))
                mEntityName
            ++ maybe
                []
                (\odi -> asn1Container (Container Context 2) (encodeObjectDigestInfoContent odi))
                mObjDigestInfo
            ++ [End Sequence]
            ++ xs
    fromASN1 = runParseASN1State parseHolder

instance ASN1Object AttCertIssuer where
    toASN1 (AttCertIssuerV1 generalNames) xs = encodeGeneralNames generalNames ++ xs
    -- IMPLICIT [0] replaces V2Form's SEQUENCE, so encode content directly inside [0]
    toASN1 (AttCertIssuerV2 v2) xs = asn1Container (Container Context 0) (encodeV2FormContent v2) ++ xs
    fromASN1 = runParseASN1State parseAttCertIssuer

instance ASN1Object AttributeCertificateInfo where
    toASN1
        ( AttributeCertificateInfo
                acVer
                acHolder
                acIssuer
                acSig
                acSn
                acValid
                acAttrs
                acUid
                acExts
            )
        xs =
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

    -- Note: decodeSignedObject strips the outer SEQUENCE before calling fromASN1.
    -- For direct fromASN1 calls (e.g., property tests), the SEQUENCE is present.
    -- We handle both cases by checking the first element.
    fromASN1 [] = Left "AttributeCertificateInfo: empty input"
    fromASN1 asn1@(Start Sequence : _) = runParseASN1State parseAttributeCertificateInfo asn1
    fromASN1 asn1 = runParseASN1State parseAttributeCertificateInfoContent asn1
