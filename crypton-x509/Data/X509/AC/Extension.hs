{-# LANGUAGE LambdaCase #-}

-- |
-- Module      : Data.X509.AC.Extension
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Attribute Certificate extensions as defined in RFC 5755.
--
-- This module provides typed extension types specific to Attribute Certificates:
--
-- * 'ExtNoRevAvail' — indicates no revocation information is available (RFC 5755 §4.3.6)
-- * 'ExtAuditIdentity' — audit trail identifier (RFC 5755 §4.3.1)
-- * 'ExtTargetInformation' — targeting restriction (RFC 5755 §4.3.2)
module Data.X509.AC.Extension
    ( -- * Extensions
      ExtNoRevAvail (..)
    , ExtAuditIdentity (..)
    , ExtTargetInformation (..)

      -- * Target types (for ExtTargetInformation)
    , Target (..)
    , TargetCertDescription (..)
    ) where

import Data.ASN1.Parse
import Data.ASN1.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.X509.AttCert (IssuerSerial, ObjectDigestInfo)
import Data.X509.Ext
    ( AltName (..)
    , Extension (..)
    , encodeGeneralName
    , parseGeneralName
    )
import Data.X509.Internal (asn1Container)

-- | No Revocation Available extension (RFC 5755 §4.3.6)
--
-- OID: id-ce-noRevAvail {2 5 29 56}
-- Criticality: MUST be FALSE
-- Value: NULL
data ExtNoRevAvail = ExtNoRevAvail
    deriving (Show, Eq)

instance Extension ExtNoRevAvail where
    extOID _ = [2, 5, 29, 56]
    extHasNestedASN1 = const True
    extEncode ExtNoRevAvail = [Null]
    extDecode [Null] = Right ExtNoRevAvail
    extDecode _ = Left "ExtNoRevAvail: expected NULL"

-- | Audit Identity extension (RFC 5755 §4.3.1)
--
-- OID: id-pe-ac-auditIdentity {1 3 6 1 5 5 7 1 4}
-- Criticality: MUST be TRUE
-- Value: OCTET STRING
newtype ExtAuditIdentity = ExtAuditIdentity B.ByteString
    deriving (Show, Eq)

instance Extension ExtAuditIdentity where
    extOID _ = [1, 3, 6, 1, 5, 5, 7, 1, 4]
    extHasNestedASN1 = const True
    extEncode (ExtAuditIdentity bs) = [OctetString bs]
    extDecode [OctetString bs] = Right (ExtAuditIdentity bs)
    extDecode _ = Left "ExtAuditIdentity: expected OctetString"

-- | Target Information extension (RFC 5755 §4.3.2)
--
-- OID: id-ce-targetInformation {2 5 29 55}
-- Criticality: MUST be TRUE
-- Value: Targets ::= SEQUENCE OF Target
newtype ExtTargetInformation = ExtTargetInformation [Target]
    deriving (Show, Eq)

data Target
    = TargetName AltName
    | TargetGroup AltName
    | TargetCert TargetCertDescription
    deriving (Show, Eq)

-- | RFC 5755 TargetCert. Field names adjusted to avoid Haskell collisions.
data TargetCertDescription = TargetCertDescription
    { targetCertificate :: IssuerSerial
    , targetCertName :: Maybe AltName
    , targetCertDigest :: Maybe ObjectDigestInfo
    }
    deriving (Show, Eq)

instance Extension ExtTargetInformation where
    extOID _ = [2, 5, 29, 55]
    extHasNestedASN1 = const True
    extEncode (ExtTargetInformation targets) =
        [Start Sequence]
            ++ concatMap encodeTarget targets
            ++ [End Sequence]
    extDecode asn1 =
        ExtTargetInformation
            <$> runParseASN1 (onNextContainer Sequence (getMany parseTarget)) asn1

encodeTarget :: Target -> [ASN1]
encodeTarget (TargetName name) =
    asn1Container (Container Context 0) (encodeGeneralName name)
encodeTarget (TargetGroup name) =
    asn1Container (Container Context 1) (encodeGeneralName name)
encodeTarget (TargetCert tc) =
    asn1Container (Container Context 2) (encodeTargetCert tc)

encodeTargetCert :: TargetCertDescription -> [ASN1]
encodeTargetCert (TargetCertDescription cert mName mDigest) =
    toASN1 cert []
        ++ maybe [] encodeGeneralName mName
        ++ maybe [] (\odi -> toASN1 odi []) mDigest

parseTarget :: ParseASN1 Target
parseTarget = do
    mName <- onNextContainerMaybe (Container Context 0) parseGeneralName
    case mName of
        Just n -> return $ TargetName n
        Nothing -> do
            mGroup <- onNextContainerMaybe (Container Context 1) parseGeneralName
            case mGroup of
                Just g -> return $ TargetGroup g
                Nothing -> do
                    mCert <- onNextContainerMaybe (Container Context 2) parseTargetCert
                    case mCert of
                        Just c -> return $ TargetCert c
                        Nothing -> throwParseError "Target: expected [0], [1], or [2]"

parseTargetCert :: ParseASN1 TargetCertDescription
parseTargetCert = do
    cert <- getObject
    mName <- parseOptionalGeneralName
    more <- hasNext
    mDigest <-
        if more
            then Just <$> getObject -- must be ObjectDigestInfo
            else return Nothing
    return $ TargetCertDescription cert mName mDigest

-- | Try to parse an optional GeneralName without consuming non-GeneralName data.
--
-- GeneralName is a CHOICE type whose alternatives all use context tags:
--   Other Context 1 (rfc822Name), Other Context 2 (dNSName),
--   Start (Container Context 4) (directoryName), Other Context 6 (uniformResourceIdentifier),
--   Other Context 7 (iPAddress), Start (Container Context 0) (otherName for XMPP/DNSSRV).
--
-- ObjectDigestInfo starts with Start Sequence, which none of the above match,
-- so the peek-based approach safely distinguishes the two.
parseOptionalGeneralName :: ParseASN1 (Maybe AltName)
parseOptionalGeneralName = do
    -- Try simple (non-constructed) GeneralName forms via getNextMaybe.
    -- Returns Nothing (without consuming) if the next element doesn't match.
    mSimple <- getNextMaybe $ \case
        Other Context 1 b -> Just $ AltNameRFC822 (BC.unpack b)
        Other Context 2 b -> Just $ AltNameDNS (BC.unpack b)
        Other Context 6 b -> Just $ AltNameURI (BC.unpack b)
        Other Context 7 b -> Just $ AltNameIP b
        _ -> Nothing
    case mSimple of
        Just name -> return (Just name)
        Nothing -> do
            -- Try directoryName [4] IMPLICIT (constructed, wraps a SEQUENCE of RDNs)
            mDir <- onNextContainerMaybe (Container Context 4) getObject
            case mDir of
                Just dn -> return (Just (AltDirectoryName dn))
                Nothing ->
                    -- Try otherName [0] IMPLICIT (constructed, used for XMPP / DNSSRV)
                    onNextContainerMaybe (Container Context 0) parseComposedAddr
  where
    -- Replicates the composed-address logic from parseGeneralName in Data.X509.Ext
    parseComposedAddr = do
        n <- getNext
        case n of
            OID [1, 3, 6, 1, 5, 5, 7, 8, 5] -> do
                c <- getNextContainerMaybe (Container Context 0)
                case c of
                    Just [ASN1String cs] ->
                        case asn1CharacterToString cs of
                            Just s -> return $ AltNameXMPP s
                            Nothing -> throwParseError "TargetCert GeneralName: invalid XMPP string"
                    _ -> throwParseError "TargetCert GeneralName: expected XMPP string"
            OID [1, 3, 6, 1, 5, 5, 7, 8, 7] -> do
                c <- getNextContainerMaybe (Container Context 0)
                case c of
                    Just [ASN1String cs] ->
                        case asn1CharacterToString cs of
                            Just s -> return $ AltNameDNSSRV s
                            Nothing -> throwParseError "TargetCert GeneralName: invalid DNSSRV string"
                    _ -> throwParseError "TargetCert GeneralName: expected DNSSRV string"
            _ -> throwParseError ("TargetCert GeneralName: unknown otherName OID " ++ show n)
