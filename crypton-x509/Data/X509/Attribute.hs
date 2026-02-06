{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use camelCase" #-}

-- |
-- Module      : Data.X509.Attribute
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Attribute Certificate attributes, as defined in RFC 5755.
module Data.X509.Attribute (
    -- * Generic Attribute types
    Attribute (..),
    Attributes (..),
    AttributeType,
    AttributeValue,
    getAttribute,
    getAttributeE,
    decodeAttribute,
    encodeAttribute,
    IsAttribute (..),

    -- * Specific Attribute data types
    Attr_Role (..),
    Attr_SvceAuthInfo (..),
    Attr_AccessIdentity (..),
    Attr_ChargingIdentity (..),
    Attr_Group (..),
    Attr_Clearance (..),

    -- ** Syntax types for attributes
    RoleSyntax (..),
    SvceAuthInfo (..),
    IetfAttrSyntax (..),
    IetfAttrSyntaxValue (..),
    Clearance (..),
    ClassListFlag (..),
    SecurityCategory (..),
    GeneralName,
    encodeGeneralNames,
    encodeGeneralName,
    parseGeneralNames,
    parseGeneralName,

    -- * OIDs
    oid_Role,
    oid_SvceAuthInfo,
    oid_AccessIdentity,
    oid_ChargingIdentity,
    oid_Group,
    oid_Clearance,
)
where

import Control.Monad (when)
import Data.ASN1.BitArray
import Data.ASN1.Parse
import Data.ASN1.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.List (find, nub)
import Data.Maybe (fromMaybe)
import Data.Proxy
import Data.X509.Ext (AltName (..), encodeGeneralName, encodeGeneralNames, parseGeneralName, parseGeneralNames)
import Data.X509.Internal (asn1Container)

type GeneralName = AltName

-- | A list of attributes. This is the top-level type for the `attributes` field.
newtype Attributes = Attributes {unAttributes :: [Attribute]}
    deriving (Show, Eq)

-- | An attribute, composed of an OID and a set of values.
data Attribute = Attribute
    { attrType :: AttributeType
    , attrValues :: [[AttributeValue]]
    -- ^ A list of encoded ASN1 values, where each inner list represents one value.
    }
    deriving (Show, Eq)

-- | An attribute type is just an OID.
type AttributeType = OID

-- | An attribute value is a full ASN1 structure.
type AttributeValue = ASN1

instance ASN1Object Attributes where
    fromASN1 :: [ASN1] -> Either String (Attributes, [ASN1])
    fromASN1 = runParseASN1State $ onNextContainer Sequence $ do
        attrs <- getMany parseAttribute
        -- Constraint: attributes field MUST NOT be empty.
        when (null attrs) $
            throwParseError "Attributes field MUST contain at least one attribute"
        -- Constraint: attribute types MUST be unique.
        let oids = map attrType attrs
        when (hasDuplicates oids) $
            throwParseError "Attribute types MUST be unique"
        return $ Attributes attrs
      where
        hasDuplicates :: Ord a => [a] -> Bool
        hasDuplicates list = length (nub list) /= length list

    toASN1 :: Attributes -> ASN1S
    toASN1 (Attributes attrs) rest =
        [Start Sequence]
            ++ concatMap encodeAttributeASN1 attrs
            ++ [End Sequence]
            ++ rest

-- | Parse a single raw 'Attribute'.
-- This follows the structure `Attribute ::= SEQUENCE { type, values }`
-- where `values` is `SET OF AttributeValue`.
parseAttribute :: ParseASN1 Attribute
parseAttribute = onNextContainer Sequence $ do
    oid <- getNextOID
    vals <-
        onNextContainer Set (getMany (onNextContainer Sequence (getMany getNext)))
    if null vals
        then throwParseError "Attribute values SET OF cannot be empty"
        else return $ Attribute oid vals
  where
    getNextOID =
        getNext >>= \case
            OID o -> return o
            _ -> throwParseError "Expected OID for attribute type"

-- | Encode a single raw \'Attribute\' into its ASN.1 representation.
encodeAttributeASN1 :: Attribute -> [ASN1]
encodeAttributeASN1 (Attribute oid vals) =
    [Start Sequence, OID oid, Start Set]
        -- vals is [[ASN1]], where each inner list is the content of a SEQUENCE.
        -- We need to wrap each one in Start/End Sequence tags.
        ++ concatMap (\v -> [Start Sequence] ++ v ++ [End Sequence]) vals
        ++ [End Set, End Sequence]

-- | Class for types that can be encoded as an attribute value.
class IsAttribute a where
    -- | The OID associated with this attribute type.
    attrOID :: Proxy a -> OID

    -- | A parser for the attribute value.
    attrParser :: Proxy a -> ParseASN1 a

    -- | Decode a single attribute value (a full ASN1 structure).
    attrDecode :: [AttributeValue] -> Either String a
    attrDecode asn1s = case runParseASN1State (attrParser (Proxy @a)) asn1s of
        Left err -> Left err
        Right (x, []) -> Right x
        Right (_, rest) -> Left ("Unexpected data after parsing: " ++ show rest)

    -- | Encode a value into a set of attribute values.
    attrEncode :: a -> [[AttributeValue]]

-- | Get a specific attribute from a list of attributes.
-- This returns a list of decoded attribute values.
-- If decoding fails, it returns Nothing.
getAttribute :: forall a. IsAttribute a => Attributes -> Maybe [a]
getAttribute attrs =
    case getAttributeE attrs of
        Nothing -> Nothing
        Just (Left _) -> Nothing
        Just (Right v) -> Just v

-- | Get a specific attribute from a list of attributes, with error reporting.
-- Returns a list of decoded attribute values, with possible decoding errors.
getAttributeE
    :: forall a. IsAttribute a => Attributes -> Maybe (Either String [a])
getAttributeE (Attributes attrs) =
    case find (\attr -> attrType attr == oid) attrs of
        Nothing -> Nothing
        Just attr -> Just $ mapM attrDecode (attrValues attr)
  where
    oid = attrOID (Proxy @a)

-- | Decode a raw 'Attribute' into a specific attribute type.
decodeAttribute
    :: forall a. IsAttribute a => Attribute -> Maybe (Either String [a])
decodeAttribute attr
    | attrType attr == attrOID (Proxy @a) = Just $ mapM attrDecode (attrValues attr)
    | otherwise = Nothing

-- | Encode a specific attribute type into a raw 'Attribute'.
encodeAttribute :: forall a. IsAttribute a => [a] -> Attribute
encodeAttribute values =
    Attribute (attrOID (Proxy @a)) (concatMap attrEncode values)

-- OIDs from RFC 5755
id_pkix :: OID
id_pkix = [1, 3, 6, 1, 5, 5, 7]

id_aca :: OID
id_aca = id_pkix ++ [10]

id_at :: OID
id_at = [2, 5, 4]

-- | OID for 'RoleSyntax' attribute: { id-at 72 }
oid_Role :: OID
oid_Role = id_at ++ [72]

-- | OID for service authentication information attribute: { id-aca 1 }
oid_SvceAuthInfo :: OID
oid_SvceAuthInfo = id_aca ++ [1]

-- | OID for access identity attribute: { id-aca 2 }
oid_AccessIdentity :: OID
oid_AccessIdentity = id_aca ++ [2]

-- | OID for charging identity attribute: { id-aca 3 }
oid_ChargingIdentity :: OID
oid_ChargingIdentity = id_aca ++ [3]

-- | OID for group attribute: { id-aca 4 }
oid_Group :: OID
oid_Group = id_aca ++ [4]

-- | OID for clearance attribute: { id-at 55 }
oid_Clearance :: OID
oid_Clearance = id_at ++ [55]

-- Specific attribute types and their IsAttribute instances

-- | Wrapper for 'RoleSyntax'
newtype Attr_Role = Attr_Role RoleSyntax deriving (Show, Eq)

-- | Wrapper for 'SvceAuthInfo' used as Service Authentication
newtype Attr_SvceAuthInfo = Attr_SvceAuthInfo SvceAuthInfo deriving (Show, Eq)

-- | Wrapper for 'SvceAuthInfo' used as Access Identity
newtype Attr_AccessIdentity = Attr_AccessIdentity SvceAuthInfo
    deriving (Show, Eq)

-- | Wrapper for 'IetfAttrSyntax' used as Charging Identity
newtype Attr_ChargingIdentity = Attr_ChargingIdentity IetfAttrSyntax
    deriving (Show, Eq)

-- | Wrapper for 'IetfAttrSyntax' used as Group
newtype Attr_Group = Attr_Group IetfAttrSyntax deriving (Show, Eq)

-- | Wrapper for 'Clearance'
newtype Attr_Clearance = Attr_Clearance Clearance deriving (Show, Eq)

-- | Role attribute syntax from RFC 5755 section 4.4.5
data RoleSyntax = RoleSyntax
    { roleAuthority :: Maybe [GeneralName]
    -- ^ GeneralNames
    , roleName :: GeneralName
    -- ^ GeneralName
    }
    deriving (Show, Eq)

instance IsAttribute Attr_Role where
    attrOID _ = oid_Role
    attrParser _ = Attr_Role <$> parseRoleSyntax
    attrEncode (Attr_Role rs) = [encodeRoleSyntax rs]

parseRoleSyntax :: ParseASN1 RoleSyntax
parseRoleSyntax = do
    auth <- onNextContainerMaybe (Container Context 0) parseGeneralNames
    name <- onNextContainer (Container Context 1) parseGeneralName
    return $ RoleSyntax auth name

encodeRoleSyntax :: RoleSyntax -> [ASN1]
encodeRoleSyntax (RoleSyntax auth name) =
    maybe [] (\a -> asn1Container (Container Context 0) (encodeGeneralNames a)) auth
        ++ asn1Container (Container Context 1) (encodeGeneralName name)

-- | Service Authentication Information attribute from RFC 5755 section 4.4.1
data SvceAuthInfo = SvceAuthInfo
    { svceAuthService :: GeneralName
    , svceAuthIdent :: GeneralName
    , svceAuthInfo :: Maybe B.ByteString
    }
    deriving (Show, Eq)

instance IsAttribute Attr_SvceAuthInfo where
    attrOID _ = oid_SvceAuthInfo
    attrParser _ = Attr_SvceAuthInfo <$> parseSvceAuthInfo
    attrEncode (Attr_SvceAuthInfo s) = [encodeSvceAuthInfo s]

instance IsAttribute Attr_AccessIdentity where
    attrOID _ = oid_AccessIdentity
    attrParser _ = Attr_AccessIdentity <$> parseSvceAuthInfo
    attrEncode (Attr_AccessIdentity s) = [encodeSvceAuthInfo s]

parseSvceAuthInfo :: ParseASN1 SvceAuthInfo
parseSvceAuthInfo = do
    service <- parseGeneralName
    ident <- parseGeneralName
    auth <- getNextMaybe (\case OctetString s -> Just s; _ -> Nothing)
    return $ SvceAuthInfo service ident auth

encodeSvceAuthInfo :: SvceAuthInfo -> [ASN1]
encodeSvceAuthInfo (SvceAuthInfo service ident auth) =
    encodeGeneralName service
        ++ encodeGeneralName ident
        ++ maybe [] (\bs -> [OctetString bs]) auth

-- | IETF attribute syntax from RFC 5755 section 4.4
data IetfAttrSyntax = IetfAttrSyntax
    { ietfPolicyAuthority :: Maybe [GeneralName] -- GeneralNames
    , ietfValues :: [IetfAttrSyntaxValue]
    }
    deriving (Show, Eq)

data IetfAttrSyntaxValue
    = IetfAttrSyntaxOctets B.ByteString
    | IetfAttrSyntaxOid OID
    | IetfAttrSyntaxString String -- UTF8String
    deriving (Show, Eq)

instance IsAttribute Attr_ChargingIdentity where
    attrOID _ = oid_ChargingIdentity
    attrParser _ = Attr_ChargingIdentity <$> parseIetfAttrSyntax
    attrEncode (Attr_ChargingIdentity s) = [encodeIetfAttrSyntax s]

instance IsAttribute Attr_Group where
    attrOID _ = oid_Group
    attrParser _ = Attr_Group <$> parseIetfAttrSyntax
    attrEncode (Attr_Group s) = [encodeIetfAttrSyntax s]

parseIetfAttrSyntax :: ParseASN1 IetfAttrSyntax
parseIetfAttrSyntax =
    IetfAttrSyntax
        <$> onNextContainerMaybe (Container Context 0) parseGeneralNames
        <*> onNextContainer Sequence (getMany parseIetfValue)

parseIetfValue :: ParseASN1 IetfAttrSyntaxValue
parseIetfValue =
    getNext >>= \case
        OctetString bs -> return $ IetfAttrSyntaxOctets bs
        OID oid -> return $ IetfAttrSyntaxOid oid
        ASN1String cs -> case asn1CharacterToString cs of
            Just s -> return $ IetfAttrSyntaxString s
            Nothing -> throwParseError "invalid IetfAttrSyntax string"
        _ -> throwParseError "unknown IetfAttrSyntax value type"

encodeIetfAttrSyntax :: IetfAttrSyntax -> [ASN1]
encodeIetfAttrSyntax (IetfAttrSyntax authority values) =
    maybe
        []
        (\gns -> asn1Container (Container Context 0) (encodeGeneralNames gns))
        authority
        ++ asn1Container Sequence (map encodeIetfValue values)

encodeIetfValue :: IetfAttrSyntaxValue -> ASN1
encodeIetfValue (IetfAttrSyntaxOctets bs) = OctetString bs
encodeIetfValue (IetfAttrSyntaxOid oid) = OID oid
encodeIetfValue (IetfAttrSyntaxString s) = ASN1String (ASN1CharacterString UTF8 (BC.pack s))

-- | Clearance attribute from RFC 5755 section 4.4.6
data Clearance = Clearance
    { clearancePolicyId :: OID
    , clearanceClassList :: [ClassListFlag]
    , clearanceSecurityCategories :: Maybe [SecurityCategory]
    }
    deriving (Show, Eq)

data ClassListFlag
    = ClassList_unmarked -- (0)
    | ClassList_unclassified -- (1)
    | ClassList_restricted -- (2)
    | ClassList_confidential -- (3)
    | ClassList_secret -- (4)
    | ClassList_topSecret -- (5)
    deriving (Show, Eq, Ord, Enum)

data SecurityCategory = SecurityCategory
    { securityCategoryType :: OID
    , securityCategoryValue :: [ASN1]
    }
    deriving (Show, Eq)

instance IsAttribute Attr_Clearance where
    attrOID _ = oid_Clearance
    attrParser _ = Attr_Clearance <$> parseClearance
    attrEncode (Attr_Clearance c) = [encodeClearance c]

parseClearance :: ParseASN1 Clearance
parseClearance = do
    policyId <-
        getNext >>= \case
            OID o -> return o
            _ -> throwParseError "Clearance: Expected OID for policyId"
    classList <-
        getNextMaybe (\case BitString bs -> Just (bitsToFlags bs); _ -> Nothing)
    secCat <- onNextContainerMaybe Set (getMany parseSecurityCategory)
    return $
        Clearance policyId (fromMaybe [ClassList_unclassified] classList) secCat

parseSecurityCategory :: ParseASN1 SecurityCategory
parseSecurityCategory = onNextContainer Sequence $ do
    typ <-
        onNextContainer (Container Context 0) $
            getNext >>= \case OID o -> return o; _ -> throwParseError "Expected OID"
    val <- onNextContainer (Container Context 1) (getMany getNext)
    return $ SecurityCategory typ val

encodeClearance :: Clearance -> [ASN1]
encodeClearance (Clearance policyId classList secCat) =
    [OID policyId]
        ++ classListEncoding
        ++ secCatEncoding
  where
    defaultClassListBits = flagsToBits [ClassList_unclassified]
    classListBits = flagsToBits classList
    classListEncoding = [BitString classListBits | not (classListBits == defaultClassListBits)]
    secCatEncoding = case secCat of
        Nothing -> []
        Just scs -> [Start Set] ++ concatMap encodeSecurityCategory scs ++ [End Set]

encodeSecurityCategory :: SecurityCategory -> [ASN1]
encodeSecurityCategory (SecurityCategory typ val) =
    [Start Sequence]
        ++ asn1Container (Container Context 0) [OID typ]
        ++ asn1Container (Container Context 1) val
        ++ [End Sequence]

-- Helpers

bitsToFlags :: Enum a => BitArray -> [a]
bitsToFlags bits = concat $ flip map [0 .. (bitArrayLength bits - 1)] $ \i -> do
    let isSet = bitArrayGetBit bits i
    ([toEnum $ fromIntegral i | isSet])

flagsToBits :: Enum a => [a] -> BitArray
flagsToBits flags = foldl bitArraySetBit bitArrayEmpty $ map (fromIntegral . fromEnum) flags
  where
    bitArrayEmpty = toBitArray (B.pack [0, 0]) 9 -- 9 bits for key usage, clearance needs less but this is safe
