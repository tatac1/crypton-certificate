{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TestAC where

import Arbitrary ()
import Control.Monad
import Data.ASN1.BitArray
import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Function (on)
import Data.Hourglass
import Data.List (nub, nubBy, sort)
import Data.X509
import Data.X509.AttCert
import Data.X509.Attribute
import qualified Data.X509.AttributeRaw as Raw
import Test.Tasty
import Test.Tasty.QuickCheck

-- | Helper from Tests.hs
arbitraryBS :: Int -> Int -> Gen B.ByteString
arbitraryBS r1 r2 = choose (r1, r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

-- | Generate a non-empty list
listOf1NonEmpty :: Gen a -> Gen [a]
listOf1NonEmpty = listOf1

-- Arbitrary instances for common types not defined in Tests.hs

instance Arbitrary AltName where
  arbitrary = do
    printable <- getASCIIString <$> arbitrary
    oneof
      [ pure $ AltNameRFC822 printable,
        pure $ AltNameDNS printable,
        pure $ AltNameURI printable,
        AltNameIP <$> arbitraryBS 4 4,
        -- TODO
        -- pure $ AltNameXMPP printable,
        -- pure $ AltNameDNSSRV printable,
        AltDirectoryName <$> arbitrary
      ]

-- Arbitrary instances for Attribute Certificate types

-- Generate a DateTime within a reasonable range to avoid `gmTime` failures.
genReasonableDateTime :: Gen DateTime
genReasonableDateTime = do
  -- Generate a year between 1970 and 2070
  year <- choose (1970, 2070)
  month <- elements [January .. December]
  -- Keep day simple to avoid complexity with month lengths
  day <- choose (1, 28)
  hour <- choose (0, 23)
  minute <- choose (0, 59)
  second <- choose (0, 59)
  let tod = TimeOfDay (Hours hour) (Minutes minute) (Seconds second) (NanoSeconds 0)
  return $ DateTime (Date year month day) tod

genValidity :: Gen AttCertValidityPeriod
genValidity = do
  start <- genReasonableDateTime
  -- Add a positive duration, up to ~10 years in seconds
  duration <- choose (1, 315576000)
  let end = timeAdd start (Seconds duration)
  return $ AttCertValidityPeriod start end

instance Arbitrary AttCertValidityPeriod where
  arbitrary = genValidity

instance Arbitrary DigestedObjectType where
  arbitrary = elements [OIDPublicKey, OIDPublicKeyCert, OIDOtherObjectTypes]

instance Arbitrary ObjectDigestInfo where
  arbitrary = do
    dot <- arbitrary
    moid <- case dot of
      OIDOtherObjectTypes -> Just <$> arbitrary
      _ -> pure Nothing
    ObjectDigestInfo dot moid <$> arbitrary <*> arbitraryBS 16 32

instance Arbitrary IssuerSerial where
  arbitrary = IssuerSerial <$> listOf1NonEmpty arbitrary <*> (getPositive <$> arbitrary) <*> (Just <$> (toBitArray <$> arbitraryBS 1 8 <*> pure 0))

instance Arbitrary Holder where
  arbitrary =
    oneof
      [ HolderBaseCertificateID <$> arbitrary,
        HolderEntityName <$> listOf1NonEmpty arbitrary,
        HolderObjectDigestInfo <$> arbitrary
      ]

-- Generator for a valid V2Form issuer name
genV2FormIssuerName :: Gen [AltName]
genV2FormIssuerName = do
  dn <- suchThat arbitrary (\(DistinguishedName l) -> not (null l))
  return [AltDirectoryName dn]

instance Arbitrary V2Form where
  arbitrary = V2Form <$> genV2FormIssuerName <*> pure Nothing <*> pure Nothing

instance Arbitrary AttCertIssuer where
  arbitrary = AttCertIssuerV2 <$> arbitrary

-- Arbitrary instances for Attributes

instance Arbitrary RoleSyntax where
  arbitrary = (RoleSyntax . Just <$> listOf1NonEmpty arbitrary) <*> arbitrary

instance Arbitrary Attr_Role where
  arbitrary = Attr_Role <$> arbitrary

instance Arbitrary SvceAuthInfo where
  arbitrary = SvceAuthInfo <$> arbitrary <*> arbitrary <*> (Just <$> arbitraryBS 8 16)

instance Arbitrary Attr_SvceAuthInfo where
  arbitrary = Attr_SvceAuthInfo <$> arbitrary

instance Arbitrary Attr_AccessIdentity where
  arbitrary = Attr_AccessIdentity <$> arbitrary

instance Arbitrary IetfAttrSyntaxValue where
  arbitrary =
    oneof
      [ IetfAttrSyntaxOctets <$> arbitraryBS 4 16,
        IetfAttrSyntaxOid <$> arbitrary,
        IetfAttrSyntaxString . getASCIIString <$> arbitrary
      ]

instance Arbitrary IetfAttrSyntax where
  arbitrary = (IetfAttrSyntax . Just <$> listOf1NonEmpty arbitrary) <*> listOf1NonEmpty arbitrary

instance Arbitrary Attr_ChargingIdentity where
  arbitrary = Attr_ChargingIdentity <$> arbitrary

instance Arbitrary Attr_Group where
  arbitrary = Attr_Group <$> arbitrary

instance Arbitrary ClassListFlag where
  arbitrary = elements [ClassList_unmarked .. ClassList_topSecret]

instance Arbitrary SecurityCategory where
  arbitrary = SecurityCategory <$> arbitrary <*> pure [IntVal 1, IntVal 2]

instance Arbitrary Clearance where
  arbitrary = do
    policyId <- arbitrary
    classList <- sort . nub <$> listOf1NonEmpty arbitrary
    secCat <- Just <$> listOf1NonEmpty arbitrary
    return $ Clearance policyId classList secCat

instance Arbitrary Attr_Clearance where
  arbitrary = Attr_Clearance <$> arbitrary

-- Generic Attribute generator
instance Arbitrary Attribute where
  arbitrary =
    oneof
      [ encodeAttribute . (: []) <$> (arbitrary :: Gen Attr_Role),
        encodeAttribute . (: []) <$> (arbitrary :: Gen Attr_SvceAuthInfo),
        encodeAttribute . (: []) <$> (arbitrary :: Gen Attr_AccessIdentity),
        encodeAttribute . (: []) <$> (arbitrary :: Gen Attr_ChargingIdentity),
        encodeAttribute . (: []) <$> (arbitrary :: Gen Attr_Group),
        encodeAttribute . (: []) <$> (arbitrary :: Gen Attr_Clearance)
      ]

instance Arbitrary Attributes where
  arbitrary = do
    -- Ensure OIDs are unique
    attrs <- nubBy (on (==) attrType) <$> listOf1NonEmpty arbitrary
    return $ Attributes attrs

-- Top-level AC Info
instance Arbitrary AttributeCertificateInfo where
  arbitrary =
    AttributeCertificateInfo
      <$> pure 1 -- version is v2(1)
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> (getPositive <$> arbitrary) -- Serial number must be positive
      <*> arbitrary
      <*> arbitrary -- list of attributes
      <*> pure Nothing -- issuer unique id
      <*> arbitrary -- extensions

-- For AttributeRaw, we need a simple ASN1 generator
instance Arbitrary ASN1 where
  arbitrary = oneof [IntVal <$> arbitrary, OctetString <$> arbitraryBS 1 10]

instance Arbitrary Raw.AttributeRaw where
  arbitrary = Raw.AttributeRaw <$> arbitrary <*> listOf1NonEmpty arbitrary

-- Properties

property_unmarshall_marshall_id :: (Show o, Eq o, ASN1Object o) => o -> Bool
property_unmarshall_marshall_id o =
  case fromASN1 (toASN1 o []) of
    Right (gotObject, []) -> gotObject == o
    _ -> False

prop_attribute_roundtrip :: (Show a, Eq a, IsAttribute a) => [a] -> Property
prop_attribute_roundtrip values =
  not (null values)
    ==> let attribute = encodeAttribute values
            attributes = Attributes [attribute]
            mDecoded = getAttributeE attributes
         in case mDecoded of
              Just (Right decodedValues) -> decodedValues === values
              _ -> counterexample "Failed to decode attribute" False

-- Test Tree

tests :: TestTree
tests =
  testGroup
    "Attribute Certificate Tests"
    [ testGroup
        "ASN.1 Marshalling"
        [ testProperty "AttCertValidityPeriod" (property_unmarshall_marshall_id :: AttCertValidityPeriod -> Bool),
          testProperty "ObjectDigestInfo" (property_unmarshall_marshall_id :: ObjectDigestInfo -> Bool),
          testProperty "IssuerSerial" (property_unmarshall_marshall_id :: IssuerSerial -> Bool),
          testProperty "V2Form" (property_unmarshall_marshall_id :: V2Form -> Bool),
          testProperty "Holder" (property_unmarshall_marshall_id :: Holder -> Bool),
          testProperty "AttCertIssuer" (property_unmarshall_marshall_id :: AttCertIssuer -> Bool),
          testProperty "Attributes" (property_unmarshall_marshall_id :: Attributes -> Bool),
          testProperty "AttributeCertificateInfo" (property_unmarshall_marshall_id :: AttributeCertificateInfo -> Bool),
          testProperty "AttributeRaw" (property_unmarshall_marshall_id :: Raw.AttributeRaw -> Bool)
        ],
      testGroup
        "Attribute Encoding/Decoding"
        [ testProperty "Role" (prop_attribute_roundtrip :: [Attr_Role] -> Property),
          testProperty "Service Auth Info" (prop_attribute_roundtrip :: [Attr_SvceAuthInfo] -> Property),
          testProperty "Access Identity" (prop_attribute_roundtrip :: [Attr_AccessIdentity] -> Property),
          testProperty "Charging Identity" (prop_attribute_roundtrip :: [Attr_ChargingIdentity] -> Property),
          testProperty "Group" (prop_attribute_roundtrip :: [Attr_Group] -> Property),
          testProperty "Clearance" (prop_attribute_roundtrip :: [Attr_Clearance] -> Property)
        ]
    ]
