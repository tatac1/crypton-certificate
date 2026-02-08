{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Tasty
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B

import Control.Applicative
import Control.Monad

import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.BitArray
import Data.ASN1.Types
import Data.List (nub, sort)
import Data.X509
import Data.X509AC

import Data.Hourglass

instance Arbitrary RSA.PublicKey where
    arbitrary = do
        bytes <- elements [64, 128, 256]
        e <- elements [0x3, 0x10001]
        n <- choose (2 ^ (8 * (bytes - 1)), 2 ^ (8 * bytes))
        return $
            RSA.PublicKey
                { RSA.public_size = bytes
                , RSA.public_n = n
                , RSA.public_e = e
                }

instance Arbitrary DSA.Params where
    arbitrary = DSA.Params <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary DSA.PublicKey where
    arbitrary = DSA.PublicKey <$> arbitrary <*> arbitrary

instance Arbitrary X25519.PublicKey where
    arbitrary = X25519.toPublic <$> arbitrary

instance Arbitrary X448.PublicKey where
    arbitrary = X448.toPublic <$> arbitrary

instance Arbitrary Ed25519.PublicKey where
    arbitrary = Ed25519.toPublic <$> arbitrary

instance Arbitrary Ed448.PublicKey where
    arbitrary = Ed448.toPublic <$> arbitrary

instance Arbitrary PubKey where
    arbitrary =
        oneof
            [ PubKeyRSA <$> arbitrary
            , PubKeyDSA <$> arbitrary
            , -- , PubKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PubKeyX25519 <$> arbitrary
            , PubKeyX448 <$> arbitrary
            , PubKeyEd25519 <$> arbitrary
            , PubKeyEd448 <$> arbitrary
            ]

instance Arbitrary RSA.PrivateKey where
    arbitrary =
        RSA.PrivateKey
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary DSA.PrivateKey where
    arbitrary = DSA.PrivateKey <$> arbitrary <*> arbitrary

instance Arbitrary X25519.SecretKey where
    arbitrary = throwCryptoError . X25519.secretKey <$> arbitraryBS 32 32

instance Arbitrary X448.SecretKey where
    arbitrary = throwCryptoError . X448.secretKey <$> arbitraryBS 56 56

instance Arbitrary Ed25519.SecretKey where
    arbitrary = throwCryptoError . Ed25519.secretKey <$> arbitraryBS 32 32

instance Arbitrary Ed448.SecretKey where
    arbitrary = throwCryptoError . Ed448.secretKey <$> arbitraryBS 57 57

instance Arbitrary PrivKey where
    arbitrary =
        oneof
            [ PrivKeyRSA <$> arbitrary
            , PrivKeyDSA <$> arbitrary
            , -- , PrivKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PrivKeyX25519 <$> arbitrary
            , PrivKeyX448 <$> arbitrary
            , PrivKeyEd25519 <$> arbitrary
            , PrivKeyEd448 <$> arbitrary
            ]

instance Arbitrary HashALG where
    arbitrary =
        elements
            [HashMD2, HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512]

instance Arbitrary PubKeyALG where
    arbitrary = elements [PubKeyALG_RSA, PubKeyALG_DSA, PubKeyALG_EC, PubKeyALG_DH]

instance Arbitrary SignatureALG where
    -- unfortunately as the encoding of this is a single OID as opposed to two OID,
    -- the testing need to limit itself to Signature ALG that has been defined in the OID database.
    -- arbitrary = SignatureALG <$> arbitrary <*> arbitrary
    arbitrary =
        elements
            [ SignatureALG HashSHA1 PubKeyALG_RSA
            , SignatureALG HashMD5 PubKeyALG_RSA
            , SignatureALG HashMD2 PubKeyALG_RSA
            , SignatureALG HashSHA256 PubKeyALG_RSA
            , SignatureALG HashSHA384 PubKeyALG_RSA
            , SignatureALG HashSHA512 PubKeyALG_RSA
            , SignatureALG HashSHA224 PubKeyALG_RSA
            , SignatureALG HashSHA1 PubKeyALG_DSA
            , SignatureALG HashSHA224 PubKeyALG_DSA
            , SignatureALG HashSHA256 PubKeyALG_DSA
            , SignatureALG HashSHA224 PubKeyALG_EC
            , SignatureALG HashSHA256 PubKeyALG_EC
            , SignatureALG HashSHA384 PubKeyALG_EC
            , SignatureALG HashSHA512 PubKeyALG_EC
            , SignatureALG_IntrinsicHash PubKeyALG_Ed25519
            , SignatureALG_IntrinsicHash PubKeyALG_Ed448
            ]

arbitraryBS r1 r2 = choose (r1, r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

arbitraryPositive :: Gen Integer
arbitraryPositive = choose (1, 2 ^ (64 :: Int))

arbitraryAscii :: Gen String
arbitraryAscii = listOf1 $ elements (['a'..'z'] ++ ['0'..'9'])

arbitraryAltName :: Gen AltName
arbitraryAltName =
    oneof
        [ AltNameRFC822 <$> arbitraryAscii
        , AltNameDNS <$> arbitraryAscii
        , AltNameURI <$> (("https://" ++) <$> arbitraryAscii)
        , AltNameIP <$> arbitraryBS 4 4
        , AltDirectoryName <$> arbitrary
        ]

instance Arbitrary ASN1StringEncoding where
    arbitrary = elements [IA5, UTF8]

instance Arbitrary ASN1CharacterString where
    arbitrary = ASN1CharacterString <$> arbitrary <*> arbitraryBS 2 36

instance Arbitrary DistinguishedName where
    arbitrary = DistinguishedName <$> (choose (1, 5) >>= \l -> replicateM l arbitraryDE)
      where
        arbitraryDE = (,) <$> arbitrary <*> arbitrary

instance Arbitrary DateTime where
    arbitrary = timeConvert <$> (arbitrary :: Gen Elapsed)
instance Arbitrary Elapsed where
    arbitrary = Elapsed . Seconds <$> (choose (1, 100000000))

instance Arbitrary Extensions where
    arbitrary =
        Extensions
            <$> oneof
                [ pure Nothing
                , Just
                    <$> ( listOf1 $
                            oneof
                                [ extensionEncode <$> arbitrary <*> (arbitrary :: Gen ExtKeyUsage)
                                ]
                        )
                ]

instance Arbitrary ExtKeyUsageFlag where
    arbitrary = elements $ enumFrom KeyUsage_digitalSignature
instance Arbitrary ExtKeyUsage where
    arbitrary = ExtKeyUsage . sort . nub <$> listOf1 arbitrary

instance Arbitrary ExtKeyUsagePurpose where
    arbitrary =
        elements
            [ KeyUsagePurpose_ServerAuth
            , KeyUsagePurpose_ClientAuth
            , KeyUsagePurpose_CodeSigning
            , KeyUsagePurpose_EmailProtection
            , KeyUsagePurpose_TimeStamping
            , KeyUsagePurpose_OCSPSigning
            ]
instance Arbitrary ExtExtendedKeyUsage where
    arbitrary = ExtExtendedKeyUsage . nub <$> listOf1 arbitrary

-- AC Extension types
instance Arbitrary ExtNoRevAvail where
    arbitrary = pure ExtNoRevAvail

instance Arbitrary ExtAuditIdentity where
    arbitrary = ExtAuditIdentity <$> arbitraryBS 1 20

instance Arbitrary Target where
    arbitrary =
        oneof
            [ TargetName <$> arbitraryAltName
            , TargetGroup <$> arbitraryAltName
            ]

instance Arbitrary ExtTargetInformation where
    arbitrary = ExtTargetInformation <$> listOf1 arbitrary

-- AC core types
instance Arbitrary BitArray where
    arbitrary = do
        len <- choose (1, 8)
        bs <- B.pack <$> vectorOf len arbitrary
        unused <- choose (0, 7)
        pure $ toBitArray bs unused

instance Arbitrary DigestedObjectType where
    arbitrary = elements [OIDPublicKey, OIDPublicKeyCert, OIDOtherObjectTypes]

instance Arbitrary ObjectDigestInfo where
    arbitrary = do
        dot <- arbitrary
        oid <- case dot of
            OIDOtherObjectTypes -> Just <$> arbitrary
            _ -> pure Nothing
        alg <- arbitrary
        digest <- B.pack <$> vectorOf 32 arbitrary
        pure $ ObjectDigestInfo dot oid alg digest

instance Arbitrary IssuerSerial where
    arbitrary =
        IssuerSerial
            <$> listOf1 arbitraryAltName
            <*> arbitraryPositive
            <*> pure Nothing

instance Arbitrary Holder where
    arbitrary =
        Holder
            <$> arbitrary
            <*> oneof [pure Nothing, Just <$> listOf1 arbitraryAltName]
            <*> arbitrary

instance Arbitrary V2Form where
    arbitrary =
        V2Form
            <$> listOf1 arbitraryAltName
            <*> arbitrary
            <*> arbitrary

instance Arbitrary AttCertIssuer where
    arbitrary =
        oneof
            [ AttCertIssuerV1 <$> listOf1 arbitraryAltName
            , AttCertIssuerV2 <$> arbitrary
            ]

instance Arbitrary AttCertValidityPeriod where
    arbitrary = AttCertValidityPeriod <$> arbitrary <*> arbitrary

instance Arbitrary Attributes where
    arbitrary = do
        let mkRole uri = Attr_Role $ RoleSyntax Nothing (AltNameURI uri)
        uri <- ("https://" ++) <$> arbitraryAscii
        pure $ Attributes [encodeAttribute [mkRole uri]]

instance Arbitrary AttributeCertificateInfo where
    arbitrary =
        AttributeCertificateInfo 1
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitraryPositive
            <*> arbitrary
            <*> arbitrary
            <*> pure Nothing
            <*> pure (Extensions Nothing)

-- Attribute syntax types
instance Arbitrary RoleSyntax where
    arbitrary =
        RoleSyntax
            <$> pure Nothing
            <*> arbitraryAltName

instance Arbitrary Attr_Role where
    arbitrary = Attr_Role <$> arbitrary

instance Arbitrary SvceAuthInfo where
    arbitrary =
        SvceAuthInfo
            <$> arbitraryAltName
            <*> arbitraryAltName
            <*> oneof [pure Nothing, Just <$> arbitraryBS 1 20]

instance Arbitrary Attr_SvceAuthInfo where
    arbitrary = Attr_SvceAuthInfo <$> arbitrary

instance Arbitrary Attr_AccessIdentity where
    arbitrary = Attr_AccessIdentity <$> arbitrary

instance Arbitrary IetfAttrSyntaxValue where
    arbitrary =
        oneof
            [ IetfAttrSyntaxOctets <$> arbitraryBS 1 20
            , IetfAttrSyntaxOid <$> arbitrary
            , IetfAttrSyntaxString <$> arbitraryAscii
            ]

instance Arbitrary IetfAttrSyntax where
    arbitrary =
        IetfAttrSyntax
            <$> pure Nothing
            <*> listOf1 arbitrary

instance Arbitrary Attr_ChargingIdentity where
    arbitrary = Attr_ChargingIdentity <$> arbitrary

instance Arbitrary Attr_Group where
    arbitrary = Attr_Group <$> arbitrary

instance Arbitrary ClassListFlag where
    arbitrary = elements $ enumFrom ClassList_unmarked

instance Arbitrary Clearance where
    arbitrary =
        Clearance
            <$> arbitrary
            <*> (sort . nub <$> listOf1 arbitrary)
            <*> pure Nothing

instance Arbitrary Attr_Clearance where
    arbitrary = Attr_Clearance <$> arbitrary

instance Arbitrary Certificate where
    arbitrary =
        Certificate
            <$> pure 2
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary RevokedCertificate where
    arbitrary =
        RevokedCertificate
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary CRL where
    arbitrary =
        CRL
            <$> pure 1
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

property_unmarshall_marshall_id
    :: (Show o, Arbitrary o, ASN1Object o, Eq o) => o -> Bool
property_unmarshall_marshall_id o =
    case got of
        Right (gotObject, [])
            | gotObject == o -> True
            | otherwise ->
                error ("object is different: " ++ show gotObject ++ " expecting " ++ show o)
        Right (gotObject, l) ->
            error
                ( "state remaining: "
                    ++ show l
                    ++ " marshalled: "
                    ++ show oMarshalled
                    ++ " parsed: "
                    ++ show gotObject
                )
        Left e ->
            error
                ( "parsing failed: "
                    ++ show e
                    ++ " object: "
                    ++ show o
                    ++ " marshalled as: "
                    ++ show oMarshalled
                )
  where
    got = fromASN1 oMarshalled
    oMarshalled = toASN1 o []

property_extension_id :: (Show e, Eq e, Extension e) => e -> Bool
property_extension_id e = case extDecode (extEncode e) of
    Left err -> error err
    Right v
        | v == e -> True
        | otherwise -> error ("expected " ++ show e ++ " got: " ++ show v)

property_attribute_id
    :: (Show a, Eq a, IsAttribute a) => a -> Bool
property_attribute_id a =
    case attrDecode (head (attrEncode a)) of
        Right v
            | v == a -> True
            | otherwise ->
                error ("attribute is different: " ++ show v ++ " expecting " ++ show a)
        Left err ->
            error ("attribute decode failed: " ++ err ++ " for: " ++ show a)

main =
    defaultMain $
        testGroup
            "X509"
            [ testGroup
                "marshall"
                [ testProperty "pubkey" (property_unmarshall_marshall_id :: PubKey -> Bool)
                , testProperty "privkey" (property_unmarshall_marshall_id :: PrivKey -> Bool)
                , testProperty
                    "signature alg"
                    (property_unmarshall_marshall_id :: SignatureALG -> Bool)
                , testGroup
                    "extension"
                    [ testProperty "key-usage" (property_extension_id :: ExtKeyUsage -> Bool)
                    , testProperty
                        "extended-key-usage"
                        (property_extension_id :: ExtExtendedKeyUsage -> Bool)
                    ]
                , testProperty
                    "extensions"
                    (property_unmarshall_marshall_id :: Extensions -> Bool)
                , testProperty
                    "certificate"
                    (property_unmarshall_marshall_id :: Certificate -> Bool)
                , testProperty "crl" (property_unmarshall_marshall_id :: CRL -> Bool)
                , testGroup
                    "ac-extension"
                    [ testProperty "noRevAvail" (property_extension_id :: ExtNoRevAvail -> Bool)
                    , testProperty "auditIdentity" (property_extension_id :: ExtAuditIdentity -> Bool)
                    , testProperty "targetInformation" (property_extension_id :: ExtTargetInformation -> Bool)
                    ]
                , testGroup
                    "attribute-certificate"
                    [ testProperty
                        "attCertValidityPeriod"
                        (property_unmarshall_marshall_id :: AttCertValidityPeriod -> Bool)
                    , testProperty
                        "issuerSerial"
                        (property_unmarshall_marshall_id :: IssuerSerial -> Bool)
                    , testProperty
                        "objectDigestInfo"
                        (property_unmarshall_marshall_id :: ObjectDigestInfo -> Bool)
                    , testProperty
                        "holder"
                        (property_unmarshall_marshall_id :: Holder -> Bool)
                    , testProperty
                        "v2Form"
                        (property_unmarshall_marshall_id :: V2Form -> Bool)
                    , testProperty
                        "attCertIssuer"
                        (property_unmarshall_marshall_id :: AttCertIssuer -> Bool)
                    , testProperty
                        "attributeCertificateInfo"
                        (property_unmarshall_marshall_id :: AttributeCertificateInfo -> Bool)
                    ]
                , testGroup
                    "ac-attribute"
                    [ testProperty "role" (property_attribute_id :: Attr_Role -> Bool)
                    , testProperty "svceAuthInfo" (property_attribute_id :: Attr_SvceAuthInfo -> Bool)
                    , testProperty "accessIdentity" (property_attribute_id :: Attr_AccessIdentity -> Bool)
                    , testProperty "chargingIdentity" (property_attribute_id :: Attr_ChargingIdentity -> Bool)
                    , testProperty "group" (property_attribute_id :: Attr_Group -> Bool)
                    , testProperty "clearance" (property_attribute_id :: Attr_Clearance -> Bool)
                    ]
                ]
            ]
