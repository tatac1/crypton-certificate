{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Tasty
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B

import Arbitrary
import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.Types
import Data.Char (digitToInt)
import Data.List (nub, sort)
import Data.X509
import qualified TestAC

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

-- Per-family AlgorithmIdentifier parameters contract:
-- ECDSA (RFC 5758 3.2, RFC 3279 2.2.3) and DSA (RFC 5758 3.1, RFC 3279
-- 2.2.2) omit the parameters field; RSA PKCS#1 v1.5 encodes an ASN.1
-- NULL (RFC 3279 2.2.1); EdDSA omits the field (RFC 8410 3).
property_sig_alg_parameters :: SignatureALG -> Bool
property_sig_alg_parameters alg@(SignatureALG _ pub)
    | pub == PubKeyALG_EC || pub == PubKeyALG_DSA = Null `notElem` toASN1 alg []
    | pub == PubKeyALG_RSA = Null `elem` toASN1 alg []
property_sig_alg_parameters alg@(SignatureALG_IntrinsicHash _) =
    Null `notElem` toASN1 alg []
property_sig_alg_parameters _ = True

hexBS :: String -> B.ByteString
hexBS = B.pack . go
  where
    go (hi : lo : xs) = fromIntegral (digitToInt hi * 16 + digitToInt lo) : go xs
    go _ = []

-- GeneralNames with a single directoryName, as encoded by OpenSSL:
--   openssl req -x509 -newkey ed25519 \
--     -subj "/CN=Vector Test" -addext "subjectAltName=dirName:dir_sect"
--   with [dir_sect] C = JP, O = Example Org, CN = Directory Name Test
-- The directoryName [4] tag is constructed (0xA4) because Name is a CHOICE,
-- making the context tag EXPLICIT (RFC 5280 4.2.1.6 and appendix A.2).
opensslDirNameSAN :: B.ByteString
opensslDirNameSAN =
    hexBS $
        "3045A4433041310B3009060355040613024A5031143012060355040A0C0B"
            ++ "4578616D706C65204F7267311C301A06035504030C134469726563746F72"
            ++ "79204E616D652054657374"

-- The same GeneralNames with directoryName under a primitive [4] tag (0x84),
-- as produced by crypton-x509 1.9.1; still accepted when decoding for
-- backward compatibility.
legacyDirNameSAN :: B.ByteString
legacyDirNameSAN =
    hexBS $
        "304584433041310B3009060355040613024A5031143012060355040A0C0B"
            ++ "4578616D706C65204F7267311C301A06035504030C134469726563746F72"
            ++ "79204E616D652054657374"

dirNameDN :: DistinguishedName
dirNameDN =
    DistinguishedName
        [ ([2, 5, 4, 6], asn1CharacterString Printable "JP")
        , ([2, 5, 4, 10], asn1CharacterString UTF8 "Example Org")
        , ([2, 5, 4, 3], asn1CharacterString UTF8 "Directory Name Test")
        ]

dirNameSAN :: ExtSubjectAltName
dirNameSAN = ExtSubjectAltName [AltNameDN dirNameDN]

case_dirname_decode_openssl :: Bool
case_dirname_decode_openssl =
    extDecodeBs opensslDirNameSAN == Right dirNameSAN

case_dirname_encode_constructed :: Bool
case_dirname_encode_constructed =
    extEncodeBs dirNameSAN == opensslDirNameSAN

case_dirname_decode_legacy_primitive :: Bool
case_dirname_decode_legacy_primitive =
    extDecodeBs legacyDirNameSAN == Right dirNameSAN

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
                , testGroup
                    "signature-alg-parameters"
                    [ testProperty
                        "per-family"
                        property_sig_alg_parameters
                    ]
                , testGroup
                    "general-name-directoryname"
                    [ testProperty
                        "decodes-openssl-constructed"
                        case_dirname_decode_openssl
                    , testProperty
                        "encodes-constructed"
                        case_dirname_encode_constructed
                    , testProperty
                        "decodes-legacy-primitive"
                        case_dirname_decode_legacy_primitive
                    ]
                , testProperty
                    "extensions"
                    (property_unmarshall_marshall_id :: Extensions -> Bool)
                , testProperty
                    "certificate"
                    (property_unmarshall_marshall_id :: Certificate -> Bool)
                , testProperty "crl" (property_unmarshall_marshall_id :: CRL -> Bool)
                , TestAC.tests
                ]
            ]
