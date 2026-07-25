-- | Arbitrary instances and roundtrip properties shared between the
-- test modules of the test suite.
module Arbitrary (
    arbitraryBS,
    property_unmarshall_marshall_id,
    property_extension_id,
) where

import Test.Tasty.QuickCheck

import qualified Data.ByteString as B

import Control.Monad
import Data.ASN1.Types
import Data.X509

import Data.Hourglass

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
