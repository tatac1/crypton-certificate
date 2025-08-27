{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Tasty
import Test.Tasty.QuickCheck

import Data.X509
import Data.ASN1.Types

import Arbitrary()
import qualified TestAC (tests)

property_unmarshall_marshall_id :: (Show o, Arbitrary o, ASN1Object o, Eq o) => o -> Bool
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

main :: IO ()
main =
  defaultMain $
    testGroup
      "X509"
      [ testGroup
          "marshall"
          [ testProperty "pubkey" (property_unmarshall_marshall_id :: PubKey -> Bool),
            testProperty "privkey" (property_unmarshall_marshall_id :: PrivKey -> Bool),
            testProperty
              "signature alg"
              (property_unmarshall_marshall_id :: SignatureALG -> Bool),
            testGroup
              "extension"
              [ testProperty "key-usage" (property_extension_id :: ExtKeyUsage -> Bool),
                testProperty
                  "extended-key-usage"
                  (property_extension_id :: ExtExtendedKeyUsage -> Bool)
              ],
            testProperty
              "extensions"
              (property_unmarshall_marshall_id :: Extensions -> Bool),
            testProperty
              "certificate"
              (property_unmarshall_marshall_id :: Certificate -> Bool),
            testProperty "crl" (property_unmarshall_marshall_id :: CRL -> Bool)
          ],
        TestAC.tests
      ]