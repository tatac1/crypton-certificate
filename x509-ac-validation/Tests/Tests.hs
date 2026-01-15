module Main (main) where

import Test.Tasty
import TestACValidation
import StaticTests
import qualified SBV

main :: IO ()
main = defaultMain allTests

allTests :: TestTree
allTests = testGroup "x509-ac-validation tests"
  [ tests  -- QuickCheck property tests from TestACValidation
  , staticTests  -- PKITS-style static tests from StaticTests
  , SBV.tests  -- SBV formal verification tests for RFC 5755
  ]
