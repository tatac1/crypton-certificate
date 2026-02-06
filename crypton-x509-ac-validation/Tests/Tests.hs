{-# LANGUAGE CPP #-}
module Main (main) where

import Test.Tasty
import TestACValidation
import StaticTests
#ifdef SBV_TESTS
import qualified SBV
#endif

main :: IO ()
main = defaultMain allTests

allTests :: TestTree
allTests = testGroup "x509-ac-validation tests"
  [ tests  -- QuickCheck property tests from TestACValidation
  , staticTests  -- PKITS-style static tests from StaticTests
#ifdef SBV_TESTS
  , SBV.tests  -- SBV formal verification tests for RFC 5755
#endif
  ]
