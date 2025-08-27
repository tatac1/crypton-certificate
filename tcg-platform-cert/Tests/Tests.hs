module Main (main) where

import Test.Tasty

import qualified Tests.OID as OID
import qualified Tests.Platform as Platform  
import qualified Tests.Component as Component
import qualified Tests.Delta as Delta
import qualified Tests.Attributes as Attributes

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "TCG Platform Certificate Tests"
  [ OID.tests
  , Platform.tests
  , Component.tests
  , Delta.tests
  , Attributes.tests
  ]