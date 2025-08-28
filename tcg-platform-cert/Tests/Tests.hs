module Main (main) where

import Test.Tasty

import qualified Tests.OID as OID
import qualified Tests.Platform as Platform  
import qualified Tests.Component as Component
import qualified Tests.Delta as Delta
import qualified Tests.Attributes as Attributes
import qualified Tests.Operations as Operations
import qualified Tests.Validation as Validation
import qualified Tests.Utils as Utils
import qualified Tests.Properties as Properties

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "TCG Platform Certificate Tests"
  [ OID.tests
  , Platform.tests
  , Component.tests
  , Delta.tests
  , Attributes.tests
  , Operations.tests
  , Validation.tests
  , Utils.tests
  , Properties.tests
  ]