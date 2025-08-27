module Tests.Delta (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.TCG.Delta
import Data.X509.TCG.Platform()
import Data.X509.TCG.Component

tests :: TestTree
tests = testGroup "Delta Platform Certificate Tests"
  [ testGroup "DeltaOperation" 
    [ testCase "DeltaOperation enumeration" $ do
        fromEnum DeltaAdd @?= 0
        fromEnum DeltaRemove @?= 1
        fromEnum DeltaModify @?= 2
        fromEnum DeltaReplace @?= 3
        fromEnum DeltaUpdate @?= 4
    ]
  , testGroup "ComponentDelta"
    [ testCase "ComponentDelta creation" $ do
        let comp = ComponentIdentifierV2 (B.pack "TestMfg") (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentCPU Nothing
            metadata = ChangeMetadata Nothing Nothing Nothing Nothing []
            delta = ComponentDelta DeltaAdd comp Nothing metadata
        cdOperation delta @?= DeltaAdd
        cdComponent delta @?= comp
        cdPreviousComponent delta @?= Nothing
    ]
  ]