module Tests.Component (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.TCG.Component

tests :: TestTree
tests = testGroup "Component Tests"
  [ testGroup "ComponentIdentifier"
    [ testCase "ComponentIdentifier creation" $ do
        let comp = ComponentIdentifier (B.pack "TestMfg") (B.pack "TestModel") (Just $ B.pack "12345") Nothing Nothing Nothing
        ciManufacturer comp @?= B.pack "TestMfg"
        ciModel comp @?= B.pack "TestModel"
        ciSerial comp @?= Just (B.pack "12345")
    ]
  , testGroup "ComponentClass" 
    [ testCase "Component class matching" $ do
        let comp = ComponentIdentifierV2 (B.pack "TestMfg") (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentCPU Nothing
        isComponentClass ComponentCPU comp @?= True
        isComponentClass ComponentMemory comp @?= False
    ]
  , testGroup "ComponentHierarchy"
    [ testCase "Component hierarchy validation" $ do
        let comp1 = ComponentIdentifierV2 (B.pack "TestMfg") (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentMotherboard Nothing
            tree = buildComponentTree [comp1]
            hierarchy = ComponentHierarchy [] tree
        validateComponentHierarchy hierarchy @?= []
    ]
  ]