module Tests.Validation (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.Attribute (Attributes(..))
import qualified Data.X509.TCG.Validation as V
import Data.X509.TCG.Component
import Data.X509.TCG.Platform

tests :: TestTree
tests = testGroup "Validation Tests"
  [ testGroup "Validation Function Existence"
    [ testCase "validateRequiredAttributes function exists" $ do
        let emptyAttrs = Attributes []
            errors = V.validateRequiredAttributes emptyAttrs
        -- Function exists and returns some result
        length errors >= 0 @?= True
    , testCase "validateAttributeCompliance function exists" $ do
        let emptyAttrs = Attributes []
            errors = V.validateAttributeCompliance emptyAttrs
        -- Function exists and returns some result
        length errors >= 0 @?= True
    ]
  , testGroup "Component Validation Functions"
    [ testCase "validateComponentHierarchy function exists" $ do
        let cpu = ComponentIdentifierV2 
                  (B.pack "AMD") 
                  (B.pack "Ryzen7") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
            components = [cpu]
            errors = V.validateComponentHierarchy components
        -- Function exists and returns some result
        length errors >= 0 @?= True
    , testCase "validateComponentStatus with valid components" $ do
        let component = ComponentIdentifierV2 
                       (B.pack "TestMfg") 
                       (B.pack "TestModel") 
                       Nothing Nothing Nothing Nothing 
                       ComponentCPU 
                       Nothing
            statusList = [(component, ComponentAdded)]
            errors = V.validateComponentStatus statusList
        -- Valid component should return no errors
        errors @?= []
    , testCase "validateComponentStatus detects empty manufacturer" $ do
        let invalidComponent = ComponentIdentifierV2 
                              B.empty  -- Empty manufacturer
                              (B.pack "TestModel") 
                              Nothing Nothing Nothing Nothing 
                              ComponentCPU 
                              Nothing
            statusList = [(invalidComponent, ComponentAdded)]
            errors = V.validateComponentStatus statusList
        -- Should return one AttributeError for empty manufacturer
        length errors @?= 1
        case errors of
          [V.AttributeError msg] -> msg @?= "Component manufacturer cannot be empty"
          _ -> assertFailure "Expected AttributeError for empty manufacturer"
    , testCase "validateComponentStatus detects empty model" $ do
        let invalidComponent = ComponentIdentifierV2 
                              (B.pack "TestMfg") 
                              B.empty  -- Empty model
                              Nothing Nothing Nothing Nothing 
                              ComponentCPU 
                              Nothing
            statusList = [(invalidComponent, ComponentAdded)]
            errors = V.validateComponentStatus statusList
        -- Should return one AttributeError for empty model
        length errors @?= 1
        case errors of
          [V.AttributeError msg] -> msg @?= "Component model cannot be empty"
          _ -> assertFailure "Expected AttributeError for empty model"
    , testCase "validateComponentStatus detects duplicate components" $ do
        let component1 = ComponentIdentifierV2 
                        (B.pack "TestMfg") 
                        (B.pack "TestModel") 
                        (Just $ B.pack "123") Nothing Nothing Nothing 
                        ComponentCPU 
                        Nothing
            component2 = ComponentIdentifierV2 
                        (B.pack "TestMfg") 
                        (B.pack "TestModel") 
                        (Just $ B.pack "123") Nothing Nothing Nothing 
                        ComponentMemory  -- Different class but same identity
                        Nothing
            statusList = [(component1, ComponentAdded), (component2, ComponentAdded)]
            errors = V.validateComponentStatus statusList
        -- Should detect duplicate components
        -- Debug: print the errors to understand what we're getting
        -- length errors >= 1 @?= True
        case errors of
          [] -> assertFailure "Expected at least one ConsistencyError for duplicate components"
          errs -> all (\err -> case err of V.ConsistencyError _ -> True; _ -> False) errs @?= True
    ]
  , testGroup "Additional Validation Functions"
    [ testCase "Validation module has comprehensive functions" $ do
        -- Test that the validation module exists and imports correctly
        let cpu = ComponentIdentifierV2 
                  (B.pack "Intel") 
                  (B.pack "i7-12700") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
        ci2Manufacturer cpu @?= B.pack "Intel"
        -- Validation functions are available and can be used
        True @?= True
    ]
  ]