module Tests.Attributes (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.X509.TCG.Attributes
import Data.X509.TCG.OID

tests :: TestTree  
tests = testGroup "TCG Attributes Tests"
  [ testGroup "Attribute OID Mapping"
    [ testCase "attributeOIDToType mappings" $ do
        attributeOIDToType tcg_at_platformConfiguration @?= "platformConfiguration"
        attributeOIDToType tcg_at_platformConfiguration_v2 @?= "platformConfiguration_v2"
        attributeOIDToType tcg_at_componentIdentifier @?= "componentIdentifier"
        attributeOIDToType tcg_at_componentIdentifier_v2 @?= "componentIdentifier_v2"
    ]
  , testGroup "Required Attributes"
    [ testCase "isRequiredAttribute checks" $ do
        isRequiredAttribute tcg_at_platformConfiguration_v2 @?= True
        isRequiredAttribute tcg_at_componentIdentifier_v2 @?= True
        isRequiredAttribute tcg_at_platformManufacturer @?= False
    ]
  , testGroup "Critical Attributes"
    [ testCase "isCriticalAttribute checks" $ do
        isCriticalAttribute tcg_ce_relevantCredentials @?= True
        isCriticalAttribute tcg_ce_relevantManifests @?= True
        isCriticalAttribute tcg_at_platformConfiguration_v2 @?= False
    ]
  ]