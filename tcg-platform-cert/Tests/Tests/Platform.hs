module Tests.Platform (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.TCG.Platform

tests :: TestTree
tests = testGroup "Platform Certificate Tests"
  [ testGroup "PlatformInfo"
    [ testCase "PlatformInfo creation" $ do
        let info = PlatformInfo (B.pack "TestMfg") (B.pack "TestModel") (B.pack "12345") (B.pack "1.0")
        piManufacturer info @?= B.pack "TestMfg"
        piModel info @?= B.pack "TestModel" 
        piSerial info @?= B.pack "12345"
        piVersion info @?= B.pack "1.0"
    ]
  , testGroup "TPMInfo"
    [ testCase "TPMInfo creation" $ do
        let version = TPMVersion 2 0 1 59
            spec = TPMSpecification (B.pack "2.0") 116 1
            info = TPMInfo (B.pack "TestTPM") version spec
        tpmModel info @?= B.pack "TestTPM"
    ]
  , testGroup "PlatformConfiguration"
    [ testCase "PlatformConfiguration creation" $ do
        let config = PlatformConfiguration (B.pack "TestMfg") (B.pack "TestModel") (B.pack "1.0") (B.pack "12345") []
        pcManufacturer config @?= B.pack "TestMfg"
        pcModel config @?= B.pack "TestModel"
        pcVersion config @?= B.pack "1.0"
        pcSerial config @?= B.pack "12345"
        pcComponents config @?= []
    ]
  ]