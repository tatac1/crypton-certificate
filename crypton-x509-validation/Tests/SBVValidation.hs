{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : SBVValidation 
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Simple SBV validation tests for X.509 certificate chains
--
-- This module contains basic tests to verify that the SBV-based formal
-- verification system works correctly for certificate chain validation.

module SBVValidation (
    sbvValidationTests,
    runSBVTests,
) where

import Data.SBV
import Data.X509.Validation.SBV
import Test.Tasty
import Test.Tasty.HUnit

-- | Main SBV validation test suite
sbvValidationTests :: TestTree
sbvValidationTests = 
    testGroup "SBV Certificate Chain Validation" 
        [ testGroup "Basic Tests" basicTests
        , testGroup "Basic Constraints" basicConstraintTests
        , testGroup "Time Validity" timeValidityTests
        , testGroup "Chain Structure" chainStructureTests
        , testGroup "Signature Validation" signatureTests
        , testGroup "RFC 5280 Compliance" rfc5280ComplianceTests
        ]

-- | Run SBV tests using Tasty
runSBVTests :: IO ()
runSBVTests = do
    putStrLn "=== SBV Certificate Chain Validation Tests ==="
    putStrLn "Use 'stack test' to run tests properly with Tasty framework."

-- | Basic SBV tests
basicTests :: [TestTree]
basicTests =
    [ testCase "Chain length validation works" testChainLengthBasic
    , testCase "SBV data structures compile" testSBVStructures
    ]

-- | Test that chain length validation works
testChainLengthBasic :: Assertion
testChainLengthBasic = do
    let chain = ChainProperty
            { chainCerts = []
            , chainLength = literal 2
            , chainTrustAnchor = undefined  -- Not used in length test
            , chainValidationTime = literal 1500000000
            }
    
    -- Test valid chain length
    result1 <- prove $ validChainLength chain
    case result1 of
        ThmResult (Unsatisfiable {}) -> return ()  -- Valid chain length should be provable
        _ -> assertFailure "Expected chain length validation to succeed"
    
    -- Test invalid chain length (empty chain)
    let emptyChain = chain { chainLength = literal 0 }
    result2 <- prove $ validChainLength emptyChain  
    case result2 of
        ThmResult (Unsatisfiable {}) -> assertFailure "Empty chain should be invalid"
        _ -> return ()  -- Expected to fail

-- | Test that SBV data structures compile and work
testSBVStructures :: Assertion
testSBVStructures = do
    -- Simple test to ensure the SBV types compile
    let cert = CertificateProperty
            { sbvCertValid = sTrue
            , sbvCertIssuerDN = literal "TestCA"
            , sbvCertSubjectDN = literal "TestCert"
            , sbvCertIsCA = sTrue
            , sbvCertCanSign = sTrue
            , sbvCertPathLength = literal (-1)
            , sbvCertNotBefore = literal 1000000000
            , sbvCertNotAfter = literal 2000000000
            , sbvCertKeyUsageCertSign = sTrue
            , sbvCertVersion = literal 3
            }
    
    let vp = ValidationProperty
            { vpChain = ChainProperty
                { chainCerts = [cert]
                , chainLength = literal 1
                , chainTrustAnchor = cert
                , chainValidationTime = literal 1500000000
                }
            , vpRequireExplicitPolicy = sFalse
            , vpInhibitAnyPolicy = sFalse
            , vpInhibitPolicyMapping = sFalse
            , vpPermittedNameSpaces = []
            , vpExcludedNameSpaces = []
            }
    
    -- Just test that it compiles and doesn't crash
    _result <- prove $ validCertificationPath vp
    -- Don't assert result, just ensure it runs
    return ()

-- | Basic constraint validation tests
basicConstraintTests :: [TestTree]
basicConstraintTests =
    [ testCase "Valid CA basic constraints" testValidCAConstraints
    , testCase "Invalid non-CA in chain" testInvalidNonCAInChain
    , testCase "Path length violation" testPathLengthViolation
    , testCase "Missing keyCertSign" testMissingKeyCertSign
    ]

-- | Test valid CA basic constraints
testValidCAConstraints :: Assertion
testValidCAConstraints = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        interCA = createConcreteCert "Root" "Inter" True True 1 3
        endEntity = createConcreteCert "Inter" "End" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, interCA, endEntity]
            , chainLength = literal 3
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validBasicConstraints chain
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- Valid constraints should be provable
        _ -> assertFailure "Expected valid CA constraints to be proven"

-- | Test invalid non-CA in intermediate position  
testInvalidNonCAInChain :: Assertion
testInvalidNonCAInChain = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        nonCA = createConcreteCert "Root" "NonCA" False False (-1) 3  -- Not a CA!
        endEntity = createConcreteCert "NonCA" "End" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, nonCA, endEntity]
            , chainLength = literal 3
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validBasicConstraints chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find counterexample
        _ -> assertFailure "Expected to find basic constraint violation"

-- | Test path length constraint violation
testPathLengthViolation :: Assertion  
testPathLengthViolation = do
    let rootCA = createConcreteCert "Root" "Root" True True 0 3  -- Path length = 0
        interCA = createConcreteCert "Root" "Inter" True True (-1) 3
        subCA = createConcreteCert "Inter" "Sub" True True (-1) 3  -- Violates path length
        endEntity = createConcreteCert "Sub" "End" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, interCA, subCA, endEntity]
            , chainLength = literal 4
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validBasicConstraints chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find violation
        _ -> assertFailure "Expected to find path length violation"

-- | Test missing keyCertSign in CA certificate
testMissingKeyCertSign :: Assertion
testMissingKeyCertSign = do
    let rootCA = createConcreteCert "Root" "Root" True False (-1) 3  -- Can't sign!
        endEntity = createConcreteCert "Root" "End" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, endEntity]
            , chainLength = literal 2
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validKeyUsage chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find key usage violation
        _ -> assertFailure "Expected to find key usage violation"

-- | Helper function to create concrete certificate properties
createConcreteCert :: String -> String -> Bool -> Bool -> Integer -> Integer -> CertificateProperty
createConcreteCert issuer subject isCA canSign pathLen version = CertificateProperty
    { sbvCertValid = sTrue
    , sbvCertIssuerDN = literal issuer
    , sbvCertSubjectDN = literal subject
    , sbvCertIsCA = if isCA then sTrue else sFalse
    , sbvCertCanSign = if canSign then sTrue else sFalse
    , sbvCertPathLength = literal pathLen
    , sbvCertNotBefore = literal 1000000000
    , sbvCertNotAfter = literal 2000000000
    , sbvCertKeyUsageCertSign = if canSign then sTrue else sFalse
    , sbvCertVersion = literal version
    }

-- | Time validity validation tests
timeValidityTests :: [TestTree]
timeValidityTests =
    [ testCase "Valid time ordering" testValidTimeOrdering
    , testCase "Expired certificate" testExpiredCertificate
    , testCase "Future certificate" testFutureCertificate
    , testCase "Complex time relationships" testComplexTimeRelationships
    ]

-- | Test valid time ordering
testValidTimeOrdering :: Assertion
testValidTimeOrdering = do
    let cert1 = createConcreteCertWithTime "Root" "Root" True True (-1) 3 1000000000 2000000000
        cert2 = createConcreteCertWithTime "Root" "End" False False (-1) 3 1200000000 1800000000
        
        chain = ChainProperty
            { chainCerts = [cert1, cert2]
            , chainLength = literal 2
            , chainTrustAnchor = cert1
            , chainValidationTime = literal 1500000000  -- Within valid range
            }
    
    result <- prove $ validTimeOrdering chain
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- Valid time ordering should be provable
        _ -> assertFailure "Expected valid time ordering to be proven"

-- | Test expired certificate detection
testExpiredCertificate :: Assertion
testExpiredCertificate = do
    let expiredCert = createConcreteCertWithTime "Root" "Expired" False False (-1) 3 1000000000 1400000000  -- Expired
        
        chain = ChainProperty
            { chainCerts = [expiredCert]
            , chainLength = literal 1
            , chainTrustAnchor = expiredCert
            , chainValidationTime = literal 1500000000  -- After expiry
            }
    
    result <- prove $ validTimeOrdering chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find time violation
        _ -> assertFailure "Expected to find expired certificate"

-- | Test future certificate detection  
testFutureCertificate :: Assertion
testFutureCertificate = do
    let futureCert = createConcreteCertWithTime "Root" "Future" False False (-1) 3 1600000000 2000000000  -- Future
        
        chain = ChainProperty
            { chainCerts = [futureCert]
            , chainLength = literal 1
            , chainTrustAnchor = futureCert
            , chainValidationTime = literal 1500000000  -- Before valid time
            }
    
    result <- prove $ validTimeOrdering chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find time violation
        _ -> assertFailure "Expected to find future certificate"

-- | Test complex time relationships
testComplexTimeRelationships :: Assertion
testComplexTimeRelationships = do
    let cert1 = createConcreteCertWithTime "Root" "Root" True True (-1) 3 800000000 1800000000
        cert2 = createConcreteCertWithTime "Root" "Inter" True True 1 3 1000000000 1700000000
        cert3 = createConcreteCertWithTime "Inter" "End" False False (-1) 3 1200000000 1600000000
        
        chain = ChainProperty
            { chainCerts = [cert1, cert2, cert3]
            , chainLength = literal 3
            , chainTrustAnchor = cert1
            , chainValidationTime = literal 1500000000  -- All should be valid at this time
            }
    
    result <- prove $ validTimeOrdering chain
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- All valid times should be provable
        _ -> assertFailure "Expected complex time relationships to be valid"

-- | Helper function to create certificate with specific time constraints
createConcreteCertWithTime :: String -> String -> Bool -> Bool -> Integer -> Integer -> Integer -> Integer -> CertificateProperty
createConcreteCertWithTime issuer subject isCA canSign pathLen version notBefore notAfter = CertificateProperty
    { sbvCertValid = sTrue
    , sbvCertIssuerDN = literal issuer
    , sbvCertSubjectDN = literal subject
    , sbvCertIsCA = if isCA then sTrue else sFalse
    , sbvCertCanSign = if canSign then sTrue else sFalse
    , sbvCertPathLength = literal pathLen
    , sbvCertNotBefore = literal notBefore
    , sbvCertNotAfter = literal notAfter
    , sbvCertKeyUsageCertSign = if canSign then sTrue else sFalse
    , sbvCertVersion = literal version
    }

-- | Chain structure validation tests
chainStructureTests :: [TestTree]
chainStructureTests =
    [ testCase "Valid issuer-subject chaining" testValidIssuerSubjectChaining
    , testCase "Broken chaining" testBrokenChaining
    , testCase "Single certificate chain" testSingleCertificateChain
    , testCase "Complex multi-level chain" testComplexMultiLevelChain
    , testCase "Cross-signed enterprise PKI" testCrossSignedEnterpriseChain
    ]

-- | Test valid issuer-subject chaining
testValidIssuerSubjectChaining :: Assertion
testValidIssuerSubjectChaining = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        interCA = createConcreteCert "Root" "Inter" True True 1 3  -- Issued by Root
        endEntity = createConcreteCert "Inter" "End" False False (-1) 3  -- Issued by Inter
        
        chain = ChainProperty
            { chainCerts = [rootCA, interCA, endEntity]
            , chainLength = literal 3
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validIssuerSubjectChaining chain
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- Valid chaining should be provable
        _ -> assertFailure "Expected valid issuer-subject chaining to be proven"

-- | Test broken chaining (issuer doesn't match subject)
testBrokenChaining :: Assertion
testBrokenChaining = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        interCA = createConcreteCert "Wrong" "Inter" True True 1 3  -- Wrong issuer!
        endEntity = createConcreteCert "Inter" "End" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, interCA, endEntity]
            , chainLength = literal 3
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validIssuerSubjectChaining chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find chaining violation
        _ -> assertFailure "Expected to find broken chaining"

-- | Test single certificate chain (self-signed)
testSingleCertificateChain :: Assertion
testSingleCertificateChain = do
    let selfSigned = createConcreteCert "SelfSigned" "SelfSigned" True True (-1) 3
        
        chain = ChainProperty
            { chainCerts = [selfSigned]
            , chainLength = literal 1
            , chainTrustAnchor = selfSigned
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validIssuerSubjectChaining chain
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- Self-signed should be valid
        _ -> assertFailure "Expected self-signed certificate to be valid"

-- | Test complex multi-level chain (realistic enterprise/government PKI scenario)
testComplexMultiLevelChain :: Assertion
testComplexMultiLevelChain = do
    -- Create a realistic 6-level enterprise PKI chain with cross-signing capability
    -- This simulates government/enterprise PKI with policy and issuing CAs
    let rootCA = createConcreteCert "Gov-Root" "Gov-Root" True True 5 3           -- pathLength=5 (allows deep hierarchy)
        policyCA = createConcreteCert "Gov-Root" "Gov-Policy" True True 3 3       -- pathLength=3 (policy level)
        issuingCA = createConcreteCert "Gov-Policy" "Gov-Issuing" True True 1 3   -- pathLength=1 (issuing level)
        deptCA = createConcreteCert "Gov-Issuing" "Dept-CA" True True 0 3         -- pathLength=0 (final CA level)
        end = createConcreteCert "Dept-CA" "Employee" False False (-1) 3          -- End entity
        
        chain = ChainProperty
            { chainCerts = [rootCA, policyCA, issuingCA, deptCA, end]
            , chainLength = literal 5
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    -- Test all validation properties for complex chain
    result1 <- prove $ validIssuerSubjectChaining chain
    result2 <- prove $ validBasicConstraints chain
    result3 <- prove $ validKeyUsage chain
    
    case (result1, result2, result3) of
        (ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {})) -> 
            return ()  -- All should be valid
        _ -> assertFailure "Expected complex chain to satisfy all validation properties"

-- | Test cross-signed enterprise PKI chain (realistic scenario)
testCrossSignedEnterpriseChain :: Assertion
testCrossSignedEnterpriseChain = do
    -- Simulate a realistic cross-signed enterprise scenario:
    -- Company A Root -> Company A Policy -> Company A Issuing -> Employee
    -- Plus potential cross-signing with Company B (longer paths possible)
    -- This represents a 7-level potential path in cross-signed environment
    let companyARootCA = createConcreteCert "CompanyA-Root" "CompanyA-Root" True True 6 3      -- pathLength=6 (allows deep cross-signing)
        companyAPolicyCA = createConcreteCert "CompanyA-Root" "CompanyA-Policy" True True 4 3  -- pathLength=4 (policy level)
        companyAIssuingCA = createConcreteCert "CompanyA-Policy" "CompanyA-Issuing" True True 2 3 -- pathLength=2 (issuing level)
        companyADeptCA = createConcreteCert "CompanyA-Issuing" "CompanyA-Dept" True True 0 3   -- pathLength=0 (department level)
        employee = createConcreteCert "CompanyA-Dept" "Employee-John" False False (-1) 3       -- End entity
        
        chain = ChainProperty
            { chainCerts = [companyARootCA, companyAPolicyCA, companyAIssuingCA, companyADeptCA, employee]
            , chainLength = literal 5
            , chainTrustAnchor = companyARootCA
            , chainValidationTime = literal 1500000000
            }
    
    -- Test all validation properties for cross-signed enterprise chain
    result1 <- prove $ validIssuerSubjectChaining chain
    result2 <- prove $ validBasicConstraints chain
    result3 <- prove $ validKeyUsage chain
    
    case (result1, result2, result3) of
        (ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {})) -> 
            return ()  -- All should be valid in this realistic scenario
        _ -> assertFailure "Expected cross-signed enterprise chain to satisfy all validation properties"

-- | Signature validation tests
signatureTests :: [TestTree]
signatureTests =
    [ testCase "Valid signature chain" testValidSignatureChain
    , testCase "Invalid signature in chain" testInvalidSignatureInChain
    , testCase "Unsigned certificate" testUnsignedCertificate
    , testCase "Wrong signing key" testWrongSigningKey
    ]

-- | Test valid signature chain
testValidSignatureChain :: Assertion
testValidSignatureChain = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        interCA = createConcreteCert "Root" "Inter" True True 1 3
        endEntity = createConcreteCert "Inter" "End" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, interCA, endEntity]
            , chainLength = literal 3
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validSignatureChain chain
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- Valid signatures should be provable
        _ -> assertFailure "Expected valid signature chain to be proven"

-- | Test invalid signature in chain
testInvalidSignatureInChain :: Assertion
testInvalidSignatureInChain = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        invalidCert = (createConcreteCert "Root" "Invalid" False False (-1) 3) 
            { sbvCertValid = sFalse }  -- Invalid certificate
        
        chain = ChainProperty
            { chainCerts = [rootCA, invalidCert]
            , chainLength = literal 2
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validSignatureChain chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find signature violation
        _ -> assertFailure "Expected to find signature violation"

-- | Test unsigned certificate
testUnsignedCertificate :: Assertion
testUnsignedCertificate = do
    let signingCA = createConcreteCert "Root" "Root" True False (-1) 3  -- Can't sign
        unsignedCert = createConcreteCert "Root" "Unsigned" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [signingCA, unsignedCert]
            , chainLength = literal 2
            , chainTrustAnchor = signingCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validSignatureChain chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find signing capability violation
        _ -> assertFailure "Expected to find unsigned certificate violation"

-- | Test wrong signing key
testWrongSigningKey :: Assertion
testWrongSigningKey = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        wrongSigner = createConcreteCert "Wrong" "Wrong" True True (-1) 3
        signedByWrong = createConcreteCert "Wrong" "Victim" False False (-1) 3
        
        chain = ChainProperty
            { chainCerts = [rootCA, signedByWrong]  -- Missing wrongSigner in chain
            , chainLength = literal 2
            , chainTrustAnchor = rootCA
            , chainValidationTime = literal 1500000000
            }
    
    result <- prove $ validIssuerSubjectChaining chain
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find chaining violation
        _ -> assertFailure "Expected to find wrong signing key violation"

-- | RFC 5280 compliance tests
rfc5280ComplianceTests :: [TestTree]
rfc5280ComplianceTests =
    [ testCase "Complete valid certification path" testCompleteValidCertificationPath
    , testCase "Multiple validation violations" testMultipleValidationViolations
    , testCase "Version compliance (X.509 v3)" testVersionCompliance
    , testCase "End-to-end validation" testEndToEndValidation
    ]

-- | Test complete valid certification path
testCompleteValidCertificationPath :: Assertion
testCompleteValidCertificationPath = do
    let rootCA = createConcreteCert "Root" "Root" True True (-1) 3
        interCA = createConcreteCert "Root" "Inter" True True 1 3
        endEntity = createConcreteCert "Inter" "End" False False (-1) 3
        
        vp = ValidationProperty
            { vpChain = ChainProperty
                { chainCerts = [rootCA, interCA, endEntity]
                , chainLength = literal 3
                , chainTrustAnchor = rootCA
                , chainValidationTime = literal 1500000000
                }
            , vpRequireExplicitPolicy = sFalse
            , vpInhibitAnyPolicy = sFalse
            , vpInhibitPolicyMapping = sFalse
            , vpPermittedNameSpaces = []
            , vpExcludedNameSpaces = []
            }
    
    result <- prove $ validCertificationPath vp
    case result of
        ThmResult (Unsatisfiable {}) -> return ()  -- Complete path should be valid
        _ -> assertFailure "Expected complete certification path to be valid"

-- | Test multiple validation violations in single chain
testMultipleValidationViolations :: Assertion
testMultipleValidationViolations = do
    let badCert = CertificateProperty
            { sbvCertValid = sFalse              -- Invalid
            , sbvCertIssuerDN = literal "Root"
            , sbvCertSubjectDN = literal "Bad"
            , sbvCertIsCA = sFalse               -- Not CA but in intermediate position
            , sbvCertCanSign = sFalse            -- Can't sign
            , sbvCertPathLength = literal (-1)
            , sbvCertNotBefore = literal 1600000000  -- Future certificate
            , sbvCertNotAfter = literal 2000000000
            , sbvCertKeyUsageCertSign = sFalse
            , sbvCertVersion = literal 2         -- Wrong version
            }
        
        vp = ValidationProperty
            { vpChain = ChainProperty
                { chainCerts = [badCert]
                , chainLength = literal 1
                , chainTrustAnchor = badCert
                , chainValidationTime = literal 1500000000
                }
            , vpRequireExplicitPolicy = sFalse
            , vpInhibitAnyPolicy = sFalse
            , vpInhibitPolicyMapping = sFalse
            , vpPermittedNameSpaces = []
            , vpExcludedNameSpaces = []
            }
    
    result <- prove $ validCertificationPath vp
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find multiple violations
        _ -> assertFailure "Expected to find multiple validation violations"

-- | Test version compliance (X.509 v3)
testVersionCompliance :: Assertion
testVersionCompliance = do
    let v2Cert = createConcreteCert "Root" "V2Cert" True True (-1) 2  -- Wrong version
        
        vp = ValidationProperty
            { vpChain = ChainProperty
                { chainCerts = [v2Cert]
                , chainLength = literal 1
                , chainTrustAnchor = v2Cert
                , chainValidationTime = literal 1500000000
                }
            , vpRequireExplicitPolicy = sFalse
            , vpInhibitAnyPolicy = sFalse
            , vpInhibitPolicyMapping = sFalse
            , vpPermittedNameSpaces = []
            , vpExcludedNameSpaces = []
            }
    
    result <- prove $ validCertificationPath vp
    case result of
        ThmResult (Satisfiable {}) -> return ()  -- Should find version violation
        _ -> assertFailure "Expected to find version violation"

-- | Test end-to-end validation with all properties
testEndToEndValidation :: Assertion
testEndToEndValidation = do
    let root = createConcreteCert "RootCA" "RootCA" True True 2 3
        inter = createConcreteCert "RootCA" "InterCA" True True 1 3
        end = createConcreteCert "InterCA" "EndEntity" False False (-1) 3
        
        vp = ValidationProperty
            { vpChain = ChainProperty
                { chainCerts = [root, inter, end]
                , chainLength = literal 3
                , chainTrustAnchor = root
                , chainValidationTime = literal 1500000000
                }
            , vpRequireExplicitPolicy = sFalse
            , vpInhibitAnyPolicy = sFalse
            , vpInhibitPolicyMapping = sFalse
            , vpPermittedNameSpaces = []
            , vpExcludedNameSpaces = []
            }
    
    -- Test individual properties
    result1 <- prove $ validChainLength (vpChain vp)
    result2 <- prove $ validTimeOrdering (vpChain vp)
    result3 <- prove $ validIssuerSubjectChaining (vpChain vp)
    result4 <- prove $ validBasicConstraints (vpChain vp)
    result5 <- prove $ validKeyUsage (vpChain vp)
    result6 <- prove $ validSignatureChain (vpChain vp)
    
    -- Test complete validation
    resultComplete <- prove $ validCertificationPath vp
    
    case (result1, result2, result3, result4, result5, result6, resultComplete) of
        (ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {}),
         ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {}), ThmResult (Unsatisfiable {}),
         ThmResult (Unsatisfiable {})) -> 
            return ()  -- All properties should be valid
        _ -> assertFailure "Expected all validation properties to be satisfied"