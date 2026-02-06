{-# LANGUAGE LambdaCase #-}

-- |
-- Module      : Data.X509.AC.Validation.Validity
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Attribute Certificate validity period validation.
--
-- This module provides validity period checking for both:
--
-- * The Attribute Certificate itself (notBeforeTime / notAfterTime)
-- * The AA certificate that issued the AC (notBefore / notAfter)
--
-- == PKITS Test Coverage
--
-- This module covers tests AC-VAL-2.1 through AC-VAL-2.8:
--
-- * AC-VAL-2.1: AA certificate notBefore in future
-- * AC-VAL-2.2: AA certificate notAfter in past
-- * AC-VAL-2.3: AC notBeforeTime in future
-- * AC-VAL-2.4: AC notAfterTime in past
-- * AC-VAL-2.5: Valid period
-- * AC-VAL-2.6: Boundary - AC start time exact
-- * AC-VAL-2.7: Boundary - AC end time exact
-- * AC-VAL-2.8: GeneralizedTime format
module Data.X509.AC.Validation.Validity (
    -- * Validity Checking
    validateACValidity,
    validateACValidityPeriod,
    validateCertValidity,
    ValidityError (..),
    ValidityResult (..),
)
where

import Data.Hourglass (DateTime, Seconds (..), timeDiff)
import Data.X509 (Certificate (..), getSigned, signedObject)
import Data.X509.AttCert
import Data.X509AC (SignedAttributeCertificate)

-- | Errors related to validity period validation.
data ValidityError
    = -- | AA certificate notBefore is in the future
      AANotYetValid
        { aaNyvNotBefore :: DateTime
        -- ^ AA certificate notBefore time
        , aaNyvValidationTime :: DateTime
        -- ^ Time at which validation was performed
        }
    | -- | AA certificate notAfter is in the past
      AAExpired
        { aaExpNotAfter :: DateTime
        -- ^ AA certificate notAfter time
        , aaExpValidationTime :: DateTime
        -- ^ Time at which validation was performed
        }
    | -- | AC notBeforeTime is in the future
      ACNotYetValid
        { acNyvNotBeforeTime :: DateTime
        -- ^ AC notBeforeTime
        , acNyvValidationTime :: DateTime
        -- ^ Time at which validation was performed
        }
    | -- | AC notAfterTime is in the past
      ACExpired
        { acExpNotAfterTime :: DateTime
        -- ^ AC notAfterTime
        , acExpValidationTime :: DateTime
        -- ^ Time at which validation was performed
        }
    deriving (Show, Eq)

-- | Result of validity checking.
data ValidityResult
    = -- | Validation passed
      ValidityOK
    | -- | Validation failed with error
      ValidityFailed ValidityError
    deriving (Show, Eq)

-- | Validate both AC and AA certificate validity periods.
--
-- This function checks that at the given validation time:
--
-- 1. The AA certificate is valid (notBefore <= validationTime <= notAfter)
-- 2. The AC is valid (notBeforeTime <= validationTime <= notAfterTime)
--
-- Note: Boundary conditions are inclusive, meaning if the validation time
-- equals exactly the notBefore/notBeforeTime, the certificate is considered
-- valid. Similarly for notAfter/notAfterTime.
validateACValidity
    :: DateTime
    -- ^ Validation time
    -> Certificate
    -- ^ AA certificate
    -> SignedAttributeCertificate
    -- ^ Signed Attribute Certificate
    -> ValidityResult
validateACValidity validationTime aaCert signedAC =
    case validateCertValidity validationTime aaCert of
        ValidityFailed err -> ValidityFailed err
        ValidityOK ->
            let aci = signedObject (getSigned signedAC)
             in validateACValidityPeriod validationTime (aciValidity aci)

-- | Validate an AC's validity period.
--
-- Checks that: notBeforeTime <= validationTime <= notAfterTime
validateACValidityPeriod
    :: DateTime
    -- ^ Validation time
    -> AttCertValidityPeriod
    -- ^ AC validity period
    -> ValidityResult
validateACValidityPeriod validationTime (AttCertValidityPeriod notBefore notAfter)
    | isBefore validationTime notBefore =
        ValidityFailed $ ACNotYetValid notBefore validationTime
    | isAfter validationTime notAfter =
        ValidityFailed $ ACExpired notAfter validationTime
    | otherwise = ValidityOK

-- | Validate an AA certificate's validity period.
--
-- Checks that: notBefore <= validationTime <= notAfter
validateCertValidity
    :: DateTime
    -- ^ Validation time
    -> Certificate
    -- ^ AA certificate
    -> ValidityResult
validateCertValidity validationTime cert
    | isBefore validationTime notBefore =
        ValidityFailed $ AANotYetValid notBefore validationTime
    | isAfter validationTime notAfter =
        ValidityFailed $ AAExpired notAfter validationTime
    | otherwise = ValidityOK
  where
    (notBefore, notAfter) = certValidity cert

-- | Check if time1 is strictly before time2.
isBefore :: DateTime -> DateTime -> Bool
isBefore time1 time2 = timeDiff time1 time2 < Seconds 0

-- | Check if time1 is strictly after time2.
isAfter :: DateTime -> DateTime -> Bool
isAfter time1 time2 = timeDiff time1 time2 > Seconds 0
