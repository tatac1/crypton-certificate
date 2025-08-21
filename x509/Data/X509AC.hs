-- |
-- Module      : Data.X509.AC
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write X.509 Attribute Certificate and their signed equivalents.
--
-- Follows RFC5755
module Data.X509AC
  ( -- * Attribute Certificate types
    SignedAttributeCertificate,
    AttributeCertificateInfo (..),
    AttCertValidityPeriod (..),
    Holder (..),
    AttCertIssuer (..),
    module Data.X509.Attribute,
    module Data.X509.AttCert,

    -- * Accessors
    getAttributesCertificate,
    getHolder,
    getIssuer,
    getAttributes,
    getValidity,
    getSerialNumber,

    -- * Decoding
    decodeSignedAttributeCertificate,
  )
where

import qualified Data.ByteString as B
import Data.X509.AttCert
import Data.X509.Attribute
import Data.X509.Signed

-- | A Signed Attibute Certificate is a `SignedExact` of an `AttributeCertificateInfo`.
type SignedAttributeCertificate = SignedExact AttributeCertificateInfo

-- * Accessors

getAttributesCertificate :: SignedAttributeCertificate -> AttributeCertificateInfo
getAttributesCertificate = signedObject . getSigned

-- | Return the holder of the attribute certificate.
getHolder :: SignedAttributeCertificate -> Holder
getHolder = aciHolder . signedObject . getSigned

-- | Return the issuer of the attribute certificate.
getIssuer :: SignedAttributeCertificate -> AttCertIssuer
getIssuer = aciIssuer . signedObject . getSigned

-- | Return the attributes of the attribute certificate.
getAttributes :: SignedAttributeCertificate -> Attributes
getAttributes = aciAttributes . signedObject . getSigned

-- | Return the validity period of the attribute certificate.
getValidity :: SignedAttributeCertificate -> AttCertValidityPeriod
getValidity = aciValidity . signedObject . getSigned

-- | Return the serial number of the attribute certificate.
getSerialNumber :: SignedAttributeCertificate -> Integer
getSerialNumber = aciSerialNumber . signedObject . getSigned

-- | Try to decode a bytestring to a SignedCertificate
decodeSignedAttributeCertificate :: B.ByteString -> Either String SignedAttributeCertificate
decodeSignedAttributeCertificate = decodeSignedObject
