{-# LANGUAGE InstanceSigs #-}

-- |
-- Module      : Data.X509.AttributeRaw
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Raw (undecoded) Attribute Certificate attributes.
--
-- This module provides low-level access to attribute data before it is
-- parsed into specific attribute types. This is useful for handling
-- unknown or custom attribute types that may not have specific parsers.
module Data.X509.AttributeRaw
  ( -- * Raw Attribute Types
    AttributeRaw (..),
    Attributes (..),

    -- * Raw ASN1 Access
    tryAttRawASN1,
    attRawASN1,
  )
where

import Data.ASN1.Parse
import Data.ASN1.Types
import Data.X509.Internal

-- | An undecoded attribute containing raw ASN.1 data.
--
-- This represents an attribute before it has been parsed into a specific
-- attribute type. It contains the OID that identifies the attribute type
-- and the raw ASN.1 values.
data AttributeRaw = AttributeRaw
  { attrRawOID :: OID, -- ^ The Object Identifier for this attribute type
    attrRawValues :: [ASN1] -- ^ The raw ASN.1 values (content of the SET OF)
  }
  deriving (Show, Eq)

instance ASN1Object AttributeRaw where
  fromASN1 :: [ASN1] -> Either String (AttributeRaw, [ASN1])
  fromASN1 = runParseASN1State parseAttributeRaw
    where
      parseAttributeRaw =
        onNextContainer Sequence $ do
          oid <- getNext >>= \n -> case n of
            OID o -> return o
            _ -> throwParseError "Expected OID for attribute type"
          values <- onNextContainer Set (getMany getNext)
          return $ AttributeRaw oid values

  toASN1 :: AttributeRaw -> ASN1S
  toASN1 (AttributeRaw oid values) xs =
    asn1Container Sequence (OID oid : asn1Container Set values) ++ xs

-- | Safely extract the raw ASN.1 values from an AttributeRaw.
--
-- This function always succeeds and returns the raw ASN.1 values.
tryAttRawASN1 :: AttributeRaw -> Either String [ASN1]
tryAttRawASN1 = Right . attrRawValues

-- | Extract the raw ASN.1 values from an AttributeRaw.
--
-- This is a convenience function that extracts the ASN.1 values.
-- Since the extraction cannot fail for well-formed AttributeRaw,
-- this function is safe to use.
attRawASN1 :: AttributeRaw -> [ASN1]
attRawASN1 = attrRawValues

-- | A collection of raw attributes (SEQUENCE OF AttributeRaw).
--
-- This type can represent either an empty attribute collection (Nothing)
-- or a non-empty collection of attributes (Just [AttributeRaw]).
newtype Attributes = Attributes (Maybe [AttributeRaw])
  deriving (Show, Eq)

instance ASN1Object Attributes where
  toASN1 :: Attributes -> ASN1S
  toASN1 (Attributes Nothing) = id
  toASN1 (Attributes (Just attrs)) =
    \xs -> asn1Container Sequence (concatMap (`toASN1` []) attrs) ++ xs

  fromASN1 :: [ASN1] -> Either String (Attributes, [ASN1])
  fromASN1 = runParseASN1State (Attributes <$> parseAttributes)
    where
      parseAttributes = onNextContainerMaybe Sequence (getMany getObject)