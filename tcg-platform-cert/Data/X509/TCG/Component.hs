{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Component
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Component identification and hierarchy structures.
--
-- This module implements component identification as defined in the IWG Platform
-- Certificate Profile v1.1. Components represent hardware and software elements
-- that make up a platform configuration.
module Data.X509.TCG.Component
  ( -- * Component Identification
    ComponentIdentifier (..),
    ComponentIdentifierV2 (..),
    ComponentClass (..),
    ComponentAddress (..),
    ComponentAddressType (..),

    -- * Component Hierarchy
    ComponentHierarchy (..),
    ComponentTree (..),
    ComponentReference (..),

    -- * Component Properties
    ComponentProperties (..),
    ComponentMeasurement (..),
    ComponentDescriptor (..),

    -- * Component Relationships
    ComponentRelation (..),
    ComponentDependency (..),

    -- * Utility Functions
    isComponentClass,
    getComponentByAddress,
    buildComponentTree,
    validateComponentHierarchy,
  )
where

import Data.ASN1.Types
import qualified Data.ByteString as B

-- | Component Identifier structure (v1)
--
-- Basic component identification without hierarchical relationships.
data ComponentIdentifier = ComponentIdentifier
  { ciManufacturer :: B.ByteString,
    ciModel :: B.ByteString,
    ciSerial :: Maybe B.ByteString,
    ciRevision :: Maybe B.ByteString,
    ciManufacturerSerial :: Maybe B.ByteString,
    ciManufacturerRevision :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Identifier structure (v2)
--
-- Enhanced component identification with class and address information.
data ComponentIdentifierV2 = ComponentIdentifierV2
  { ci2Manufacturer :: B.ByteString,
    ci2Model :: B.ByteString,
    ci2Serial :: Maybe B.ByteString,
    ci2Revision :: Maybe B.ByteString,
    ci2ManufacturerSerial :: Maybe B.ByteString,
    ci2ManufacturerRevision :: Maybe B.ByteString,
    ci2ComponentClass :: ComponentClass,
    ci2ComponentAddress :: Maybe ComponentAddress
  }
  deriving (Show, Eq)

-- | Component Class enumeration
--
-- Defines the type/category of a platform component.
data ComponentClass
  = ComponentMotherboard
  | ComponentCPU
  | ComponentMemory
  | ComponentHardDrive
  | ComponentNetworkInterface
  | ComponentGraphicsCard
  | ComponentSoundCard
  | ComponentOpticalDrive
  | ComponentKeyboard
  | ComponentMouse
  | ComponentDisplay
  | ComponentSpeaker
  | ComponentMicrophone
  | ComponentCamera
  | ComponentTouchscreen
  | ComponentFingerprint
  | ComponentBluetooth
  | ComponentWifi
  | ComponentEthernet
  | ComponentUSB
  | ComponentFireWire
  | ComponentSCSI
  | ComponentIDE
  | -- | For custom component classes
    ComponentOther OID
  deriving (Show, Eq)

-- | Component Address structure
--
-- Physical or logical address of a component within the platform.
data ComponentAddress = ComponentAddress
  { caAddressType :: ComponentAddressType,
    caAddress :: B.ByteString
  }
  deriving (Show, Eq)

-- | Component Address Type enumeration
data ComponentAddressType
  = AddressPCI
  | AddressUSB
  | AddressSATA
  | AddressI2C
  | AddressSPI
  | AddressMAC
  | AddressLogical
  | AddressOther B.ByteString
  deriving (Show, Eq)

-- | Component Hierarchy structure
--
-- Represents the hierarchical relationship between components.
data ComponentHierarchy = ComponentHierarchy
  { chRootComponents :: [ComponentReference],
    chComponentTree :: ComponentTree
  }
  deriving (Show, Eq)

-- | Component Tree structure
--
-- Tree representation of component relationships.
data ComponentTree = ComponentTree
  { ctComponent :: ComponentIdentifierV2,
    ctChildren :: [ComponentTree],
    ctProperties :: ComponentProperties
  }
  deriving (Show, Eq)

-- | Component Reference structure
--
-- Reference to a component in the hierarchy.
data ComponentReference = ComponentReference
  { crCertificateSerial :: Integer,
    crComponentIndex :: Int,
    crComponentIdentifier :: ComponentIdentifierV2
  }
  deriving (Show, Eq)

-- | Component Properties structure
--
-- Additional properties and metadata for components.
data ComponentProperties = ComponentProperties
  { cpMeasurements :: [ComponentMeasurement],
    cpDescriptor :: Maybe ComponentDescriptor,
    cpRelations :: [ComponentRelation]
  }
  deriving (Show, Eq)

-- | Component Measurement structure
--
-- Cryptographic measurements of component state.
data ComponentMeasurement = ComponentMeasurement
  { cmDigestAlgorithm :: OID,
    cmDigestValue :: B.ByteString,
    cmMeasurementType :: MeasurementType
  }
  deriving (Show, Eq)

-- | Measurement Type enumeration
data MeasurementType
  = MeasurementFirmware
  | MeasurementSoftware
  | MeasurementConfiguration
  | MeasurementIdentity
  | MeasurementOther B.ByteString
  deriving (Show, Eq)

-- | Component Descriptor structure
--
-- Human-readable description and metadata.
data ComponentDescriptor = ComponentDescriptor
  { cdDescription :: B.ByteString,
    cdVendorInfo :: Maybe B.ByteString,
    -- | Key-value pairs
    cdProperties :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- | Component Relation structure
--
-- Describes relationships between components.
data ComponentRelation = ComponentRelation
  { crRelationType :: ComponentRelationType,
    crTargetComponent :: ComponentReference,
    crRelationProperties :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- | Component Relation Type enumeration
data ComponentRelationType
  = RelationParentOf
  | RelationChildOf
  | RelationDependsOn
  | RelationConflictsWith
  | RelationReplaces
  | RelationReplacedBy
  | RelationOther B.ByteString
  deriving (Show, Eq)

-- | Component Dependency structure
--
-- Describes dependency relationships between components.
data ComponentDependency = ComponentDependency
  { cdDependentComponent :: ComponentReference,
    cdRequiredComponent :: ComponentReference,
    cdDependencyType :: DependencyType,
    cdVersionConstraints :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Dependency Type enumeration
data DependencyType
  = DependencyRequired
  | DependencyOptional
  | DependencyConditional
  | DependencyIncompatible
  deriving (Show, Eq, Enum)

-- * Utility Functions

-- | Check if a component belongs to a specific class
isComponentClass :: ComponentClass -> ComponentIdentifierV2 -> Bool
isComponentClass targetClass component = ci2ComponentClass component == targetClass

-- | Get component by address from a component hierarchy
getComponentByAddress :: ComponentAddress -> ComponentHierarchy -> Maybe ComponentIdentifierV2
getComponentByAddress addr hierarchy = searchInTree addr (chComponentTree hierarchy)
  where
    searchInTree :: ComponentAddress -> ComponentTree -> Maybe ComponentIdentifierV2
    searchInTree target tree =
      case ci2ComponentAddress (ctComponent tree) of
        Just compAddr | compAddr == target -> Just (ctComponent tree)
        _ -> searchInChildren target (ctChildren tree)

    searchInChildren :: ComponentAddress -> [ComponentTree] -> Maybe ComponentIdentifierV2
    searchInChildren target trees =
      case trees of
        [] -> Nothing
        (t : ts) -> case searchInTree target t of
          Just result -> Just result
          Nothing -> searchInChildren target ts

-- | Build a component tree from a list of components
buildComponentTree :: [ComponentIdentifierV2] -> ComponentTree
buildComponentTree components =
  case components of
    [] -> error "Cannot build tree from empty component list"
    (root : _) -> ComponentTree root [] defaultProperties
  where
    defaultProperties = ComponentProperties [] Nothing []

-- | Validate component hierarchy for consistency
validateComponentHierarchy :: ComponentHierarchy -> [String]
validateComponentHierarchy hierarchy =
  validateTree (chComponentTree hierarchy)
  where
    validateTree :: ComponentTree -> [String]
    validateTree tree =
      validateComponent (ctComponent tree)
        ++ concatMap validateTree (ctChildren tree)

    validateComponent :: ComponentIdentifierV2 -> [String]
    validateComponent component
      | B.null (ci2Manufacturer component) = ["Component missing manufacturer"]
      | B.null (ci2Model component) = ["Component missing model"]
      | otherwise = []

-- ASN.1 instances will be implemented in a separate phase
-- instance ASN1Object ComponentIdentifier where ...
-- instance ASN1Object ComponentIdentifierV2 where ...
-- instance ASN1Object ComponentClass where ...