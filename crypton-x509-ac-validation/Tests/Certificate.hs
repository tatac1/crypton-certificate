{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Types and functions used to build test certificates for AC validation.
--
-- This module provides utilities for dynamically generating:
-- * Public Key Certificates (PKC) for use as AA certificates
-- * Attribute Certificates (AC) for validation testing
--
-- Adapted from x509-validation/Tests/Certificate.hs
module Certificate
  ( -- * Hash algorithms
    hashMD2,
    hashMD5,
    hashSHA1,
    hashSHA224,
    hashSHA256,
    hashSHA384,
    hashSHA512,

    -- * Key and signature utilities
    Alg (..),
    Keys,
    generateKeys,

    -- * PKC Certificate utilities
    Pair (..),
    mkDn,
    mkExtension,
    leafStdExts,
    aaStdExts,

    -- * PKC Certificate creation
    Auth (..),
    mkCertificate,
    mkCA,
    mkAA,
    mkLeaf,

    -- * AC Certificate utilities
    SignedAttributeCertificate,
    ACPair (..),
    mkTestAC,
    mkTestACInfo,
    mkTestHolder,
    mkTestIssuer,
    mkTestValidityPeriod,

    -- * AC signing
    signAttributeCertificate,

    -- * CRL utilities
    mkTestCRL,
    mkRevokedCertificate,
    signCRL,
  )
where

import Control.Applicative

import Crypto.Hash.Algorithms
import Crypto.Number.Serialize

import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS as PSS

import qualified Data.ByteString as B

import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.ByteArray (convert)
import Data.Maybe (catMaybes)
import Data.String (fromString)
import Data.X509
import Data.X509.AttCert
import Data.X509.Attribute

import Data.Hourglass

--------------------------------------------------------------------------------
-- Crypto utilities
--------------------------------------------------------------------------------

-- | Hash algorithm pairing for certificate signature operations.
--
-- Maps the typed cryptographic hash @hash@ to its corresponding 'HashALG'
-- enumeration value, as used in RFC 5280 Section 4.1.1.2:
--
--   AlgorithmIdentifier ::= SEQUENCE {
--     algorithm    OBJECT IDENTIFIER,
--     parameters   ANY DEFINED BY algorithm OPTIONAL
--   }
--
-- The hash algorithm is a component of the 'SignatureALG' used in:
--   - PKC signatures (RFC 5280 Section 4.1.1.2, tbsCertificate.signature)
--   - AC signatures  (RFC 5755 Section 4.1, acinfo.signature)
--   - CRL signatures (RFC 5280 Section 5.1.1.2, tbsCertList.signature)
data GHash hash = GHash {getHashALG :: HashALG, getHashAlgorithm :: hash}

-- | MD2 hash algorithm (OID 1.2.840.113549.2.2). Deprecated; for legacy tests only.
hashMD2 :: GHash MD2
-- | MD5 hash algorithm (OID 1.2.840.113549.2.5). Deprecated; for legacy tests only.
hashMD5 :: GHash MD5
-- | SHA-1 hash algorithm (OID 1.3.14.3.2.26). Deprecated per RFC 6194.
hashSHA1 :: GHash SHA1
-- | SHA-224 hash algorithm (OID 2.16.840.1.101.3.4.2.4).
hashSHA224 :: GHash SHA224
-- | SHA-256 hash algorithm (OID 2.16.840.1.101.3.4.2.1). Recommended minimum.
hashSHA256 :: GHash SHA256
-- | SHA-384 hash algorithm (OID 2.16.840.1.101.3.4.2.2).
hashSHA384 :: GHash SHA384
-- | SHA-512 hash algorithm (OID 2.16.840.1.101.3.4.2.3).
hashSHA512 :: GHash SHA512
hashMD2 = GHash HashMD2 MD2
hashMD5 = GHash HashMD5 MD5
hashSHA1 = GHash HashSHA1 SHA1
hashSHA224 = GHash HashSHA224 SHA224
hashSHA256 = GHash HashSHA256 SHA256
hashSHA384 = GHash HashSHA384 SHA384
hashSHA512 = GHash HashSHA512 SHA512

-- | Key generation and signature algorithm specification.
--
-- Maps to SignatureALG from RFC 5280 Section 4.1.1.2:
--   AlgorithmIdentifier ::= SEQUENCE {
--     algorithm    OBJECT IDENTIFIER,
--     parameters   ANY DEFINED BY algorithm OPTIONAL
--   }
--
-- Used to produce the signature on PKCs (RFC 5280 Section 4.1.1.3),
-- ACs (RFC 5755 Section 4.1), and CRLs (RFC 5280 Section 5.1.1.3).
--
-- Supported algorithms:
--   - AlgRSA: PKCS#1 v1.5 RSA with hash (OID 1.2.840.113549.1.1.*)
--   - AlgRSAPSS: RSASSA-PSS (OID 1.2.840.113549.1.1.10)
--   - AlgDSA: DSA with hash (OID 1.2.840.10040.4.*)
--   - AlgEC: ECDSA with hash (OID 1.2.840.10045.4.*)
--   - AlgEd25519: Ed25519 (OID 1.3.101.112)
--   - AlgEd448: Ed448 (OID 1.3.101.113)
data Alg pub priv where
  AlgRSA
    :: (HashAlgorithm hash, RSA.HashAlgorithmASN1 hash)
    => Int
    -> GHash hash
    -> Alg RSA.PublicKey RSA.PrivateKey
  AlgRSAPSS
    :: HashAlgorithm hash
    => Int
    -> PSS.PSSParams hash B.ByteString B.ByteString
    -> GHash hash
    -> Alg RSA.PublicKey RSA.PrivateKey
  AlgDSA
    :: HashAlgorithm hash
    => DSA.Params
    -> GHash hash
    -> Alg DSA.PublicKey DSA.PrivateKey
  AlgEC
    :: HashAlgorithm hash
    => ECC.CurveName
    -> GHash hash
    -> Alg ECDSA.PublicKey ECDSA.PrivateKey
  AlgEd25519 :: Alg Ed25519.PublicKey Ed25519.SecretKey
  AlgEd448 :: Alg Ed448.PublicKey Ed448.SecretKey

-- | Triple of algorithm, public key, and private key for a given scheme.
--
-- RFC 5280 Section 4.1.2.7 (Subject Public Key Info):
--   SubjectPublicKeyInfo ::= SEQUENCE {
--     algorithm         AlgorithmIdentifier,
--     subjectPublicKey  BIT STRING
--   }
--
-- The public key component ends up in the PKC's subjectPublicKeyInfo field,
-- while the private key is used for signing operations (PKC, AC, or CRL).
type Keys pub priv = (Alg pub priv, pub, priv)

-- | Generate a fresh key pair for the given signature algorithm.
--
-- This is used to produce key material for PKC subjects (RFC 5280 Section
-- 4.1.2.7) and for AA signing keys (RFC 5755 Section 3.2). The generated
-- key pair is suitable for:
--   - SubjectPublicKeyInfo in issued certificates
--   - Signing ACs when the key belongs to an Attribute Authority
--   - Signing CRLs / ACRLs when the key belongs to the issuer
generateKeys :: Alg pub priv -> IO (Keys pub priv)
generateKeys alg@(AlgRSA bits _) = generateRSAKeys alg bits
generateKeys alg@(AlgRSAPSS bits _ _) = generateRSAKeys alg bits
generateKeys alg@(AlgDSA params _) = do
  x <- DSA.generatePrivate params
  let y = DSA.calculatePublic params x
  return (alg, DSA.PublicKey params y, DSA.PrivateKey params x)
generateKeys alg@(AlgEC name _) = do
  let curve = ECC.getCurveByName name
  (pub, priv) <- ECC.generate curve
  return (alg, pub, priv)
generateKeys alg@AlgEd25519 = do
  secret <- Ed25519.generateSecretKey
  return (alg, Ed25519.toPublic secret, secret)
generateKeys alg@AlgEd448 = do
  secret <- Ed448.generateSecretKey
  return (alg, Ed448.toPublic secret, secret)

-- | Internal helper to generate RSA key pairs.
--
-- Generates an RSA key pair with the specified bit length and a fixed public
-- exponent of 3. Used by both AlgRSA (PKCS#1 v1.5, OID 1.2.840.113549.1.1.*)
-- and AlgRSAPSS (RSASSA-PSS, OID 1.2.840.113549.1.1.10) algorithms.
--
-- The resulting public key populates SubjectPublicKeyInfo (RFC 5280 Section
-- 4.1.2.7) in PKCs, while the private key is retained for signing.
generateRSAKeys
  :: Alg RSA.PublicKey RSA.PrivateKey
  -> Int
  -> IO (Alg RSA.PublicKey RSA.PrivateKey, RSA.PublicKey, RSA.PrivateKey)
generateRSAKeys alg bits = addAlg <$> RSA.generate size e
  where
    addAlg (pub, priv) = (alg, pub, priv)
    size = bits `div` 8
    e = 3

-- | Convert algorithm-specific public key to the generic 'PubKey' type.
--
-- RFC 5280 Section 4.1.2.7 (Subject Public Key Info):
--   SubjectPublicKeyInfo ::= SEQUENCE {
--     algorithm         AlgorithmIdentifier,
--     subjectPublicKey  BIT STRING
--   }
--
-- The resulting 'PubKey' is placed in the certificate's 'certPubKey' field
-- and encoded into the SubjectPublicKeyInfo structure. For EC keys, the
-- public point is serialized in uncompressed form (0x04 || x || y) as
-- required by SEC 1, Section 2.3.3.
getPubKey :: Alg pub priv -> pub -> PubKey
getPubKey (AlgRSA _ _) key = PubKeyRSA key
getPubKey (AlgRSAPSS _ _ _) key = PubKeyRSA key
getPubKey (AlgDSA _ _) key = PubKeyDSA key
getPubKey (AlgEC name _) key = PubKeyEC (PubKeyEC_Named name pub)
  where
    ECC.Point x y = ECDSA.public_q key
    pub = SerializedPoint bs
    bs = B.cons 4 (i2ospOf_ bytes x `B.append` i2ospOf_ bytes y)
    bits = ECC.curveSizeBits (ECC.getCurveByName name)
    bytes = (bits + 7) `div` 8
getPubKey AlgEd25519 key = PubKeyEd25519 key
getPubKey AlgEd448 key = PubKeyEd448 key

-- | Derive the 'SignatureALG' identifier from an 'Alg' value.
--
-- RFC 5280 Section 4.1.1.2 (signatureAlgorithm):
--   "This field contains the algorithm identifier for the algorithm
--    used by the CA to sign the certificate."
--
-- RFC 5755 Section 4.1 (signature in AttributeCertificateInfo):
--   "The signature field contains the algorithm identifier for the
--    algorithm used by the AC issuer to sign the AC."
--
-- For Ed25519/Ed448, the hash is intrinsic to the algorithm (PureEdDSA),
-- so 'SignatureALG_IntrinsicHash' is used instead of a separate hash OID.
getSignatureALG :: Alg pub priv -> SignatureALG
getSignatureALG (AlgRSA _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSA
getSignatureALG (AlgRSAPSS _ _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSAPSS
getSignatureALG (AlgDSA _ hash) = SignatureALG (getHashALG hash) PubKeyALG_DSA
getSignatureALG (AlgEC _ hash) = SignatureALG (getHashALG hash) PubKeyALG_EC
getSignatureALG AlgEd25519 = SignatureALG_IntrinsicHash PubKeyALG_Ed25519
getSignatureALG AlgEd448 = SignatureALG_IntrinsicHash PubKeyALG_Ed448

-- | Perform a digital signature operation using the given algorithm and key.
--
-- RFC 5280 Section 4.1.1.3 (signatureValue):
--   "The signatureValue field contains a digital signature computed upon
--    the ASN.1 DER encoded tbsCertificate."
--
-- RFC 5755 Section 4.1 (signatureValue for ACs):
--   The AC signatureValue is computed over the DER-encoded
--   AttributeCertificateInfo, analogous to PKC signing.
--
-- For DSA and ECDSA, the signature is DER-encoded as:
--   Dss-Sig-Value / ECDSA-Sig-Value ::= SEQUENCE {
--     r  INTEGER,
--     s  INTEGER
--   }
-- per RFC 3279 Section 2.2.2 (DSA) and Section 2.2.3 (ECDSA).
--
-- For Ed25519/Ed448, the raw signature bytes are returned directly
-- (RFC 8032).
doSign :: Alg pub priv -> priv -> B.ByteString -> IO B.ByteString
doSign (AlgRSA _ hash) key msg = do
  result <- RSA.signSafer (Just $ getHashAlgorithm hash) key msg
  case result of
    Left err -> error ("doSign(AlgRSA): " ++ show err)
    Right sigBits -> return sigBits
doSign (AlgRSAPSS _ params _) key msg = do
  result <- PSS.signSafer params key msg
  case result of
    Left err -> error ("doSign(AlgRSAPSS): " ++ show err)
    Right sigBits -> return sigBits
doSign (AlgDSA _ hash) key msg = do
  sig <- DSA.sign key (getHashAlgorithm hash) msg
  return $
    encodeASN1'
      DER
      [ Start Sequence
      , IntVal (DSA.sign_r sig)
      , IntVal (DSA.sign_s sig)
      , End Sequence
      ]
doSign (AlgEC _ hash) key msg = do
  sig <- ECDSA.sign key (getHashAlgorithm hash) msg
  return $
    encodeASN1'
      DER
      [ Start Sequence
      , IntVal (ECDSA.sign_r sig)
      , IntVal (ECDSA.sign_s sig)
      , End Sequence
      ]
doSign AlgEd25519 key msg =
  return $ convert $ Ed25519.sign key (Ed25519.toPublic key) msg
doSign AlgEd448 key msg =
  return $ convert $ Ed448.sign key (Ed448.toPublic key) msg

--------------------------------------------------------------------------------
-- PKC Certificate utilities
--------------------------------------------------------------------------------

-- | A signed PKC bundled with its private key and algorithm.
--
-- This type packages the information needed to use a certificate as a
-- signing authority:
--   - 'pairAlg': the signature algorithm, corresponding to
--     AlgorithmIdentifier in RFC 5280 Section 4.1.1.2
--   - 'pairSignedCert': the signed X.509 PKC (RFC 5280 Section 4.1)
--   - 'pairKey': the private key for producing signatures
--
-- A 'Pair' representing a CA can sign subordinate PKCs (RFC 5280 Section
-- 4.1.1.3). A 'Pair' representing an AA can sign ACs (RFC 5755 Section
-- 4.1) and ACRLs (RFC 5755 Section 6).
data Pair pub priv = Pair
  { pairAlg :: Alg pub priv
  , pairSignedCert :: SignedCertificate
  , pairKey :: priv
  }

-- | Build a DistinguishedName with a single CommonName (CN) attribute.
--
-- RFC 5280 Section 4.1.2.4 (Issuer) and Section 4.1.2.6 (Subject):
--   "The issuer field identifies the entity that has signed and issued
--    the certificate." / "The subject field identifies the entity
--    associated with the public key stored in the subject public key
--    field."
--
-- Both issuer and subject are of type Name (DistinguishedName), encoded as:
--   Name ::= CHOICE { rdnSequence RDNSequence }
--   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
--
-- This helper creates a minimal DN containing only the CommonName
-- attribute (OID 2.5.4.3), which is sufficient for test purposes.
mkDn :: String -> DistinguishedName
mkDn cn = DistinguishedName [(getObjectID DnCommonName, fromString cn)]

-- | Build a raw certificate extension from a typed extension value.
--
-- RFC 5280 Section 4.2 (Certificate Extensions):
--   Extension ::= SEQUENCE {
--     extnID     OBJECT IDENTIFIER,
--     critical   BOOLEAN DEFAULT FALSE,
--     extnValue  OCTET STRING
--   }
--
-- The @crit@ parameter sets the critical flag. Per RFC 5280 Section 4.2:
--   "A certificate-using system MUST reject the certificate if it encounters
--    a critical extension it does not recognize."
--
-- This is also used for AC extensions (RFC 5755 Section 4.2.9).
mkExtension :: Extension a => Bool -> a -> ExtensionRaw
mkExtension crit ext = ExtensionRaw (extOID ext) crit (extEncodeBs ext)

-- | Default extensions for leaf (end-entity) certificates.
--
-- RFC 5280 Section 4.2.1.3 (Key Usage):
--   "The key usage extension defines the purpose of the key contained
--    in the certificate."
--
-- RFC 5280 Section 4.2.1.12 (Extended Key Usage):
--   "This extension indicates one or more purposes for which the
--    certified public key may be used."
--
-- Leaf certificates are issued with:
--   - keyUsage: digitalSignature | keyEncipherment (non-critical)
--   - extKeyUsage: id-kp-serverAuth | id-kp-clientAuth (non-critical)
--
-- These represent a typical TLS end-entity certificate. Leaf certificates
-- are NOT used to sign ACs; that role is reserved for AA certificates.
leafStdExts :: [ExtensionRaw]
leafStdExts = [ku, eku]
  where
    ku =
      mkExtension False $
        ExtKeyUsage
          [KeyUsage_digitalSignature, KeyUsage_keyEncipherment]
    eku =
      mkExtension False $
        ExtExtendedKeyUsage
          [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_ClientAuth]

-- | Default extensions for Attribute Authority (AA) certificates.
--
-- RFC 5755 Section 3.2 (AA - Attribute Authority):
--   "The entity that signs the AC is the AC issuer. The AC issuer's
--    certificate is the AA certificate."
--
-- RFC 5280 Section 4.2.1.9 (Basic Constraints):
--   "The cA boolean indicates whether the certified public key may be
--    used to verify certificate signatures."
--
-- RFC 5280 Section 4.2.1.3 (Key Usage):
--   "The keyCertSign bit is asserted when the subject public key is
--    used for verifying signatures on public key certificates."
--
-- AA certificates are created with:
--   - basicConstraints: cA=TRUE (critical) per RFC 5280 Section 4.2.1.9
--   - keyUsage: keyCertSign | digitalSignature (critical) per RFC 5280 Section 4.2.1.3
--
-- The keyCertSign bit allows the AA to sign ACs, and digitalSignature
-- allows direct authentication operations.
aaStdExts :: [ExtensionRaw]
aaStdExts = [bc, ku]
  where
    bc =
      mkExtension True $
        ExtBasicConstraints True Nothing  -- CA=true for AA
    ku =
      mkExtension True $
        ExtKeyUsage
          [KeyUsage_keyCertSign, KeyUsage_digitalSignature]

--------------------------------------------------------------------------------
-- Authority signing a certificate
--------------------------------------------------------------------------------

-- | Certificate signing authority: either self-signed or issued by a CA.
--
-- Models the two signing modes for X.509 certificates:
--
--   - 'Self': self-signed certificate where the subject signs its own
--     certificate. Per RFC 5280 Section 3.2: "CAs can self-issue
--     certificates." The issuer DN equals the subject DN.
--
--   - 'CA': a CA (or AA) 'Pair' acts as the issuing authority. The issuer
--     DN is taken from the CA's subject DN, and the CA's private key signs
--     the new certificate per RFC 5280 Section 4.1.1.3.
--
-- Type parameters @pubI@/@privI@ are the issuer's key types, and
-- @pubS@/@privS@ are the subject's key types. When 'Self', these are
-- unified via type equality constraints.
data Auth pubI privI pubS privS where
  Self :: (pubI ~ pubS, privI ~ privS) => Auth pubI privI pubS privS
  CA :: Pair pubI privI -> Auth pubI privI pubS privS

-- | Fold over 'Auth': return a default for self-signed, or apply a function
-- to the issuer 'Pair' for CA-signed. Used to extract issuer-dependent
-- values such as the issuer DN (RFC 5280 Section 4.1.2.4).
foldAuth
  :: a
  -> (Pair pubI privI -> a)
  -> Auth pubI privI pubS privS
  -> a
foldAuth x _ Self = x
foldAuth _ f (CA p) = f p

-- | Extract the signing private key from 'Auth': the subject's own key for
-- self-signed, or the issuer's private key for CA-signed. This key is used
-- to compute the signatureValue (RFC 5280 Section 4.1.1.3).
foldAuthPriv
  :: privS
  -> (Pair pubI privI -> privI)
  -> Auth pubI privI pubS privS
  -> privI
foldAuthPriv x _ Self = x
foldAuthPriv _ f (CA p) = f p

-- | Extract a type-indexed value from 'Auth', parameterized by both public
-- and private key types. Used to obtain the issuer's 'Alg' so that the
-- correct 'SignatureALG' (RFC 5280 Section 4.1.1.2) is used for signing.
foldAuthPubPriv
  :: k pubS privS
  -> (Pair pubI privI -> k pubI privI)
  -> Auth pubI privI pubS privS
  -> k pubI privI
foldAuthPubPriv x _ Self = x
foldAuthPubPriv _ f (CA p) = f p

--------------------------------------------------------------------------------
-- PKC Certificate creation functions
--------------------------------------------------------------------------------

-- | Build and sign an X.509 v3 Public Key Certificate (PKC).
--
-- RFC 5280 Section 4.1 (Basic Certificate Fields):
--   Certificate ::= SEQUENCE {
--     tbsCertificate      TBSCertificate,
--     signatureAlgorithm  AlgorithmIdentifier,
--     signatureValue      BIT STRING
--   }
--
--   TBSCertificate ::= SEQUENCE {
--     version         [0]  EXPLICIT Version DEFAULT v1,
--     serialNumber         CertificateSerialNumber,
--     signature            AlgorithmIdentifier,
--     issuer               Name,
--     validity             Validity,
--     subject              Name,
--     subjectPublicKeyInfo SubjectPublicKeyInfo,
--     ...
--     extensions      [3]  EXPLICIT Extensions OPTIONAL
--   }
--
-- The certificate is DER-encoded and signed using the issuer's private key
-- (from 'Auth'). The signature algorithm in tbsCertificate.signature MUST
-- match the outer signatureAlgorithm per RFC 5280 Section 4.1.1.2.
--
-- When the authority is 'Self', the certificate is self-signed (issuer DN
-- equals subject DN). When the authority is @CA pair@, the issuer DN and
-- signing key are taken from the CA's certificate.
mkCertificate
  :: Int
  -- ^ Certificate version (2 = v3 per RFC 5280 Section 4.1.2.1)
  -> Integer
  -- ^ Serial number (RFC 5280 Section 4.1.2.2)
  -> DistinguishedName
  -- ^ Subject DN (RFC 5280 Section 4.1.2.6)
  -> (DateTime, DateTime)
  -- ^ Certificate validity period (RFC 5280 Section 4.1.2.5)
  -> [ExtensionRaw]
  -- ^ Extensions to include (RFC 5280 Section 4.2)
  -> Auth pubI privI pubS privS
  -- ^ Authority signing the new certificate
  -> Keys pubS privS
  -- ^ Keys for the new certificate
  -> IO (Pair pubS privS)
  -- ^ The new certificate/key pair
mkCertificate version serial dn validity exts auth (algS, pubKey, privKey) = do
  signedCert <- objectToSignedExactF signatureFunction cert
  return
    Pair
      { pairAlg = algS
      , pairSignedCert = signedCert
      , pairKey = privKey
      }
  where
    pairCert = signedObject . getSigned . pairSignedCert

    cert =
      Certificate
        { certVersion = version
        , certSerial = serial
        , certSignatureAlg = signAlgI
        , certIssuerDN = issuerDN
        , certValidity = validity
        , certSubjectDN = dn
        , certPubKey = getPubKey algS pubKey
        , certExtensions = extensions
        }

    signingKey = foldAuthPriv privKey pairKey auth
    algI = foldAuthPubPriv algS pairAlg auth

    signAlgI = getSignatureALG algI
    issuerDN = foldAuth dn (certSubjectDN . pairCert) auth
    extensions = Extensions (if null exts then Nothing else Just exts)

    signatureFunction objRaw = do
      sigBits <- doSign algI signingKey objRaw
      return (sigBits, signAlgI)

-- | Build a Certificate Authority (CA) certificate.
--
-- RFC 5280 Section 6.1 (Basic Path Validation):
--   "A certification path is a chain of certificates, where the subject
--    of one certificate is the issuer of the next."
--
-- RFC 5280 Section 4.2.1.9 (Basic Constraints):
--   "The basic constraints extension identifies whether the subject of
--    the certificate is a CA and the maximum depth of valid
--    certification paths that include this certificate."
--
-- The CA certificate is created as X.509 v3 (version = 2). The caller
-- may optionally supply:
--   - basicConstraints (e.g., cA=TRUE with optional pathLenConstraint)
--   - keyUsage (e.g., keyCertSign for signing subordinate certificates)
--
-- In AC validation (RFC 5755 Section 5), the CA sits in the certification
-- path that verifies the AA's PKC, establishing trust in the AA.
mkCA
  :: Integer
  -- ^ Serial number (RFC 5280 Section 4.1.2.2)
  -> String
  -- ^ Common name for the subject DN
  -> (DateTime, DateTime)
  -- ^ CA validity period (RFC 5280 Section 4.1.2.5)
  -> Maybe ExtBasicConstraints
  -- ^ CA basic constraints (RFC 5280 Section 4.2.1.9)
  -> Maybe ExtKeyUsage
  -- ^ CA key usage (RFC 5280 Section 4.2.1.3)
  -> Auth pubI privI pubS privS
  -- ^ Authority signing the new certificate
  -> Keys pubS privS
  -- ^ Keys for the new certificate
  -> IO (Pair pubS privS)
  -- ^ The new CA certificate/key pair
mkCA serial cn validity bc ku =
  let exts = catMaybes [mkExtension True <$> bc, mkExtension False <$> ku]
   in mkCertificate 2 serial (mkDn cn) validity exts

-- | Create an Attribute Authority (AA) certificate.
--
-- RFC 5755 Section 3.2 (AA - Attribute Authority):
--   "The entity that signs the AC is the AC issuer. The AC issuer's
--    certificate is the AA certificate."
--
-- RFC 5755 Section 4.2.3:
--   "Each AC issuer MUST be uniquely identified by one of the attributes
--    in the issuer field of the PKC."
--
-- The AA certificate is created with:
--   - basicConstraints: cA=TRUE (critical) per RFC 5280 Section 4.2.1.9
--   - keyUsage: keyCertSign | digitalSignature (critical) per RFC 5280 Section 4.2.1.3
--
-- These extensions allow the AA to sign ACs (keyCertSign) and verify
-- that the PKC holder is a legitimate Attribute Authority. The AA's PKC
-- must be validated through a certification path back to a trust anchor
-- before its ACs can be trusted (RFC 5755 Section 5).
mkAA
  :: Integer
  -- ^ Serial number (RFC 5280 Section 4.1.2.2)
  -> String
  -- ^ Common name for the AA subject DN
  -> (DateTime, DateTime)
  -- ^ AA validity period (RFC 5280 Section 4.1.2.5)
  -> Auth pubI privI pubS privS
  -- ^ Authority signing the new certificate
  -> Keys pubS privS
  -- ^ Keys for the new certificate
  -> IO (Pair pubS privS)
  -- ^ The new AA certificate/key pair
mkAA serial cn validity = mkCertificate 2 serial (mkDn cn) validity aaStdExts

-- | Build a leaf (end-entity) certificate.
--
-- RFC 5280 Section 4.2.1.9 (Basic Constraints):
--   "If the basic constraints extension is not present in a version 3
--    certificate, or the extension is present but the cA boolean is not
--    asserted, then the certified public key MUST NOT be used to verify
--    certificate signatures."
--
-- A leaf certificate represents an end entity that does not sign other
-- certificates. It uses 'leafStdExts' which sets:
--   - keyUsage: digitalSignature | keyEncipherment
--   - extKeyUsage: id-kp-serverAuth | id-kp-clientAuth
--
-- In the AC validation context (RFC 5755), a leaf certificate may serve
-- as the holder of an Attribute Certificate, identified via the holder
-- field (RFC 5755 Section 4.2.2). The fixed serial number 100 is used
-- for simplicity in test scenarios.
mkLeaf
  :: String
  -- ^ Common name for the subject DN
  -> (DateTime, DateTime)
  -- ^ Certificate validity period (RFC 5280 Section 4.1.2.5)
  -> Auth pubI privI pubS privS
  -- ^ Authority signing the new certificate
  -> Keys pubS privS
  -- ^ Keys for the new certificate
  -> IO (Pair pubS privS)
  -- ^ The new leaf certificate/key pair
mkLeaf cn validity = mkCertificate 2 100 (mkDn cn) validity leafStdExts

--------------------------------------------------------------------------------
-- AC (Attribute Certificate) utilities
--------------------------------------------------------------------------------

-- | Signed Attribute Certificate type alias.
--
-- RFC 5755 Section 4.1 (Attribute Certificate):
--   AttributeCertificate ::= SEQUENCE {
--     acinfo               AttributeCertificateInfo,
--     signatureAlgorithm   AlgorithmIdentifier,
--     signatureValue       BIT STRING
--   }
--
-- 'SignedExact' wraps the 'AttributeCertificateInfo' with its DER encoding,
-- the signature algorithm, and the signature value, forming the complete
-- signed AC structure.
type SignedAttributeCertificate = SignedExact AttributeCertificateInfo

-- | Bundle of a signed Attribute Certificate and its issuing AA.
--
-- RFC 5755 Section 3.2:
--   "The entity that signs the AC is the AC issuer. The AC issuer's
--    certificate is the AA certificate."
--
-- This type pairs the signed AC with the AA's 'Pair' so that tests can
-- easily access both the AC (for validation) and the AA's signing
-- credentials (for constructing trust chains).
--
--   - 'acpAA': The Attribute Authority's PKC and private key
--   - 'acpSignedAC': The signed AttributeCertificate (RFC 5755 Section 4.1)
data ACPair pub priv = ACPair
  { acpAA :: Pair pub priv
  -- ^ The AA certificate/key pair that signed this AC
  , acpSignedAC :: SignedAttributeCertificate
  -- ^ The signed Attribute Certificate
  }

-- | Create a test Holder from a PKC (typically an AA certificate).
--
-- RFC 5755 Section 4.2.2 (Holder):
--   Holder ::= SEQUENCE {
--     baseCertificateID   [0] IssuerSerial OPTIONAL,
--     entityName          [1] GeneralNames OPTIONAL,
--     objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
--   }
--
-- Per RFC 5755: "The holder field is a SEQUENCE allowing three different
-- (optional) syntaxes: baseCertificateID, entityName, and
-- objectDigestInfo." This function uses baseCertificateID with the
-- certificate's issuer DN and serial number as the holder identification.
--
-- RFC 5755 Section 4.2.2:
--   IssuerSerial ::= SEQUENCE {
--     issuer    GeneralNames,
--     serial    CertificateSerialNumber,
--     issuerUID UniqueIdentifier OPTIONAL
--   }
--
-- Only baseCertificateID is set; entityName and objectDigestInfo are Nothing.
mkTestHolder :: SignedCertificate -> Holder
mkTestHolder aaCert =
  let cert = signedObject (getSigned aaCert)
      issuerDn = certIssuerDN cert
      serial = certSerial cert
      issuerSerial = IssuerSerial [AltDirectoryName issuerDn] serial Nothing
   in Holder (Just issuerSerial) Nothing Nothing

-- | Create a test AttCertIssuer from an AA certificate.
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   AttCertIssuer ::= CHOICE {
--     v1Form   GeneralNames,  -- MUST NOT be used in this profile
--     v2Form   [0] V2Form     -- v2 only
--   }
--
--   V2Form ::= SEQUENCE {
--     issuerName            GeneralNames OPTIONAL,
--     baseCertificateID     [0] IssuerSerial OPTIONAL,
--     objectDigestInfo      [1] ObjectDigestInfo OPTIONAL
--   }
--
-- Per RFC 5755 Section 4.2.3: "The v2Form alternative MUST be used."
-- This function constructs an 'AttCertIssuerV2' with the AA's subject DN
-- as a directoryName in the issuerName field of V2Form. The
-- baseCertificateID and objectDigestInfo fields are left as Nothing.
mkTestIssuer :: SignedCertificate -> AttCertIssuer
mkTestIssuer aaCert =
  let cert = signedObject (getSigned aaCert)
      dn = certSubjectDN cert
   in AttCertIssuerV2 $ V2Form [AltDirectoryName dn] Nothing Nothing

-- | Create a test AC validity period.
--
-- RFC 5755 Section 4.2.6 (Validity Period):
--   AttCertValidityPeriod ::= SEQUENCE {
--     notBeforeTime  GeneralizedTime,
--     notAfterTime   GeneralizedTime
--   }
--
-- Per RFC 5755: "The notBeforeTime and notAfterTime fields define the
-- validity period of the AC." Unlike PKC validity (which uses UTCTime
-- for dates before 2050), AC validity always uses GeneralizedTime.
--
-- During AC validation (RFC 5755 Section 5, step 3), the current time
-- must fall within this period for the AC to be considered valid.
mkTestValidityPeriod :: DateTime -> DateTime -> AttCertValidityPeriod
mkTestValidityPeriod = AttCertValidityPeriod

-- | Construct an AttributeCertificateInfo for testing.
--
-- RFC 5755 Section 4.1 (Attribute Certificate Info):
--   AttributeCertificateInfo ::= SEQUENCE {
--     version              AttCertVersion,  -- version is v2
--     holder               Holder,
--     issuer               AttCertIssuer,
--     signature            AlgorithmIdentifier,
--     serialNumber         CertificateSerialNumber,
--     attrCertValidityPeriod AttCertValidityPeriod,
--     attributes           SEQUENCE OF Attribute,
--     issuerUniqueID       UniqueIdentifier OPTIONAL,
--     extensions           Extensions OPTIONAL
--   }
--
-- Per RFC 5755 Section 4.1: "The version field MUST have the value of
-- v2." This function sets aciVersion = 1 (which encodes as v2, since
-- v2 is encoded as INTEGER 1 in ASN.1).
--
-- The issuer is derived from the AA certificate's subject DN using
-- 'mkTestIssuer'. The issuerUniqueID is left as Nothing, consistent
-- with RFC 5755 Section 4.2.8 which states it MUST NOT be used unless
-- the AC issuer reuses the same DN for different entities.
mkTestACInfo
  :: SignedCertificate
  -- ^ AA certificate (used to derive the issuer via 'mkTestIssuer')
  -> Holder
  -- ^ Holder of the AC (RFC 5755 Section 4.2.2)
  -> Integer
  -- ^ Serial number (RFC 5755 Section 4.2.5)
  -> AttCertValidityPeriod
  -- ^ Validity period (RFC 5755 Section 4.2.6)
  -> Attributes
  -- ^ Attributes granted by this AC (RFC 5755 Section 4.2.7)
  -> [ExtensionRaw]
  -- ^ Extensions (RFC 5755 Section 4.2.9)
  -> SignatureALG
  -- ^ Signature algorithm (RFC 5755 Section 4.1, acinfo.signature)
  -> AttributeCertificateInfo
mkTestACInfo aaCert holder serial validity attrs exts sigAlg =
  AttributeCertificateInfo
    { aciVersion = 1
    , aciHolder = holder
    , aciIssuer = mkTestIssuer aaCert
    , aciSignature = sigAlg
    , aciSerialNumber = serial
    , aciValidity = validity
    , aciAttributes = attrs
    , aciIssuerUniqueID = Nothing
    , aciExtensions = Extensions (if null exts then Nothing else Just exts)
    }

-- | Sign an AttributeCertificateInfo to produce a complete Attribute Certificate.
--
-- RFC 5755 Section 4.1 (Attribute Certificate):
--   AttributeCertificate ::= SEQUENCE {
--     acinfo               AttributeCertificateInfo,
--     signatureAlgorithm   AlgorithmIdentifier,
--     signatureValue       BIT STRING
--   }
--
-- The signing process:
--   1. DER-encode the AttributeCertificateInfo
--   2. Compute the digital signature over the encoding using the AA's
--      private key and the specified algorithm
--   3. Package the result as a SignedExact structure
--
-- Per RFC 5755 Section 4.1: "The signatureAlgorithm field contains the
-- algorithm identifier for the algorithm used by the AC issuer to sign
-- the AttributeCertificateInfo." The outer signatureAlgorithm MUST be
-- identical to acinfo.signature.
signAttributeCertificate
  :: Alg pub priv
  -> priv
  -> AttributeCertificateInfo
  -> IO SignedAttributeCertificate
signAttributeCertificate alg privKey aci =
  objectToSignedExactF signatureFunction aci
  where
    signatureFunction objRaw = do
      sigBits <- doSign alg privKey objRaw
      return (sigBits, aciSignature aci)

-- | Create a complete test Attribute Certificate signed by an AA.
--
-- RFC 5755 Section 4 (Attribute Certificate Profile):
--   This function assembles a complete AC by:
--   1. Deriving the SignatureALG from the AA's algorithm ('getSignatureALG')
--   2. Constructing the AttributeCertificateInfo via 'mkTestACInfo'
--   3. Signing it with the AA's private key via 'signAttributeCertificate'
--
-- RFC 5755 Section 3.2:
--   "The entity that signs the AC is the AC issuer. The AC issuer's
--    certificate is the AA certificate."
--
-- The resulting 'ACPair' bundles the signed AC with the AA's credentials,
-- providing everything needed to set up an AC validation test scenario
-- per RFC 5755 Section 5 (Attribute Certificate Validation).
mkTestAC
  :: Pair pub priv
  -- ^ AA certificate/key pair (the AC issuer per RFC 5755 Section 3.2)
  -> Holder
  -- ^ Holder of the AC (RFC 5755 Section 4.2.2)
  -> Integer
  -- ^ Serial number (RFC 5755 Section 4.2.5)
  -> AttCertValidityPeriod
  -- ^ Validity period (RFC 5755 Section 4.2.6)
  -> Attributes
  -- ^ Attributes granted by this AC (RFC 5755 Section 4.2.7)
  -> [ExtensionRaw]
  -- ^ Extensions (RFC 5755 Section 4.2.9)
  -> IO (ACPair pub priv)
mkTestAC aaPair holder serial validity attrs exts = do
  let sigAlg = getSignatureALG (pairAlg aaPair)
  let aci = mkTestACInfo (pairSignedCert aaPair) holder serial validity attrs exts sigAlg
  signedAC <- signAttributeCertificate (pairAlg aaPair) (pairKey aaPair) aci
  return ACPair
    { acpAA = aaPair
    , acpSignedAC = signedAC
    }

--------------------------------------------------------------------------------
-- CRL (Certificate Revocation List) utilities
--------------------------------------------------------------------------------

-- | Create a revoked certificate entry for a CRL or ACRL.
--
-- RFC 5755 Section 6 (Revocation):
--   "In order to determine the revocation status of an AC, the relying
--    party must obtain the appropriate ACRL."
--
-- RFC 5280 Section 5.1 (CRL Fields):
--   revokedCertificates SEQUENCE OF SEQUENCE {
--     userCertificate    CertificateSerialNumber,
--     revocationDate     Time,
--     crlEntryExtensions Extensions OPTIONAL
--   }
--
-- Each entry identifies a revoked certificate (or AC) by its serial number
-- and the date it was revoked. The crlEntryExtensions are left empty
-- (Extensions Nothing) for test simplicity.
--
-- For ACRLs, the userCertificate field contains the serial number of the
-- revoked Attribute Certificate, not a PKC serial number.
mkRevokedCertificate
  :: Integer
  -- ^ Serial number of the revoked certificate/AC
  -> DateTime
  -- ^ Revocation date
  -> RevokedCertificate
mkRevokedCertificate serialNum revDate =
  RevokedCertificate
    { revokedSerialNumber = serialNum
    , revokedDate = revDate
    , revokedExtensions = Extensions Nothing
    }

-- | Sign a CRL to produce a SignedCRL.
--
-- RFC 5280 Section 5.1 (CRL Fields):
--   CertificateList ::= SEQUENCE {
--     tbsCertList          TBSCertList,
--     signatureAlgorithm   AlgorithmIdentifier,
--     signatureValue       BIT STRING
--   }
--
-- The signing process mirrors PKC and AC signing:
--   1. DER-encode the TBSCertList (CRL data)
--   2. Compute the digital signature using the issuer's private key
--   3. Package as a SignedExact structure
--
-- Per RFC 5280 Section 5.1.1.2: "This field MUST contain the same
-- algorithm identifier as the signature field in the sequence
-- tbsCertList."
--
-- For ACRLs (RFC 5755 Section 6), the CRL is signed by the same AA
-- that issued the Attribute Certificates being revoked.
signCRL
  :: Alg pub priv
  -> priv
  -> CRL
  -> IO SignedCRL
signCRL alg privKey crlData =
  objectToSignedExactF signatureFunction crlData
  where
    signatureFunction objRaw = do
      sigBits <- doSign alg privKey objRaw
      return (sigBits, crlSignatureAlg crlData)

-- | Create and sign a test CRL (or ACRL) issued by a CA or AA.
--
-- RFC 5280 Section 5.1 (CRL Fields):
--   TBSCertList ::= SEQUENCE {
--     version              Version OPTIONAL,
--     signature            AlgorithmIdentifier,
--     issuer               Name,
--     thisUpdate           Time,
--     nextUpdate           Time OPTIONAL,
--     revokedCertificates  SEQUENCE OF SEQUENCE { ... } OPTIONAL,
--     crlExtensions        [0] EXPLICIT Extensions OPTIONAL
--   }
--
-- RFC 5755 Section 6 (Revocation):
--   "Attribute certificate revocation lists (ACRLs) have the same
--    syntax as PKC CRLs."
--
-- The CRL is constructed with version 1 (v2 encoding), the issuer's
-- subject DN as the CRL issuer, and signed using the issuer's private
-- key. The nextUpdate field is optional: when Nothing, the CRL has no
-- scheduled next update. Extensions are left empty for test simplicity.
mkTestCRL
  :: Pair pub priv
  -- ^ Issuer certificate/key pair (AA or CA that signs the CRL)
  -> DateTime
  -- ^ thisUpdate: CRL issue time (RFC 5280 Section 5.1.2.4)
  -> Maybe DateTime
  -- ^ nextUpdate: next scheduled CRL (RFC 5280 Section 5.1.2.5)
  -> [RevokedCertificate]
  -- ^ List of revoked certificates/ACs
  -> IO SignedCRL
mkTestCRL issuerPair thisUpdate mNextUpdate revokedCerts = do
  let issuerCert = signedObject (getSigned (pairSignedCert issuerPair))
  let issuerDn = certSubjectDN issuerCert
  let sigAlg = getSignatureALG (pairAlg issuerPair)
  let crlData = CRL
        { crlVersion = 1
        , crlSignatureAlg = sigAlg
        , crlIssuer = issuerDn
        , crlThisUpdate = thisUpdate
        , crlNextUpdate = mNextUpdate
        , crlRevokedCertificates = revokedCerts
        , crlExtensions = Extensions Nothing
        }
  signCRL (pairAlg issuerPair) (pairKey issuerPair) crlData
