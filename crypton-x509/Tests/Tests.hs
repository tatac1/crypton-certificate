{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Tasty
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B

import Control.Applicative
import Control.Monad

import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.BitArray
import Data.ASN1.Types
import Data.List (nub, sort)
import Data.X509
import Data.X509AC

import Data.Hourglass

instance Arbitrary RSA.PublicKey where
    arbitrary = do
        bytes <- elements [64, 128, 256]
        e <- elements [0x3, 0x10001]
        n <- choose (2 ^ (8 * (bytes - 1)), 2 ^ (8 * bytes))
        return $
            RSA.PublicKey
                { RSA.public_size = bytes
                , RSA.public_n = n
                , RSA.public_e = e
                }

instance Arbitrary DSA.Params where
    arbitrary = DSA.Params <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary DSA.PublicKey where
    arbitrary = DSA.PublicKey <$> arbitrary <*> arbitrary

instance Arbitrary X25519.PublicKey where
    arbitrary = X25519.toPublic <$> arbitrary

instance Arbitrary X448.PublicKey where
    arbitrary = X448.toPublic <$> arbitrary

instance Arbitrary Ed25519.PublicKey where
    arbitrary = Ed25519.toPublic <$> arbitrary

instance Arbitrary Ed448.PublicKey where
    arbitrary = Ed448.toPublic <$> arbitrary

instance Arbitrary PubKey where
    arbitrary =
        oneof
            [ PubKeyRSA <$> arbitrary
            , PubKeyDSA <$> arbitrary
            , -- , PubKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PubKeyX25519 <$> arbitrary
            , PubKeyX448 <$> arbitrary
            , PubKeyEd25519 <$> arbitrary
            , PubKeyEd448 <$> arbitrary
            ]

instance Arbitrary RSA.PrivateKey where
    arbitrary =
        RSA.PrivateKey
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary DSA.PrivateKey where
    arbitrary = DSA.PrivateKey <$> arbitrary <*> arbitrary

instance Arbitrary X25519.SecretKey where
    arbitrary = throwCryptoError . X25519.secretKey <$> arbitraryBS 32 32

instance Arbitrary X448.SecretKey where
    arbitrary = throwCryptoError . X448.secretKey <$> arbitraryBS 56 56

instance Arbitrary Ed25519.SecretKey where
    arbitrary = throwCryptoError . Ed25519.secretKey <$> arbitraryBS 32 32

instance Arbitrary Ed448.SecretKey where
    arbitrary = throwCryptoError . Ed448.secretKey <$> arbitraryBS 57 57

instance Arbitrary PrivKey where
    arbitrary =
        oneof
            [ PrivKeyRSA <$> arbitrary
            , PrivKeyDSA <$> arbitrary
            , -- , PrivKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PrivKeyX25519 <$> arbitrary
            , PrivKeyX448 <$> arbitrary
            , PrivKeyEd25519 <$> arbitrary
            , PrivKeyEd448 <$> arbitrary
            ]

instance Arbitrary HashALG where
    arbitrary =
        elements
            [HashMD2, HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512]

instance Arbitrary PubKeyALG where
    arbitrary = elements [PubKeyALG_RSA, PubKeyALG_DSA, PubKeyALG_EC, PubKeyALG_DH]

instance Arbitrary SignatureALG where
    -- unfortunately as the encoding of this is a single OID as opposed to two OID,
    -- the testing need to limit itself to Signature ALG that has been defined in the OID database.
    -- arbitrary = SignatureALG <$> arbitrary <*> arbitrary
    arbitrary =
        elements
            [ SignatureALG HashSHA1 PubKeyALG_RSA
            , SignatureALG HashMD5 PubKeyALG_RSA
            , SignatureALG HashMD2 PubKeyALG_RSA
            , SignatureALG HashSHA256 PubKeyALG_RSA
            , SignatureALG HashSHA384 PubKeyALG_RSA
            , SignatureALG HashSHA512 PubKeyALG_RSA
            , SignatureALG HashSHA224 PubKeyALG_RSA
            , SignatureALG HashSHA1 PubKeyALG_DSA
            , SignatureALG HashSHA224 PubKeyALG_DSA
            , SignatureALG HashSHA256 PubKeyALG_DSA
            , SignatureALG HashSHA224 PubKeyALG_EC
            , SignatureALG HashSHA256 PubKeyALG_EC
            , SignatureALG HashSHA384 PubKeyALG_EC
            , SignatureALG HashSHA512 PubKeyALG_EC
            , SignatureALG_IntrinsicHash PubKeyALG_Ed25519
            , SignatureALG_IntrinsicHash PubKeyALG_Ed448
            ]

arbitraryBS r1 r2 = choose (r1, r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

-- | Generate a positive integer for use as AC serial numbers.
--
-- RFC 5755 Section 4.2.5 (Serial Number):
--   "The serial number MUST be a positive INTEGER"
--   "CAs conforming to this profile MUST NOT use serialNumber values longer
--    than 20 octets."
--
-- This generator produces values in [1, 2^64], satisfying the positivity
-- requirement. Values of 0 or negative are NOT valid serial numbers.
-- Note: the 20-octet upper bound is a profile constraint (tested separately
-- in crypton-x509-ac-validation), not a codec constraint.
arbitraryPositive :: Gen Integer
arbitraryPositive = choose (1, 2 ^ (64 :: Int))

-- | Generate a non-empty ASCII string for use in GeneralName fields.
--
-- Used to construct RFC 5755 / RFC 5280 GeneralName values such as:
--   - rfc822Name (IA5String)
--   - dNSName (IA5String)
--   - uniformResourceIdentifier (IA5String)
--
-- Per RFC 5280 Section 4.2.1.6, these fields use IA5String encoding,
-- which is a subset of ASCII. This generator produces non-empty strings
-- containing only lowercase letters and digits, ensuring valid IA5 content.
arbitraryAscii :: Gen String
arbitraryAscii = listOf1 $ elements (['a'..'z'] ++ ['0'..'9'])

-- | Generate a random GeneralName (AltName) value.
--
-- RFC 5755 uses GeneralName (defined in RFC 5280 Section 4.2.1.6) extensively:
--   - Holder.entityName (Section 4.2.2): "SEQUENCE OF GeneralName"
--   - AttCertIssuer.issuerName (Section 4.2.3): "SEQUENCE OF GeneralName"
--   - Target.targetName/targetGroup (Section 4.3.2): "GeneralName"
--
-- GeneralName ::= CHOICE {
--   otherName       [0]  OtherName,
--   rfc822Name      [1]  IA5String,
--   dNSName         [2]  IA5String,
--   x400Address     [3]  ORAddress,
--   directoryName   [4]  Name,
--   ediPartyName    [5]  EDIPartyName,
--   uniformResourceIdentifier [6] IA5String,
--   iPAddress       [7]  OCTET STRING,
--   registeredID    [8]  OBJECT IDENTIFIER
-- }
--
-- This generator covers 5 of the 9 alternatives: rfc822Name [1], dNSName [2],
-- directoryName [4], uniformResourceIdentifier [6], iPAddress [7].
-- Excluded: otherName [0] (AltNameXMPP/AltNameDNSSRV), x400Address [3],
-- ediPartyName [5], registeredID [8] — these are rarely used in practice.
arbitraryAltName :: Gen AltName
arbitraryAltName =
    oneof
        [ AltNameRFC822 <$> arbitraryAscii
        , AltNameDNS <$> arbitraryAscii
        , AltNameURI <$> (("https://" ++) <$> arbitraryAscii)
        , AltNameIP <$> arbitraryBS 4 4
        , AltDirectoryName <$> arbitrary
        ]

instance Arbitrary ASN1StringEncoding where
    arbitrary = elements [IA5, UTF8]

instance Arbitrary ASN1CharacterString where
    arbitrary = ASN1CharacterString <$> arbitrary <*> arbitraryBS 2 36

instance Arbitrary DistinguishedName where
    arbitrary = DistinguishedName <$> (choose (1, 5) >>= \l -> replicateM l arbitraryDE)
      where
        arbitraryDE = (,) <$> arbitrary <*> arbitrary

instance Arbitrary DateTime where
    arbitrary = timeConvert <$> (arbitrary :: Gen Elapsed)
instance Arbitrary Elapsed where
    arbitrary = Elapsed . Seconds <$> (choose (1, 100000000))

instance Arbitrary Extensions where
    arbitrary =
        Extensions
            <$> oneof
                [ pure Nothing
                , Just
                    <$> ( listOf1 $
                            oneof
                                [ extensionEncode <$> arbitrary <*> (arbitrary :: Gen ExtKeyUsage)
                                ]
                        )
                ]

instance Arbitrary ExtKeyUsageFlag where
    arbitrary = elements $ enumFrom KeyUsage_digitalSignature
instance Arbitrary ExtKeyUsage where
    arbitrary = ExtKeyUsage . sort . nub <$> listOf1 arbitrary

instance Arbitrary ExtKeyUsagePurpose where
    arbitrary =
        elements
            [ KeyUsagePurpose_ServerAuth
            , KeyUsagePurpose_ClientAuth
            , KeyUsagePurpose_CodeSigning
            , KeyUsagePurpose_EmailProtection
            , KeyUsagePurpose_TimeStamping
            , KeyUsagePurpose_OCSPSigning
            ]
instance Arbitrary ExtExtendedKeyUsage where
    arbitrary = ExtExtendedKeyUsage . nub <$> listOf1 arbitrary

-- =====================================================================
-- AC Extension types (RFC 5755 Section 4.3)
--
-- These Arbitrary instances generate random values for the three typed
-- AC extension types defined in Data.X509.AC.Extension. Each instance
-- is designed to produce values that satisfy ASN.1 DER codec constraints
-- (encode → decode roundtrip fidelity).
-- =====================================================================

-- | RFC 5755 Section 4.3.6 — No Revocation Available
--
-- ASN.1 definition:
--   id-ce-noRevAvail  OBJECT IDENTIFIER ::= { id-ce 56 }
--   The extension value is NULL.
--
-- DER encoding: The value is always the ASN.1 NULL type, encoded as '0500'H.
-- There is only one valid value (ExtNoRevAvail), so the generator is trivial.
--
-- Expected: extEncode produces [Null], extDecode [Null] returns Right ExtNoRevAvail.
-- NOT expected: Any non-NULL value (e.g., [OctetString ...]) would fail decoding.
instance Arbitrary ExtNoRevAvail where
    arbitrary = pure ExtNoRevAvail

-- | RFC 5755 Section 4.3.1 — Audit Identity
--
-- ASN.1 definition:
--   id-pe-ac-auditIdentity  OBJECT IDENTIFIER ::= { id-pe 4 }
--   The extension value is an OCTET STRING.
--
-- Per RFC 5755: "This extension contains audit identity information to
-- facilitate audit trails [...] The field is an OCTET STRING type."
--
-- This generator produces OCTET STRING values of length 1 to 20 bytes.
-- The length range is chosen to be representative of typical audit IDs.
--
-- Expected: extEncode produces [OctetString bs], extDecode [OctetString bs]
--   returns Right (ExtAuditIdentity bs) where bs is the same ByteString.
-- NOT expected: Empty OCTET STRING (length 0) — while technically valid in
--   ASN.1, an empty audit identity has no practical use.
instance Arbitrary ExtAuditIdentity where
    arbitrary = ExtAuditIdentity <$> arbitraryBS 1 20

-- | RFC 5755 Section 4.3.2 — TargetCert (part of Target CHOICE)
--
-- ASN.1 definition:
--   TargetCert ::= SEQUENCE {
--     targetCertificate  IssuerSerial,
--     targetName         GeneralName OPTIONAL,
--     certDigestInfo     ObjectDigestInfo OPTIONAL
--   }
--
-- targetCertificate is REQUIRED — a TargetCert without it is invalid.
-- targetName and certDigestInfo are both OPTIONAL.
--
-- This generator always sets optional fields to Nothing to avoid ambiguity
-- in the parseOptionalGeneralName parser (distinguishing GeneralName context
-- tags from ObjectDigestInfo's SEQUENCE start tag). The REQUIRED field
-- (targetCertificate) is always present via the IssuerSerial Arbitrary instance.
--
-- Expected: toASN1 produces [Start (Container Context 2), ...IssuerSerial...,
--   End (Container Context 2)]. fromASN1 reconstructs the same TargetCertDescription.
-- NOT expected: Missing targetCertificate field — this would cause a parse error.
instance Arbitrary TargetCertDescription where
    arbitrary =
        TargetCertDescription
            <$> arbitrary
            <*> pure Nothing
            <*> pure Nothing

-- | RFC 5755 Section 4.3.2 — Target (CHOICE type)
--
-- ASN.1 definition:
--   Target ::= CHOICE {
--     targetName   [0]  GeneralName,
--     targetGroup  [1]  GeneralName,
--     targetCert   [2]  TargetCert
--   }
--
-- Each alternative uses IMPLICIT context tagging:
--   - [0] IMPLICIT wraps a GeneralName (targetName)
--   - [1] IMPLICIT wraps a GeneralName (targetGroup)
--   - [2] IMPLICIT wraps a TargetCert SEQUENCE
--
-- This generator produces all three alternatives with equal probability.
--
-- Expected: Each alternative encodes with its respective context tag and
--   decodes back to the same constructor. E.g., TargetName encodes as
--   [Start (Container Context 0), ...GeneralName..., End (Container Context 0)].
-- NOT expected: A context tag outside {0, 1, 2} — the parser would fail with
--   "Target: expected [0], [1], or [2]".
instance Arbitrary Target where
    arbitrary =
        oneof
            [ TargetName <$> arbitraryAltName
            , TargetGroup <$> arbitraryAltName
            , TargetCert <$> arbitrary
            ]

-- | RFC 5755 Section 4.3.2 — Target Information extension
--
-- ASN.1 definition:
--   id-ce-targetInformation  OBJECT IDENTIFIER ::= { id-ce 55 }
--   SEQUENCE OF Target
--
-- Per RFC 5755: "If this extension is not present, then the AC does not
-- target any particular server."
-- When present, the SEQUENCE MUST contain at least one Target element.
--
-- This generator uses listOf1 to ensure the list is non-empty, satisfying
-- the "SEQUENCE OF" semantic constraint (an empty SEQUENCE OF is valid in
-- ASN.1 but meaningless for targeting).
--
-- Expected: extEncode produces [Start Sequence, ...targets..., End Sequence],
--   extDecode reconstructs ExtTargetInformation with the same list of Targets.
-- NOT expected: An empty target list — while ASN.1 permits empty SEQUENCE OF,
--   a targeting extension with no targets is semantically invalid.
instance Arbitrary ExtTargetInformation where
    arbitrary = ExtTargetInformation <$> listOf1 arbitrary

-- =====================================================================
-- AC core types (RFC 5755 Section 4)
--
-- These Arbitrary instances generate the core ASN.1 structures that
-- compose an Attribute Certificate. Each instance models the ASN.1
-- definition from RFC 5755 with constraints sufficient for codec
-- roundtrip fidelity (toASN1 → fromASN1 == identity).
-- =====================================================================

-- | BIT STRING — used in ObjectDigestInfo.objectDigest and IssuerSerial.issuerUID.
--
-- ASN.1 BIT STRING encoding in DER: the first content octet indicates the
-- number of unused bits (0-7) in the final octet. The remaining content
-- octets are the bit data.
--
-- This generator produces BIT STRINGs of 1-8 octets with 0-7 unused bits,
-- covering the typical range of digest values and unique identifiers.
--
-- Expected: toBitArray bs unused → fromBitArray produces identical bytes.
-- NOT expected: unused > 7 (invalid DER), or len = 0 with unused > 0.
instance Arbitrary BitArray where
    arbitrary = do
        len <- choose (1, 8)
        bs <- B.pack <$> vectorOf len arbitrary
        unused <- choose (0, 7)
        pure $ toBitArray bs unused

-- | RFC 5755 Section 4.2.2 — DigestedObjectType enumeration
--
-- ASN.1 definition:
--   DigestedObjectType ::= ENUMERATED {
--     publicKey       (0),
--     publicKeyCert   (1),
--     otherObjectTypes(2)
--   }
--
-- This enumeration determines what kind of object the digest covers
-- in ObjectDigestInfo. All three values are generated with equal probability.
--
-- Expected: Each value encodes as Enumerated 0/1/2 and decodes back.
-- NOT expected: Values outside {0, 1, 2} — the parser rejects unknown enum values.
instance Arbitrary DigestedObjectType where
    arbitrary = elements [OIDPublicKey, OIDPublicKeyCert, OIDOtherObjectTypes]

-- | RFC 5755 Section 4.2.2 — ObjectDigestInfo
--
-- ASN.1 definition:
--   ObjectDigestInfo ::= SEQUENCE {
--     digestedObjectType  DigestedObjectType,
--     otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
--     digestAlgorithm     AlgorithmIdentifier,
--     objectDigest        BIT STRING
--   }
--
-- Per RFC 5755: "If digestedObjectType is otherObjectTypes, then
-- otherObjectTypeID MUST be present." For publicKey (0) and
-- publicKeyCert (1), otherObjectTypeID MUST be absent.
--
-- This generator enforces the conditional presence constraint:
--   - OIDOtherObjectTypes → generates Just <OID>
--   - OIDPublicKey/OIDPublicKeyCert → generates Nothing
-- The digest is a fixed 32-byte BIT STRING (representative of SHA-256).
--
-- Expected: The conditional OID field is present/absent based on
--   digestedObjectType, and the roundtrip preserves this relationship.
-- NOT expected: otherObjectTypeID present when type is publicKey/publicKeyCert,
--   or absent when type is otherObjectTypes — these would produce encoding
--   mismatches during roundtrip.
instance Arbitrary ObjectDigestInfo where
    arbitrary = do
        dot <- arbitrary
        oid <- case dot of
            OIDOtherObjectTypes -> Just <$> arbitrary
            _ -> pure Nothing
        alg <- arbitrary
        digest <- B.pack <$> vectorOf 32 arbitrary
        pure $ ObjectDigestInfo dot oid alg digest

-- | RFC 5755 Section 4.2.2 — IssuerSerial
--
-- ASN.1 definition:
--   IssuerSerial ::= SEQUENCE {
--     issuer     GeneralNames,
--     serial     CertificateSerialNumber,
--     issuerUID  UniqueIdentifier OPTIONAL
--   }
--
-- GeneralNames is "SEQUENCE OF GeneralName" with at least one element.
-- CertificateSerialNumber is an INTEGER (must be positive per Section 4.2.5).
-- issuerUID is an OPTIONAL BIT STRING (UniqueIdentifier).
--
-- This generator produces:
--   - issuer: non-empty list of GeneralNames (listOf1)
--   - serial: positive integer via arbitraryPositive
--   - issuerUID: always Nothing (optional field not exercised)
--
-- Expected: Encodes as SEQUENCE { SEQUENCE OF GeneralName, INTEGER, [optional BIT STRING] }
--   and decodes back to identical IssuerSerial.
-- NOT expected: Empty issuer list (violates SEQUENCE OF SIZE (1..MAX)),
--   or zero/negative serial number.
instance Arbitrary IssuerSerial where
    arbitrary =
        IssuerSerial
            <$> listOf1 arbitraryAltName
            <*> arbitraryPositive
            <*> pure Nothing

-- | RFC 5755 Section 4.2.2 — Holder
--
-- ASN.1 definition:
--   Holder ::= SEQUENCE {
--     baseCertificateID  [0]  IssuerSerial OPTIONAL,
--     entityName         [1]  GeneralNames OPTIONAL,
--     objectDigestInfo   [2]  ObjectDigestInfo OPTIONAL
--   }
--
-- Per RFC 5755 Section 4.2.2: "For any environment, the holder field
-- MUST be populated. [...] At least one of the three options MUST be
-- used." A Holder with all three fields absent is invalid.
--
-- This generator produces:
--   - baseCertificateID [0]: via Arbitrary IssuerSerial (may be present)
--   - entityName [1]: randomly Nothing or Just (non-empty GeneralNames list)
--   - objectDigestInfo [2]: via Arbitrary ObjectDigestInfo (may be present)
--
-- Note: The Arbitrary IssuerSerial/ObjectDigestInfo instances may generate
-- Nothing-like values depending on upstream constraints, but this generator
-- exercises both present and absent optional fields.
--
-- Expected: Each OPTIONAL field uses IMPLICIT context tagging ([0], [1], [2])
--   in the DER encoding and decodes back correctly.
-- NOT expected: All three fields simultaneously absent (semantically invalid,
--   though the codec does not enforce this — profile validation does).
instance Arbitrary Holder where
    arbitrary =
        Holder
            <$> arbitrary
            <*> oneof [pure Nothing, Just <$> listOf1 arbitraryAltName]
            <*> arbitrary

-- | RFC 5755 Section 4.2.3 — V2Form (AttCertIssuer alternative)
--
-- ASN.1 definition:
--   V2Form ::= SEQUENCE {
--     issuerName           GeneralNames OPTIONAL,
--     baseCertificateID  [0]  IssuerSerial OPTIONAL,
--     objectDigestInfo   [1]  ObjectDigestInfo OPTIONAL
--   }
--
-- Per RFC 5755 Section 4.2.3: "Conformant ACs MUST use the v2Form choice,
-- which MUST contain one and only one GeneralName in the issuerName, and
-- that name MUST contain a non-empty distinguished name in the directoryName
-- field."
--
-- This generator produces:
--   - issuerName: non-empty GeneralNames (listOf1) — required for valid V2Form
--   - baseCertificateID: via Arbitrary IssuerSerial (OPTIONAL)
--   - objectDigestInfo: via Arbitrary ObjectDigestInfo (OPTIONAL)
--
-- Note: RFC 5755 profile validation further requires baseCertificateID and
-- objectDigestInfo to be absent, but the codec must handle their presence.
--
-- Expected: Encodes as SEQUENCE with optional context-tagged fields and
--   decodes back correctly.
-- NOT expected: Empty issuerName — the codec accepts it, but RFC 5755
--   profile validation rejects it.
instance Arbitrary V2Form where
    arbitrary =
        V2Form
            <$> listOf1 arbitraryAltName
            <*> arbitrary
            <*> arbitrary

-- | RFC 5755 Section 4.2.3 — AttCertIssuer (CHOICE)
--
-- ASN.1 definition:
--   AttCertIssuer ::= CHOICE {
--     v1Form   GeneralNames,       -- MUST NOT be used in this profile
--     v2Form   [0]  V2Form         -- v2 only
--   }
--
-- Per RFC 5755: "The AC issuer's name MUST be in the issuer field in the
-- v2Form [...] Conformant ACs MUST use the v2Form choice."
--
-- This generator produces BOTH v1Form and v2Form to exercise the codec's
-- ability to encode/decode both alternatives, even though v1Form is
-- prohibited by the RFC 5755 profile.
--
--   - AttCertIssuerV1: encodes as bare SEQUENCE OF GeneralName (no context tag)
--   - AttCertIssuerV2: encodes as [0] IMPLICIT V2Form
--
-- Expected: v1Form encodes without context tag, v2Form uses [0] IMPLICIT.
--   Both decode back to the correct constructor.
-- NOT expected: Confusion between the two forms — the parser distinguishes
--   them by the presence or absence of the [0] context tag.
instance Arbitrary AttCertIssuer where
    arbitrary =
        oneof
            [ AttCertIssuerV1 <$> listOf1 arbitraryAltName
            , AttCertIssuerV2 <$> arbitrary
            ]

-- | RFC 5755 Section 4.2.6 — AttCertValidityPeriod
--
-- ASN.1 definition:
--   AttCertValidityPeriod ::= SEQUENCE {
--     notBeforeTime  GeneralizedTime,
--     notAfterTime   GeneralizedTime
--   }
--
-- Per RFC 5755: "Attribute certificate validity is defined by the
-- notBeforeTime and notAfterTime values."
-- Both fields use GeneralizedTime (YYYYMMDDHHMMSSZ format).
--
-- This generator produces two random DateTime values. Note that
-- notBeforeTime may be after notAfterTime in the generated value —
-- this is intentional for codec testing (the codec does not enforce
-- temporal ordering; profile validation does).
--
-- Expected: Both fields encode as GeneralizedTime ASN.1 values and
--   decode back to the same DateTime pair.
-- NOT expected: UTCTime encoding — RFC 5755 mandates GeneralizedTime
--   for AC validity periods (unlike X.509 PKCs which allow UTCTime).
instance Arbitrary AttCertValidityPeriod where
    arbitrary = AttCertValidityPeriod <$> arbitrary <*> arbitrary

-- | RFC 5755 Section 4.2.7 — Attributes
--
-- ASN.1 definition:
--   Attributes ::= SEQUENCE OF Attribute
--   Attribute ::= SEQUENCE {
--     type   OBJECT IDENTIFIER,
--     values SET OF AttributeValue
--   }
--
-- Per RFC 5755: "The attributes field gives information about the AC holder."
-- The sequence MUST contain at least one Attribute.
--
-- This generator produces an Attributes value containing a single Role
-- attribute with a URI-based roleName. Role (RFC 5755 Section 4.4.5) is
-- chosen because it is the most commonly used AC attribute type and has
-- well-defined ASN.1 encoding.
--
-- Expected: Encodes as SEQUENCE OF (SEQUENCE { OID, SET OF AttributeValue })
--   and decodes back with the same OID and attribute values.
-- NOT expected: Empty Attributes sequence — while ASN.1 permits it, an AC
--   without any attributes is meaningless.
instance Arbitrary Attributes where
    arbitrary = do
        let mkRole uri = Attr_Role $ RoleSyntax Nothing (AltNameURI uri)
        uri <- ("https://" ++) <$> arbitraryAscii
        pure $ Attributes [encodeAttribute [mkRole uri]]

-- | RFC 5755 Section 4.1 — AttributeCertificateInfo (the unsigned AC body)
--
-- ASN.1 definition:
--   AttributeCertificateInfo ::= SEQUENCE {
--     version              AttCertVersion,       -- version is v2
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
-- RFC 5755 Section 4.2.1 (Version):
--   "The version field MUST have the value of v2."
--   AttCertVersion ::= INTEGER { v2(1) }
--
-- This generator produces AttributeCertificateInfo with:
--   - version: fixed at 1 (v2) — the ONLY valid version per RFC 5755.
--     Version v1 (value 0) is NOT backwards-compatible and MUST NOT be used.
--   - holder: random Holder (Section 4.2.2)
--   - issuer: random AttCertIssuer (Section 4.2.3)
--   - signature: random AlgorithmIdentifier
--   - serialNumber: positive integer (Section 4.2.5)
--   - attrCertValidityPeriod: random time pair (Section 4.2.6)
--   - attributes: random Attributes (Section 4.2.7)
--   - issuerUniqueID: always Nothing (optional, rarely used)
--   - extensions: always Nothing (optional, tested separately)
--
-- Expected: version encodes as INTEGER 1, all fields encode in order per
--   the SEQUENCE definition, and fromASN1 reconstructs the identical structure.
-- NOT expected: version = 0 (v1) — the parser would accept it but it violates
--   RFC 5755. Extensions with unknown critical OIDs would also be problematic
--   for profile validation (but not for codec testing).
instance Arbitrary AttributeCertificateInfo where
    arbitrary =
        AttributeCertificateInfo 1
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitraryPositive
            <*> arbitrary
            <*> arbitrary
            <*> pure Nothing
            <*> pure (Extensions Nothing)

-- =====================================================================
-- Attribute syntax types (RFC 5755 Section 4.4 and related RFCs)
--
-- These Arbitrary instances generate random values for the attribute
-- types that can appear in the AC's attributes field (Section 4.2.7).
-- Each attribute type has its own OID and ASN.1 syntax. The IsAttribute
-- type class provides attrEncode/attrDecode for roundtrip testing.
-- =====================================================================

-- | RFC 5755 Section 4.4.5 — RoleSyntax
--
-- ASN.1 definition:
--   RoleSyntax ::= SEQUENCE {
--     roleAuthority  [0]  GeneralNames OPTIONAL,
--     roleName       [1]  GeneralName
--   }
--
-- Per RFC 5755: "The roleName field MUST be present [...] the preferred
-- form for the roleName GeneralName is a uniformResourceIdentifier."
--
-- This generator produces:
--   - roleAuthority: always Nothing (optional, rarely used in practice)
--   - roleName: a random GeneralName via arbitraryAltName
--
-- Expected: roleName [1] IMPLICIT GeneralName encodes and decodes correctly.
--   roleAuthority, when absent, produces no ASN.1 tags.
-- NOT expected: Missing roleName — the parser requires it. A RoleSyntax with
--   a non-URI roleName is valid for codec testing but produces a warning in
--   profile validation.
instance Arbitrary RoleSyntax where
    arbitrary =
        RoleSyntax
            <$> pure Nothing
            <*> arbitraryAltName

-- | RFC 5755 Section 4.4.5 — Role attribute wrapper
--
-- OID: id-at-role {2 5 4 72}
-- Per RFC 5755: "The id-at-role attribute type [...] specifies the role(s)
-- that the AC holder is authorized to assume."
--
-- This is the IsAttribute wrapper for RoleSyntax. The attrEncode function
-- produces an Attribute with OID {2 5 4 72} and the DER-encoded RoleSyntax
-- as the value. attrDecode reverses this process.
--
-- Expected: attrEncode produces Attribute { type = OID {2 5 4 72}, values = ... },
--   and attrDecode reconstructs the identical Attr_Role.
-- NOT expected: Wrong OID — attrDecode would fail with "unknown attribute OID".
instance Arbitrary Attr_Role where
    arbitrary = Attr_Role <$> arbitrary

-- | RFC 5755 Section 4.4.1 — SvceAuthInfo (Service Authentication Information)
--
-- ASN.1 definition:
--   SvceAuthInfo ::= SEQUENCE {
--     service   GeneralName,
--     ident     GeneralName,
--     authInfo  OCTET STRING OPTIONAL
--   }
--
-- Per RFC 5755: "This attribute provides information that can be used to
-- authenticate the AC holder to the service."
-- OID: id-aca-authenticationInfo {1 3 6 1 5 5 7 10 1}
--
-- This generator produces:
--   - service: random GeneralName (identifies the target service)
--   - ident: random GeneralName (identifies the holder)
--   - authInfo: randomly Nothing or a 1-20 byte OCTET STRING
--
-- Expected: All three fields encode in SEQUENCE order. The optional authInfo
--   field, when present, encodes as OCTET STRING.
-- NOT expected: Missing service or ident — both are REQUIRED fields.
instance Arbitrary SvceAuthInfo where
    arbitrary =
        SvceAuthInfo
            <$> arbitraryAltName
            <*> arbitraryAltName
            <*> oneof [pure Nothing, Just <$> arbitraryBS 1 20]

-- | RFC 5755 Section 4.4.1 — SvceAuthInfo attribute wrapper
--
-- OID: id-aca-authenticationInfo {1 3 6 1 5 5 7 10 1}
--
-- Expected: attrEncode produces an Attribute with the correct OID,
--   attrDecode reconstructs the identical Attr_SvceAuthInfo.
-- NOT expected: OID mismatch or malformed SvceAuthInfo SEQUENCE.
instance Arbitrary Attr_SvceAuthInfo where
    arbitrary = Attr_SvceAuthInfo <$> arbitrary

-- | RFC 5755 Section 4.4.2 — AccessIdentity attribute wrapper
--
-- ASN.1: Uses the same SvceAuthInfo SEQUENCE structure, but with a
-- different OID: id-aca-accessIdentity {1 3 6 1 5 5 7 10 2}
--
-- Per RFC 5755: "This attribute provides the holder's identity to
-- use when accessing the indicated service."
-- The difference from SvceAuthInfo is semantic, not syntactic.
--
-- Expected: attrEncode uses OID {1 3 6 1 5 5 7 10 2} (not {... 10 1}).
-- NOT expected: Confusion with SvceAuthInfo OID — the two attributes have
--   identical SEQUENCE structure but different OIDs.
instance Arbitrary Attr_AccessIdentity where
    arbitrary = Attr_AccessIdentity <$> arbitrary

-- | RFC 4476 / RFC 5755 Section 4.4 — IetfAttrSyntax value (CHOICE)
--
-- ASN.1 definition:
--   IetfAttrSyntax ::= SEQUENCE {
--     policyAuthority  [0]  GeneralNames OPTIONAL,
--     values           SEQUENCE OF CHOICE {
--                        octets    OCTET STRING,
--                        oid       OBJECT IDENTIFIER,
--                        string    UTF8String
--                      }
--   }
--
-- This generator produces one of the three CHOICE alternatives:
--   - IetfAttrSyntaxOctets: OCTET STRING (1-20 bytes)
--   - IetfAttrSyntaxOid: OBJECT IDENTIFIER (random OID)
--   - IetfAttrSyntaxString: UTF8String (ASCII subset)
--
-- Expected: Each alternative encodes with its native ASN.1 tag (0x04, 0x06,
--   0x0C respectively) and decodes back to the correct constructor.
-- NOT expected: Mixing tag types within a single SEQUENCE OF — all values
--   in one IetfAttrSyntax SHOULD use the same CHOICE alternative per RFC 4476.
instance Arbitrary IetfAttrSyntaxValue where
    arbitrary =
        oneof
            [ IetfAttrSyntaxOctets <$> arbitraryBS 1 20
            , IetfAttrSyntaxOid <$> arbitrary
            , IetfAttrSyntaxString <$> arbitraryAscii
            ]

-- | RFC 4476 / RFC 5755 Section 4.4 — IetfAttrSyntax
--
-- Used by both ChargingIdentity and Group attributes.
--
-- This generator produces:
--   - policyAuthority: always Nothing (optional)
--   - values: non-empty list of IetfAttrSyntaxValue
--
-- Expected: Encodes as SEQUENCE { [optional [0] GeneralNames], SEQUENCE OF value }
--   and decodes back to the identical structure.
-- NOT expected: Empty values list (SEQUENCE OF SIZE (1..MAX) requires >= 1).
instance Arbitrary IetfAttrSyntax where
    arbitrary =
        IetfAttrSyntax
            <$> pure Nothing
            <*> listOf1 arbitrary

-- | RFC 5755 Section 4.4.3 — Charging Identity attribute wrapper
--
-- OID: id-aca-chargingIdentity {1 3 6 1 5 5 7 10 3}
-- Syntax: IetfAttrSyntax (RFC 4476)
--
-- Per RFC 5755: "This attribute indicates to the target that billing
-- for the service should be applied to the indicated identity."
--
-- Expected: attrEncode uses OID {1 3 6 1 5 5 7 10 3}, attrDecode
--   reconstructs the identical Attr_ChargingIdentity with IetfAttrSyntax.
-- NOT expected: Wrong OID or malformed IetfAttrSyntax.
instance Arbitrary Attr_ChargingIdentity where
    arbitrary = Attr_ChargingIdentity <$> arbitrary

-- | RFC 5755 Section 4.4.4 — Group attribute wrapper
--
-- OID: id-aca-group {1 3 6 1 5 5 7 10 4}
-- Syntax: IetfAttrSyntax (RFC 4476)
--
-- Per RFC 5755: "This attribute carries information about group
-- memberships of the AC holder."
--
-- Expected: attrEncode uses OID {1 3 6 1 5 5 7 10 4}.
-- NOT expected: Confusion with ChargingIdentity (same IetfAttrSyntax
--   structure, different OID).
instance Arbitrary Attr_Group where
    arbitrary = Attr_Group <$> arbitrary

-- | RFC 5755 Section 4.4.6 — ClassList flag enumeration
--
-- ASN.1 definition:
--   ClassList ::= BIT STRING {
--     unmarked    (0),
--     unclassified(1),
--     restricted  (2),
--     confidential(3),
--     secret      (4),
--     topSecret   (5)
--   }
--
-- This generator produces one of the six defined flags. The ClassList
-- is used in the Clearance attribute to specify security classification.
--
-- Expected: Each flag maps to a specific bit position (0-5) in the BIT STRING.
-- NOT expected: Bit positions beyond 5 — while DER permits longer BIT STRINGs,
--   they would not correspond to any defined classification level.
instance Arbitrary ClassListFlag where
    arbitrary = elements $ enumFrom ClassList_unmarked

-- | RFC 5755 Section 4.4.6 / RFC 3281 — Clearance
--
-- ASN.1 definition:
--   Clearance ::= SEQUENCE {
--     policyId         OBJECT IDENTIFIER,
--     classList        ClassList DEFAULT {unclassified},
--     securityCategories  SET OF SecurityCategory OPTIONAL
--   }
--
-- Per RFC 5755: "The clearance attribute [...] is used to specify the
-- security clearance of the AC holder."
--
-- This generator produces:
--   - policyId: random OID (identifies the security policy)
--   - classList: sorted, deduplicated, non-empty list of ClassListFlags
--     (sort and nub ensure deterministic BIT STRING encoding for roundtrip)
--   - securityCategories: always Nothing (OPTIONAL, complex structure)
--
-- Expected: policyId encodes as OID, classList as BIT STRING with flags
--   at positions 0-5, and the SEQUENCE roundtrips correctly.
-- NOT expected: Duplicate flags in classList (would cause non-deterministic
--   BIT STRING encoding, breaking roundtrip). Empty classList (the DEFAULT
--   {unclassified} means absence encodes differently from presence).
instance Arbitrary Clearance where
    arbitrary =
        Clearance
            <$> arbitrary
            <*> (sort . nub <$> listOf1 arbitrary)
            <*> pure Nothing

-- | RFC 5755 Section 4.4.6 — Clearance attribute wrapper
--
-- OID: id-at-clearance {2 5 4 55}
--
-- Expected: attrEncode uses OID {2 5 4 55}, attrDecode reconstructs
--   the identical Attr_Clearance with Clearance structure.
-- NOT expected: Wrong OID or malformed Clearance SEQUENCE.
instance Arbitrary Attr_Clearance where
    arbitrary = Attr_Clearance <$> arbitrary

instance Arbitrary Certificate where
    arbitrary =
        Certificate
            <$> pure 2
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary RevokedCertificate where
    arbitrary =
        RevokedCertificate
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary CRL where
    arbitrary =
        CRL
            <$> pure 1
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

property_unmarshall_marshall_id
    :: (Show o, Arbitrary o, ASN1Object o, Eq o) => o -> Bool
property_unmarshall_marshall_id o =
    case got of
        Right (gotObject, [])
            | gotObject == o -> True
            | otherwise ->
                error ("object is different: " ++ show gotObject ++ " expecting " ++ show o)
        Right (gotObject, l) ->
            error
                ( "state remaining: "
                    ++ show l
                    ++ " marshalled: "
                    ++ show oMarshalled
                    ++ " parsed: "
                    ++ show gotObject
                )
        Left e ->
            error
                ( "parsing failed: "
                    ++ show e
                    ++ " object: "
                    ++ show o
                    ++ " marshalled as: "
                    ++ show oMarshalled
                )
  where
    got = fromASN1 oMarshalled
    oMarshalled = toASN1 o []

property_extension_id :: (Show e, Eq e, Extension e) => e -> Bool
property_extension_id e = case extDecode (extEncode e) of
    Left err -> error err
    Right v
        | v == e -> True
        | otherwise -> error ("expected " ++ show e ++ " got: " ++ show v)

-- | Roundtrip property for IsAttribute types (RFC 5755 Section 4.2.7 / 4.4).
--
-- This property verifies that for any attribute value 'a':
--   attrDecode (head (attrEncode a)) == Right a
--
-- The test exercises the complete attribute encoding pipeline:
--   1. attrEncode: converts the typed Haskell value to a list of raw Attribute
--      structures (SEQUENCE { OID, SET OF ASN1 values })
--   2. head: takes the first (and typically only) encoded Attribute
--   3. attrDecode: parses the raw Attribute back to the typed Haskell value
--      by matching the OID and decoding the SET OF values
--
-- This verifies that:
--   - The attribute OID is correctly encoded and recognized during decoding
--   - The ASN.1 value encoding is deterministic (DER canonical form)
--   - All fields in the attribute syntax survive the roundtrip unchanged
--
-- Expected result: Right v where v == a (identity roundtrip).
-- Failure modes:
--   - Left err: decoding failed — indicates an encoding/parsing bug
--   - Right v where v /= a: value changed during roundtrip — indicates
--     a non-deterministic encoding or incorrect field parsing
property_attribute_id
    :: (Show a, Eq a, IsAttribute a) => a -> Bool
property_attribute_id a =
    case attrDecode (head (attrEncode a)) of
        Right v
            | v == a -> True
            | otherwise ->
                error ("attribute is different: " ++ show v ++ " expecting " ++ show a)
        Left err ->
            error ("attribute decode failed: " ++ err ++ " for: " ++ show a)

main =
    defaultMain $
        testGroup
            "X509"
            [ testGroup
                "marshall"
                [ testProperty "pubkey" (property_unmarshall_marshall_id :: PubKey -> Bool)
                , testProperty "privkey" (property_unmarshall_marshall_id :: PrivKey -> Bool)
                , testProperty
                    "signature alg"
                    (property_unmarshall_marshall_id :: SignatureALG -> Bool)
                , testGroup
                    "extension"
                    [ testProperty "key-usage" (property_extension_id :: ExtKeyUsage -> Bool)
                    , testProperty
                        "extended-key-usage"
                        (property_extension_id :: ExtExtendedKeyUsage -> Bool)
                    ]
                , testProperty
                    "extensions"
                    (property_unmarshall_marshall_id :: Extensions -> Bool)
                , testProperty
                    "certificate"
                    (property_unmarshall_marshall_id :: Certificate -> Bool)
                , testProperty "crl" (property_unmarshall_marshall_id :: CRL -> Bool)
                  -- =============================================================
                  -- AC Extension roundtrip tests (RFC 5755 Section 4.3)
                  --
                  -- These tests verify that each AC extension type satisfies:
                  --   extDecode (extEncode e) == Right e
                  -- for 100 randomly generated values.
                  --
                  -- The Extension type class provides:
                  --   extOID: the extension's OID (used to match during parsing)
                  --   extHasNestedASN1: whether the value is wrapped in an outer OCTET STRING
                  --   extEncode: Haskell value → [ASN1]
                  --   extDecode: [ASN1] → Either String e
                  -- =============================================================
                , testGroup
                    "ac-extension"
                    [ -- | RFC 5755 Section 4.3.6 — No Revocation Available
                      -- OID: {2 5 29 56}
                      -- Verifies: extEncode ExtNoRevAvail produces [Null],
                      --   and extDecode [Null] returns Right ExtNoRevAvail.
                      -- There is exactly one valid value, so this test verifies
                      --   the trivial roundtrip: NULL → NULL.
                      testProperty "noRevAvail" (property_extension_id :: ExtNoRevAvail -> Bool)
                      -- | RFC 5755 Section 4.3.1 — Audit Identity
                      -- OID: {1 3 6 1 5 5 7 1 4}
                      -- Verifies: extEncode (ExtAuditIdentity bs) produces [OctetString bs],
                      --   and extDecode [OctetString bs] returns Right (ExtAuditIdentity bs).
                      -- The OCTET STRING content (1-20 bytes) must survive roundtrip unchanged.
                    , testProperty "auditIdentity" (property_extension_id :: ExtAuditIdentity -> Bool)
                      -- | RFC 5755 Section 4.3.2 — Target Information
                      -- OID: {2 5 29 55}
                      -- Verifies: A SEQUENCE OF Target values (each using IMPLICIT context
                      --   tags [0]/[1]/[2] for TargetName/TargetGroup/TargetCert) encodes to
                      --   [Start Sequence, ...targets..., End Sequence] and decodes back to
                      --   the identical ExtTargetInformation with the same list of Targets.
                      -- This is the most complex extension test because Target is a CHOICE
                      --   type with three alternatives, each using different context tags.
                    , testProperty "targetInformation" (property_extension_id :: ExtTargetInformation -> Bool)
                    ]
                  -- =============================================================
                  -- AC core type ASN1Object roundtrip tests (RFC 5755 Section 4)
                  --
                  -- These tests verify that each AC core ASN.1 structure satisfies:
                  --   fromASN1 (toASN1 o []) == Right (o, [])
                  -- for 100 randomly generated values.
                  --
                  -- The ASN1Object type class provides:
                  --   toASN1: Haskell value → [ASN1] (DER-compatible ASN.1 stream)
                  --   fromASN1: [ASN1] → Either String (value, [ASN1] remaining)
                  --
                  -- A successful roundtrip verifies:
                  --   1. All fields encode to their correct ASN.1 types and tags
                  --   2. IMPLICIT context tags [0], [1], [2] are correctly applied
                  --   3. OPTIONAL fields (Nothing/Just) are correctly present/absent
                  --   4. SEQUENCE/SET structure is correctly nested
                  --   5. No residual ASN.1 elements remain after parsing
                  -- =============================================================
                , testGroup
                    "attribute-certificate"
                    [ -- | RFC 5755 Section 4.2.6 — AttCertValidityPeriod
                      -- Verifies: SEQUENCE { GeneralizedTime, GeneralizedTime } roundtrip.
                      -- Both notBeforeTime and notAfterTime must encode as GeneralizedTime
                      -- (not UTCTime) and decode back to the same DateTime values.
                      testProperty
                        "attCertValidityPeriod"
                        (property_unmarshall_marshall_id :: AttCertValidityPeriod -> Bool)
                      -- | RFC 5755 Section 4.2.2 — IssuerSerial
                      -- Verifies: SEQUENCE { GeneralNames, INTEGER, [OPTIONAL BIT STRING] }
                      -- The issuer field (SEQUENCE OF GeneralName) must contain at least one
                      -- element. The serial must be a positive INTEGER. The optional issuerUID
                      -- (BIT STRING) roundtrips correctly whether present or absent.
                    , testProperty
                        "issuerSerial"
                        (property_unmarshall_marshall_id :: IssuerSerial -> Bool)
                      -- | RFC 5755 Section 4.2.2 — ObjectDigestInfo
                      -- Verifies: SEQUENCE { ENUMERATED, [OPTIONAL OID], AlgId, BIT STRING }
                      -- The conditional otherObjectTypeID field must be present when
                      -- digestedObjectType is otherObjectTypes (2) and absent otherwise.
                      -- This tests the parser's ability to handle conditional OPTIONAL fields.
                    , testProperty
                        "objectDigestInfo"
                        (property_unmarshall_marshall_id :: ObjectDigestInfo -> Bool)
                      -- | RFC 5755 Section 4.2.2 — Holder
                      -- Verifies: SEQUENCE { [0] IssuerSerial OPTIONAL,
                      --   [1] GeneralNames OPTIONAL, [2] ObjectDigestInfo OPTIONAL }
                      -- All three fields use IMPLICIT context tags. The parser must correctly
                      -- distinguish between the tags and handle any combination of present/absent
                      -- fields. At least one field should be present (profile constraint).
                    , testProperty
                        "holder"
                        (property_unmarshall_marshall_id :: Holder -> Bool)
                      -- | RFC 5755 Section 4.2.3 — V2Form
                      -- Verifies: SEQUENCE { GeneralNames, [0] IssuerSerial OPTIONAL,
                      --   [1] ObjectDigestInfo OPTIONAL }
                      -- The issuerName (GeneralNames) is the primary issuer identifier.
                      -- baseCertificateID [0] and objectDigestInfo [1] are OPTIONAL and
                      -- use IMPLICIT context tags that must not be confused with each other.
                    , testProperty
                        "v2Form"
                        (property_unmarshall_marshall_id :: V2Form -> Bool)
                      -- | RFC 5755 Section 4.2.3 — AttCertIssuer (CHOICE)
                      -- Verifies: The parser correctly distinguishes between:
                      --   v1Form: bare SEQUENCE OF GeneralName (no context tag)
                      --   v2Form: [0] IMPLICIT V2Form (wrapped in context tag 0)
                      -- A bug in this parser previously caused double SEQUENCE unwrapping
                      -- for v1Form (fixed in commit 74c73cc). This test prevents regression.
                    , testProperty
                        "attCertIssuer"
                        (property_unmarshall_marshall_id :: AttCertIssuer -> Bool)
                      -- | RFC 5755 Section 4.1 — AttributeCertificateInfo (complete AC body)
                      -- Verifies the entire AC structure roundtrip:
                      --   SEQUENCE { INTEGER (version=1), Holder, AttCertIssuer,
                      --     AlgorithmIdentifier, INTEGER (serial), AttCertValidityPeriod,
                      --     SEQUENCE OF Attribute, [OPTIONAL UniqueIdentifier],
                      --     [OPTIONAL Extensions] }
                      -- This is the most comprehensive roundtrip test — it exercises all
                      -- the sub-type codecs together in a single SEQUENCE. A failure here
                      -- could indicate a bug in any of the constituent type codecs.
                    , testProperty
                        "attributeCertificateInfo"
                        (property_unmarshall_marshall_id :: AttributeCertificateInfo -> Bool)
                    ]
                  -- =============================================================
                  -- AC attribute roundtrip tests (RFC 5755 Section 4.4)
                  --
                  -- These tests verify that each attribute syntax type satisfies:
                  --   attrDecode (head (attrEncode a)) == Right a
                  -- for 100 randomly generated values.
                  --
                  -- The IsAttribute type class provides:
                  --   attrOID: the attribute's OID (e.g., {2 5 4 72} for Role)
                  --   attrEncode: Haskell value → [Attribute] (OID + SET OF values)
                  --   attrDecode: Attribute → Either String a
                  --
                  -- A successful roundtrip verifies:
                  --   1. The attribute OID is correctly encoded and matched during decode
                  --   2. The attribute value SET OF encoding preserves all fields
                  --   3. Complex CHOICE types (e.g., IetfAttrSyntaxValue) decode to
                  --      the correct alternative
                  -- =============================================================
                , testGroup
                    "ac-attribute"
                    [ -- | RFC 5755 Section 4.4.5 — Role
                      -- OID: {2 5 4 72}
                      -- Verifies: RoleSyntax { roleAuthority [0] OPTIONAL, roleName [1] }
                      -- encodes with the correct OID and decodes back. Tests that the
                      -- IMPLICIT [1] tag on roleName is correctly applied.
                      testProperty "role" (property_attribute_id :: Attr_Role -> Bool)
                      -- | RFC 5755 Section 4.4.1 — Service Authentication Information
                      -- OID: {1 3 6 1 5 5 7 10 1}
                      -- Verifies: SvceAuthInfo { service, ident, authInfo OPTIONAL }
                      -- with the correct OID. Tests that the optional authInfo OCTET STRING
                      -- is correctly present/absent.
                    , testProperty "svceAuthInfo" (property_attribute_id :: Attr_SvceAuthInfo -> Bool)
                      -- | RFC 5755 Section 4.4.2 — Access Identity
                      -- OID: {1 3 6 1 5 5 7 10 2}
                      -- Verifies: Same SvceAuthInfo structure but different OID.
                      -- Tests that the OID distinguishes AccessIdentity from SvceAuthInfo
                      -- despite having identical SEQUENCE structures.
                    , testProperty "accessIdentity" (property_attribute_id :: Attr_AccessIdentity -> Bool)
                      -- | RFC 5755 Section 4.4.3 — Charging Identity
                      -- OID: {1 3 6 1 5 5 7 10 3}
                      -- Verifies: IetfAttrSyntax { policyAuthority OPTIONAL,
                      --   values SEQUENCE OF CHOICE { octets, oid, string } }
                      -- Tests that the CHOICE type values decode to the correct alternative.
                    , testProperty "chargingIdentity" (property_attribute_id :: Attr_ChargingIdentity -> Bool)
                      -- | RFC 5755 Section 4.4.4 — Group
                      -- OID: {1 3 6 1 5 5 7 10 4}
                      -- Verifies: Same IetfAttrSyntax structure as ChargingIdentity
                      -- but different OID. Tests OID discrimination.
                    , testProperty "group" (property_attribute_id :: Attr_Group -> Bool)
                      -- | RFC 5755 Section 4.4.6 — Clearance
                      -- OID: {2 5 4 55}
                      -- Verifies: Clearance { policyId OID, classList BIT STRING,
                      --   securityCategories OPTIONAL }
                      -- Tests that the BIT STRING classList (with flags at positions 0-5)
                      -- encodes deterministically (sorted, deduplicated) and roundtrips.
                    , testProperty "clearance" (property_attribute_id :: Attr_Clearance -> Bool)
                    ]
                ]
            ]
