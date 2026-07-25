## ADDED Requirements

### Requirement: PR#1 — RFC 準拠エンコーディング修正が独立してマージ可能である

PR#1 ブランチ (`pr1-rfc-encoding-fixes`) SHALL は upstream/main (c20fcc7) から分岐し、AC 実装への言及なしに独立した価値を持つバグ修正のみを含む。変更は (1) ECDSA / DSA 署名の AlgorithmIdentifier における parameters 省略（RFC 5758 §3.2 / RFC 3279 §2.2.2）、(2) `AltNameDN` (directoryName) の EXPLICIT constructed `[4]` encode への修正と constructed / primitive 両形式の decode 受理、の 2 点に限定する（MUST）。各修正には根拠 RFC の引用コメントとテストを添付する。

#### Scenario: ECDSA 署名の AlgorithmIdentifier に parameters が含まれない

- **WHEN** `SignatureALG hash PubKeyALG_EC` を `toASN1` でエンコードする
- **THEN** 出力 ASN.1 列は `Start Sequence : OID ... : End Sequence` であり `Null` を含まない
- **THEN** DSA (`PubKeyALG_DSA`) も同様に `Null` を含まない

#### Scenario: directoryName が constructed で出力され両形式を読める

- **WHEN** `AltNameDN dn` をエンコードする
- **THEN** 出力は constructed `[4]` コンテナ内に `Name` (SEQUENCE) を含む（primitive `Other Context 4` ではない）
- **WHEN** OpenSSL が生成した directoryName SAN を含む証明書（テストベクタ）をデコードする
- **THEN** `AltNameDN` として正しくパースされる
- **WHEN** 旧実装（primitive `[4]` に DER 埋め込み）で書かれたデータをデコードする
- **THEN** 後方互換として同じ `AltNameDN` にパースされる

#### Scenario: 既存テストが退行しない

- **WHEN** PR#1 ブランチで `cabal test`（crypton-x509 / crypton-x509-validation）を実行する
- **THEN** upstream 既存のテストがすべて PASS する

### Requirement: PR#2 — AC 型が非破壊のモジュール追加として構成される

PR#2 ブランチ (`pr2-attribute-certificate`) SHALL は PR#1 の上に積み、crypton-x509 パッケージへ RFC 5755 の型とエンコーディングを追加する。公開モジュールの追加は `Data.X509AC`（ファサード）1 本のみとし（MUST）、`Data.X509.AttCert` / `Data.X509.Attribute` / `Data.X509.AC.Extension` は other-modules に置く。既存ファイルの変更は (a) cabal のモジュール追加、(b) `Data.X509.Ext` の既存トップレベル関数の export 追加、(c) `Tests/Tests.hs` へのテスト hook 追加、に限定し、既存関数の rename・移動・挙動変更を行なってはならない（MUST NOT）。

#### Scenario: ファサードから AC の全機能に到達できる

- **WHEN** 利用者が `import Data.X509AC` のみを書く
- **THEN** `SignedAttributeCertificate` / `AttributeCertificateInfo` / `Holder`（pattern synonym 含む）/ `AttCertIssuer` / `V2Form` / Attribute 型一式 / AC 拡張一式 / encode・decode・アクセサ関数が利用できる

#### Scenario: 既存公開 API が変化しない（追加を除く）

- **WHEN** PR#2 適用前後で `Data.X509` の export を比較する
- **THEN** 既存シンボルの削除・型変更がなく、追加は `Data.X509.Ext` 経由の GeneralName parse / encode 関数のみである

#### Scenario: roundtrip プロパティが成立する

- **WHEN** QuickCheck が任意の AC 型値（Arbitrary インスタンス）を生成し encode → decode する
- **THEN** 元の値と一致する（`Tests/TestAC.hs`、SBV に依存しない）

#### Scenario: 実 AC テストベクタがデコードできる

- **WHEN** OpenSSL / 既存実装で生成された RFC 5755 準拠 AC (DER) をデコードする
- **THEN** `decodeSignedAttributeCertificate` が成功し、holder / issuer / attributes が期待値と一致する

### Requirement: PR#3 — 検証パッケージが既存コードに触れず追加される

PR#3 ブランチ (`pr3-ac-validation`) SHALL は PR#2 の上に積み、新規パッケージ `crypton-x509-ac-validation`（`Data.X509.AC.Validation` とサブモジュール Path / Revocation / Signature / Validity）を追加する。既存パッケージのソース変更は禁止し（MUST NOT）、許容される既存ファイル変更は `cabal.project` と CI ワークフローへのパッケージ登録のみとする。crypton-x509 からの import は公開 API（`Data.X509AC` / `Data.X509`）に限定する（MUST）。新規の外部依存を導入してはならない（MUST NOT、依存は upstream 既存依存の範囲内）。

#### Scenario: 公開 API のみで検証パッケージがビルドできる

- **WHEN** `crypton-x509-ac-validation` をビルドする
- **THEN** crypton-x509 の hidden モジュール（`Data.X509.AttCert` 等）への直接 import が存在せず、ビルドが成功する

#### Scenario: RFC 5755 検証がテストで確認される

- **WHEN** `cabal test crypton-x509-ac-validation` を実行する
- **THEN** 署名・有効期間・パス・失効の検証テスト（TestACValidation / StaticTests / TestVectors）が PASS する

### Requirement: SBV 形式検証は upstream PR に含めない

upstream へ提出する 3 つの PR ブランチ SHALL は SBV への依存・`sbv-tests` フラグ・SBV テストファイルを一切含まない（MUST NOT）。SBV 形式検証は fork 側でのみ維持する。

#### Scenario: PR ブランチに sbv が現れない

- **WHEN** 各 PR ブランチで `grep -ri sbv` を cabal ファイルとソースに対して実行する
- **THEN** 一致がない

### Requirement: upstream のコーディング規約に整形一致する

3 つの PR ブランチの全 Haskell ソース SHALL は upstream の `fourmolu.yaml` による整形で差分ゼロであり、新規モジュールには upstream 同等のモジュールヘッダ（License / Maintainer / Stability / Portability）と明示的 export リストを備える（MUST）。

#### Scenario: fourmolu が差分を出さない

- **WHEN** PR ブランチで `fourmolu --mode check` を upstream の設定で実行する
- **THEN** 全ファイルが差分なしで通過する
