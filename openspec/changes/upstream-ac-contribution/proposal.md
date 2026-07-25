## Why

fork 元 (upstream) の [kazu-yamamoto/crypton-certificate](https://github.com/kazu-yamamoto/crypton-certificate) には X.509 Attribute Certificate (RFC 5755) の実装が存在しない。本 fork は AC 実装（型・エンコーディング・検証）を保有しており、下流の haskell-tcg-cert（TCG Platform Certificate / EK 検証）が依存している。upstream にマージされれば fork の維持コスト（履歴分岐による merge 不能、cherry-pick 追従）が恒久的に解消され、Haskell エコシステムにも RFC 5755 実装が提供される。

ゴール: **upstream に PR を提出しマージされること**。そのために「メンテナーがレビューしやすい」「既存コードを破壊しない」「メンテナンスが容易なモジュール形式」の 3 要件を満たす構成に再編する。

先行作業 `upstream-pr-clean` ブランチ（2026-02-14、upstream/main の旧先端 fedffa5 ベース、10 コミット）が土台。fork main の AC 実装（2026-01-15）より新しく、明示的 export リスト・fourmolu 整形・IMPLICIT tagging / DER 修正済みのため、これを最新 upstream/main (c20fcc7) に載せ替えて再構成する。

## What Changes

段階的 PR 3 本に分割し、それぞれ upstream/main (c20fcc7) から分岐したブランチとして作成する。

- **PR#1 `pr1-rfc-encoding-fixes`** — 独立した RFC 準拠バグ修正（既存コード変更 約20行）
  - AlgorithmIdentifier: ECDSA / DSA 署名の parameters を省略（RFC 5758 §3.2 / RFC 3279 §2.2.2 で MUST absent。現状 `Null` を出力）
  - directoryName: upstream が 2026-05 に追加した `AltNameDN` は primitive `[4]` で encode / decode するが、`GeneralName` は CHOICE のため `directoryName [4]` は EXPLICIT constructed が正（RFC 5280 §4.2.1.6）。encode を constructed に修正し、decode は両形式を受理（後方互換）。OpenSSL 生成の実証テストベクタを添付
- **PR#2 `pr2-attribute-certificate`** — AC 型の追加（crypton-x509、新規追加 約1,200行、PR#1 の上に積む）
  - 新規: `Data.X509.AttCert` / `Data.X509.Attribute` / `Data.X509.AC.Extension`（いずれも other-modules）、`Data.X509AC`（唯一の新規公開モジュール = ファサード、upstream の `Data.X509` パターン踏襲）、`Tests/TestAC.hs`（QuickCheck roundtrip）
  - 既存変更（最小）: cabal へのモジュール追加、`Ext.hs` の既存未公開トップレベル関数（`getAddr` / `encodeAltName` 等）の export 追加数行、`Tests/Tests.hs` への hook 数行
- **PR#3 `pr3-ac-validation`** — 検証パッケージ（新規パッケージのみ、既存コード非接触、PR#2 の上に積む）
  - 新規パッケージ `crypton-x509-ac-validation`（Validation / Path / Revocation / Signature / Validity、約1,100行＋テスト）
  - import は公開 API（`Data.X509AC` / `Data.X509` / `Data.X509.Validation`）に統一
  - `cabal.project` / CI ワークフローへのパッケージ登録

fork 専用に残すもの（PR に含めない）:

- SBV 形式検証テスト（約2,600行）と `sbv-tests` フラグ
- `AttributeRaw` モジュール（pr-clean で廃止済み）、TCG 系パッケージ

## Capabilities

### New Capabilities

- `attribute-certificate-upstream`: upstream へ提案する RFC 5755 AC 実装一式の要件（PR 3 本の受け入れ条件、モジュール境界、非破壊性、テスト、整形規約）

### Modified Capabilities

該当なし（fork 自体のランタイム挙動は変えない。PR ブランチは upstream/main ベースで fork main とは独立）。

### Removed Capabilities

該当なし。

## Scope Classification (Required)

| Scope | yes | no |
|-------|-----|-----|
| Haskell ライブラリ API（公開モジュール追加） | [x] | [ ] |
| 既存公開 API の破壊的変更 | [ ] | [x] |
| ASN.1 エンコーディング挙動（バグ修正） | [x] | [ ] |
| 新規パッケージ | [x] | [ ] |
| cabal / CI 構成 | [x] | [ ] |
| 新規依存の追加 | [ ] | [x] |
| fork 独自機能の変更（TCG / SBV） | [ ] | [x] |

## Cross-cutting Impact (Required)

### 公開 API への影響

- PR#1: `AltNameDN` の encode 出力バイト列が変わる（primitive → constructed）。型シグネチャ変更なし。decode は両形式受理のため既存データの読取りは維持
- PR#2: 公開モジュール +1（`Data.X509AC`）。`Ext.hs` の export 追加は `Data.X509` の丸ごと再 export を通じて公開 API に追加される（追加のみ、非破壊）
- PR#3: 新規パッケージのため既存 API 影響なし

### 依存関係

新規依存なし。`crypton-x509-ac-validation` の依存（base / bytestring / crypton-asn1-types / crypton-x509 / crypton-x509-validation / time-hourglass）はすべて upstream 既存依存の範囲内。

### 互換性

- upstream の既存テストがすべて PASS すること（各 PR ブランチで確認）
- fork 側: PR ブランチは fork main に影響しない。将来 upstream にマージされた後、fork は upstream 実装へ切替（別 change）

### 検証

- 各 PR ブランチで `cabal build all` + `cabal test`（macOS ローカルは隔離 project file 方式、CI 相当は GitHub Actions）
- PR#1: 修正前後の DER バイト列比較 + OpenSSL 生成証明書の decode テストベクタ
- PR#2: QuickCheck roundtrip（encode → decode = id）+ 実 AC テストベクタ
- fourmolu で upstream の `fourmolu.yaml` に整形一致

## Impact

- **upstream リポジトリ**: crypton-x509（モジュール追加 + 小修正）、crypton-x509-ac-validation（新規）、cabal.project、CI
- **fork リポジトリ**: PR 用ブランチ 3 本の追加のみ。main / sync-upstream は非接触
- **リスク**: AltNameDN 修正（PR#1）は upstream の新規コードへの変更のため受理が不確実。拒否された場合は AC 側を upstream 表現に合わせる代替案に切替（相互運用性は低下、design.md 参照）
- **下流（haskell-tcg-cert）**: 影響なし（fork の既存実装を当面維持）
