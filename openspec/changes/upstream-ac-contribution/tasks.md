# Tasks: upstream-ac-contribution

pr-clean 10 コミットの行き先対応表（design.md D6 の取り込み漏れ防止）:

| pr-clean コミット | 内容 | 行き先 |
|---|---|---|
| a8107bf | AC 型（AttCert / Attribute / X509AC） | PR#2 |
| 44aa414 | Data.X509.AC.Extension | PR#2 |
| 4cf10fb | ECDSA / DSA DER 修正 | **PR#1** |
| 4cf10fb | GeneralizedTime 修正（AC validity） | PR#2 |
| ffe2169 | directoryName tagging 修正 | **PR#1**（AltNameDN へ適応） |
| ffe2169 | V2Form / GeneralNames IMPLICIT tagging 修正 | PR#2 |
| 0127996 / 977ac26 / 9aafd89 | QuickCheck roundtrip・Arbitrary・RFC コメント | PR#2 |
| e9e984f | crypton-x509-ac-validation パッケージ | PR#3 |
| fc769a0 / 0e977dc | SBV 証明 | **除外**（fork 専用） |

## 1. 共通準備

- [ ] 1.1 upstream/main (c20fcc7) から `pr1-rfc-encoding-fixes` ブランチを作成
- [ ] 1.2 upstream の `fourmolu.yaml` と CI ワークフロー（GitHub Actions）の内容を確認し、ローカル検証手順（隔離 project file での `cabal build` / `cabal test`）を確立
- [ ] 1.3 OpenSSL でテストベクタを生成: (a) directoryName SAN を含む証明書、(b) RFC 5755 準拠 AC（PR#2 用）

## 2. PR#1: RFC 準拠エンコーディング修正

- [ ] 2.1 `AlgorithmIdentifier.hs`: ECDSA / DSA の `toASN1` で parameters を省略（pr-clean 4cf10fb の 3 行 + RFC 引用コメント）
- [ ] 2.2 `Ext.hs`: `AltNameDN` の encode を EXPLICIT constructed `[4]` に修正、decode は constructed / primitive 両受理（pr-clean ffe2169 の方式を upstream の AltNameDN 実装へ適応）
- [ ] 2.3 テスト追加: DER バイト列の直接比較（parameters 不在、constructed タグ）、OpenSSL テストベクタの decode、旧形式 decode の後方互換
- [ ] 2.4 検証: `cabal build` + `cabal test`（crypton-x509 / crypton-x509-validation）全 PASS、`fourmolu --mode check` 差分ゼロ
- [ ] 2.5 コミット整理（修正 1 件 = 1 コミット、本文に RFC 根拠とテストベクタの出自を記載）

## 3. PR#2: AC 型の追加

- [ ] 3.1 `pr2-attribute-certificate` ブランチを PR#1 の上に作成
- [ ] 3.2 pr-clean から `AttCert.hs` / `Attribute.hs` / `AC/Extension.hs` / `X509AC.hs` を取り込み（`git checkout upstream-pr-clean -- <paths>`）
- [ ] 3.3 upstream の現行 `Ext.hs` に適応: `Attribute.hs` の import を `getAddr` / `encodeAltName`（upstream 既存名）に書き換え、`AltDirectoryName` 参照を `AltNameDN` に統一。pr-clean の rename・`AltDirectoryName` 追加は持ち込まない
- [ ] 3.4 `Ext.hs`: `getAddr` / `parseGeneralNames` / `encodeAltName` / `encodeGeneralNames` を export リストに追加（変更はこの数行のみ）
- [ ] 3.5 `Data.X509AC` ファサードを補完: pattern synonym（`HolderBaseCertificateID` 等）と PR#3 が必要とする全シンボルを再 export
- [ ] 3.6 cabal: exposed-modules に `Data.X509AC`、other-modules に `AttCert` / `Attribute` / `AC.Extension` を追加
- [ ] 3.7 テスト: pr-clean の 932 行分を `Tests/TestAC.hs` に分離（QuickCheck roundtrip / Arbitrary / RFC コメント、SBV 部分は除外）、`Tests.hs` に hook 数行、AC テストベクタ decode テストを追加
- [ ] 3.8 検証: `cabal build` + `cabal test` 全 PASS、`grep -ri sbv` ゼロ件、fourmolu 差分ゼロ、`Data.X509` の既存 export 不変を確認
- [ ] 3.9 コミット整理（型 → 拡張 → テストの論理単位）

## 4. PR#3: 検証パッケージ

- [ ] 4.1 `pr3-ac-validation` ブランチを PR#2 の上に作成
- [ ] 4.2 pr-clean から `crypton-x509-ac-validation/` を取り込み（SBV.hs と sbv-tests フラグは除外）
- [ ] 4.3 import を公開 API に統一: `Data.X509.AttCert` / `Data.X509.AlgorithmIdentifier` 直 import を `Data.X509AC` / `Data.X509` に書き換え（不足があれば 3.5 のファサードを補完して PR#2 に反映）
- [ ] 4.4 `cabal.project` と CI ワークフローにパッケージを登録
- [ ] 4.5 検証: 全パッケージ `cabal build` + `cabal test` PASS、hidden モジュール直 import ゼロ、fourmolu 差分ゼロ
- [ ] 4.6 コミット整理

## 5. 提出と追跡

- [ ] 5.1 3 ブランチを origin (tatac1/crypton-certificate) に push
- [ ] 5.2 PR#1 を upstream へ提出（本文: バグの説明、RFC 引用、テストベクタ、互換性への配慮）
- [ ] 5.3 PR#1 マージ後、PR#2 を rebase して提出（本文: RFC 5755 の概要、モジュール構成、非破壊性の説明、CRL 前例への言及）
- [ ] 5.4 PR#2 マージ後、PR#3 を rebase して提出
- [ ] 5.5 各 PR のレビュー指摘対応（AltNameDN 修正が拒否された場合は design.md のフォールバックに切替）
- [ ] 5.6 全マージ後: fork を upstream 実装へ切替える change を別途起票
