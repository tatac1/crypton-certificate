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

- [x] 1.1 upstream/main (c20fcc7) から `pr1-rfc-encoding-fixes` ブランチを作成
- [x] 1.2 upstream の `fourmolu.yaml` と CI ワークフロー（GitHub Actions）の内容を確認し、ローカル検証手順（隔離 project file での `cabal build` / `cabal test`）を確立 — ベースライン: 改変前 upstream/main で両テストスイート PASS を実測（GHC 9.10.2 / macOS）
- [x] 1.3 OpenSSL でテストベクタを生成: (a) directoryName SAN を含む証明書 ✓（constructed 0xA4 を実測確認）。(b) AC ベクタは OpenSSL CLI に AC 生成機能がないため、PR#3 の TestVectors.hs（固定 DER ベクタ）で代替（spec 改訂済）

## 2. PR#1: RFC 準拠エンコーディング修正

- [x] 2.1 `AlgorithmIdentifier.hs`: ECDSA / DSA の `toASN1` で parameters を省略（pr-clean 4cf10fb の 3 行 + RFC 引用コメント）
- [x] 2.2 `Ext.hs`: `AltNameDN` の encode を EXPLICIT constructed `[4]` に修正、decode は constructed / primitive 両受理
- [x] 2.3 テスト追加: TDD（RED 実測→GREEN）。encode は OpenSSL ベクタと**バイト単位一致**、旧 primitive 形式の後方互換 decode も検証
- [x] 2.4 検証: 全 12 テスト PASS（crypton-x509）+ validation PASS、fourmolu 差分ゼロ
- [x] 2.5 コミット整理: `0c7d2a7`（AlgorithmIdentifier）+ `4a97a45`（directoryName）

## 3. PR#2: AC 型の追加

- [x] 3.1 `pr2-attribute-certificate` ブランチを PR#1 の上に作成
- [x] 3.2 pr-clean から `AttCert.hs` / `Attribute.hs` / `AC/Extension.hs` / `X509AC.hs` を取り込み
- [x] 3.3 【改訂 design D4】AC 側 17+ 箇所の書き換えより Ext.hs 内部（6 箇所）の rename が小さいため、`getAddr`→`parseGeneralName` / `encodeAltName`→`encodeGeneralName` の rename を採用（module-private のため公開 API 不変）。`AltDirectoryName`→`AltNameDN` 統一は実施
- [x] 3.4 `Ext.hs`: 4 関数を haddock 付きで export
- [x] 3.5 ファサード補完: pattern synonym 3 種 + `GeneralNames`（PR#3 ビルドで発覚し fixup で追補）
- [x] 3.6 cabal: exposed に `Data.X509AC`、other-modules に 3 モジュール追加
- [x] 3.7 【改訂 design D5】orphan インスタンスは Main から import 不能のため `Tests/Arbitrary.hs` に無変更移動し、AC テストは `Tests/TestAC.hs` に分離（SBV 除外）。hook は 1 行
- [x] 3.8 検証: 全 28 テスト PASS、sbv ゼロ件、fourmolu 差分ゼロ
- [x] 3.9 コミット整理: `a598d15`（core types）→ `995f420`（extensions + facade）→ `ec74ffa`（tests）。各コミット単独ビルドを detached HEAD で実測
- [x] 3.10 【追加】PR#1 修正の実効確認: arbitraryAltName が `AltNameDN` を含み、roundtrip が constructed 経路を通過

## 4. PR#3: 検証パッケージ

- [x] 4.1 `pr3-ac-validation` ブランチを PR#2 の上に作成
- [x] 4.2 pr-clean から取り込み（SBV.hs / sbv-tests フラグ / CPP 分岐を除去、cabal を upstream 様式で書き直し、test 依存 memory→ram、crypton-x509 >= 1.9.1）
- [x] 4.3 import を公開 API に統一（`Data.X509AC` / `Data.X509`）。hidden 直 import ゼロを確認。Tests/Certificate.hs のローカル `SignedAttributeCertificate` 別名はファサード提供に置換
- [x] 4.4 `cabal.project` に登録（CI の build targets は `all:*` のため追加設定不要。stack.yaml は upstream 側が旧ディレクトリ名のまま壊れている既存問題のためスコープ外）
- [x] 4.5 検証: `cabal build all` exit 0（全 6 パッケージ）、全 39 テスト PASS、fourmolu 差分ゼロ
- [x] 4.6 コミット整理: `b0539e7`（package）+ `694fbba`（tests）

## 5. 提出と追跡

- [ ] 5.1 3 ブランチを origin (tatac1/crypton-certificate) に push
- [ ] 5.2 PR#1 を upstream へ提出（本文: バグの説明、RFC 引用、テストベクタ、互換性への配慮）
- [ ] 5.3 PR#1 マージ後、PR#2 を rebase して提出（本文: RFC 5755 の概要、モジュール構成、非破壊性の説明、CRL 前例への言及）
- [ ] 5.4 PR#2 マージ後、PR#3 を rebase して提出
- [ ] 5.5 各 PR のレビュー指摘対応（AltNameDN 修正が拒否された場合は design.md のフォールバックに切替）
- [ ] 5.6 全マージ後: fork を upstream 実装へ切替える change を別途起票
