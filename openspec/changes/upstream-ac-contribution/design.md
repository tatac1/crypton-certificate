# Design: Attribute Certificate の upstream 貢献

## Context

- upstream = kazu-yamamoto/crypton-certificate（main = c20fcc7、2026-06 時点）
- fork の履歴は作り直されており upstream と merge 不能（偽の add/add 衝突）。PR ブランチは **upstream/main から直接分岐**する
- 土台 = `upstream-pr-clean` ブランチ（10 コミット）。fork main の AC より新しく、後発バグ修正（IMPLICIT tagging / ECDSA・DSA DER / GeneralizedTime）を含む
- upstream は 2026-05 に name-constraints 実装（PR #30）で `AltNameDN`（directoryName）を自前追加した。pr-clean の `AltDirectoryName` + `parseGeneralName` 公開と機能重複するため、rebase 時に解消が必要

## Goals / Non-Goals

**Goals:**

- upstream にマージされる構成（レビュー容易・既存非破壊・保守容易なモジュール形式）
- 各 PR が独立した価値を持ち、単独でレビュー・マージ可能

**Non-Goals:**

- SBV 形式検証の upstream 化（fork 専用に残す）
- TCG 系パッケージの upstream 化
- fork main への AC 実装の変更（PR ブランチとは独立）

## Decisions

### D1: 段階的 PR 3 本（採用）vs 単一 PR vs AC 型のみ

段階的 3 本を採用。単一 PR は差分 3,500 行超でレビュー負担が大きく、upstream のマージ履歴（小粒 PR 中心）に合わない。AC 型のみではゴールの半分で止まる。段階化により PR#1 は独立したバグ修正として先行受理を狙え、PR#2/#3 は「追加のみ」で非破壊性を明確化できる。

### D2: directoryName は EXPLICIT constructed に修正（PR#1 に含める）

upstream の `AltNameDN` は primitive `[4]` に DER を埋め込む実装だが、`GeneralName ::= CHOICE { ..., directoryName [4] Name, ... }` の `Name` は CHOICE のため implicit tag 不可、`[4]` は事実上 EXPLICIT constructed（RFC 5280）。OpenSSL 等の実装は constructed を生成・期待するため、現状のままでは相互運用しない。RFC 5755 で AC の issuer は directoryName 形式が MUST であり、AC 実装（PR#2）の前提となる。

- encode: constructed `[4] { Name }` に修正
- decode: constructed / primitive 両受理（upstream 現行実装で書かれたデータへの後方互換）
- 実証: OpenSSL 生成証明書のテストベクタを添付し「コードで示す」

代替案（issue で先に相談）は往復時間がかかり、修正の正しさはテストベクタで自明に示せるため PR 直行とする。**拒否された場合のフォールバック**: PR#2 の AC 実装を upstream の primitive 表現に合わせる（相互運用性は犠牲、fork では引き続き constructed を維持）。

### D3: 公開面はファサード 1 本（`Data.X509AC`）のみ

upstream の露出パターン（`Data.X509` / `Data.X509.EC` のみ公開、実装は other-modules + ファサードで丸ごと再 export）に厳密に合わせる。

- `Data.X509AC` のみ exposed-modules に追加。`AttCert` / `Attribute` / `AC.Extension` は other-modules
- pr-clean が行っていた `AlgorithmIdentifier` の expose 化は撤回（`Data.X509` が `module Data.X509.AlgorithmIdentifier` を丸ごと再 export 済みで不要）
- ファサードには pattern synonym（`HolderBaseCertificateID` 等）を含む、PR#3 が必要とする全シンボルを再 export する（現状の pr-clean ファサードは pattern synonym 非掲載のため補完）

### D4: `Ext.hs` への変更は「export 追加」のみ

`Data.X509.Attribute` は GeneralName の parse / encode を必要とする。upstream の name-constraints 実装で `getAddr` / `encodeAltName` が既にトップレベル化されている（未 export）ため、**export リストへの追加のみ**行い、pr-clean の rename（`getAddr` → `parseGeneralName`）は不要な churn として撤回。upstream 自身が直近で `recognizedOIDs` に同じ操作をしており、スタイル整合する。

### D5: テストは新規ファイルに分離

pr-clean は既存 `Tests/Tests.hs` に 932 行を追記していた。既存ファイルの diff を数行（hook のみ）に抑えるため `Tests/TestAC.hs` に分離し、cabal の other-modules に追加する。

### D6: pr-clean の 10 コミットは論理単位に再構成

fix コミット（IMPLICIT tagging、DER 修正）を対象機能に畳み込み、PR ごとに独立でビルド・テストが通るコミット列に組み直す。cherry-pick ではなくコンテンツの載せ替え（`git checkout upstream-pr-clean -- <paths>` + 手動調整）で行う。理由: pr-clean は旧 upstream ベースのため、そのまま rebase すると Ext.hs で upstream の新実装（AltNameDN / name-constraints）と衝突し、履歴が汚れる。

## Risks / Trade-offs

| リスク | 影響 | 緩和策 |
|--------|------|--------|
| D2 の AltNameDN 修正が拒否される | PR#2 の相互運用性 | テストベクタで正当性を明示。拒否時は upstream 表現に追従（フォールバック） |
| PR#2 の受理が遅延し PR#3 が塩漬け | ゴール未達 | PR#2 を「追加のみ」に絞り受理障壁を最小化。PR#3 は PR#2 マージ後に提出 |
| pr-clean 再構成時の後発 fix の取り込み漏れ | 品質退行 | tasks.md で fix コミット逐一の対応表を作り、roundtrip テストで検証 |
| fourmolu 整形差でレビューノイズ | レビュー負担 | 提出前に upstream の fourmolu.yaml で全ファイル整形 |

## Migration Plan

1. PR#1 → PR#2 → PR#3 の順に提出。各 PR は前段のマージを待って rebase 後に提出
2. すべてマージされた後、fork は upstream 実装へ切替（別 change として起票）
3. 拒否・長期停滞時は fork 維持を継続（現状維持のためロールバック不要）

## Open Questions

- upstream の CI（GitHub Actions）への `crypton-x509-ac-validation` 追加方法は PR#3 作成時に upstream のワークフロー定義を確認して決定
- `Data.X509AC` というモジュール名（`Data.X509.AC` ではなくフラット）は pr-clean の選択を維持。upstream レビューで指摘があれば rename に応じる
