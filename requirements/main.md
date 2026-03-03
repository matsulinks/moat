# Security-System 要件定義 v1.0

## 1. 背景・目的

2026年3月現在、OpenClawは30,000〜42,000超のインスタンスがインターネットに露出しており、
ClawJacked攻撃、悪意スキル混入（ClawHub）、prompt injection経由の横移動・credential exfilが
多発している。本プロジェクトは、複数台の専用ミニPCでOpenClawを安全に並行運用するための
多層防御システムを設計・実装する。

## 2. 解決すべき脅威モデル（Defense in Depth 7層）

| Layer | 脅威 | 対象 |
|-------|------|------|
| 1 | 外部からの直接アクセス・横移動 | ネットワーク分離 |
| 2 | コンテナブレイクアウト・権限昇格 | Docker sandbox |
| 3 | 不正命令・アカウント乗っ取り | 認証・アクセス制御 |
| 4 | credential exfil・芋づる漏洩 | 機密情報管理 |
| 5 | 悪意スキル・prompt injection | スキル/プロンプト防御 |
| 6 | 高リスクツール実行・データ破壊 | 実行時最小権限 |
| 7 | 侵害検知遅延・対応遅延 | 監視・インシデント対応 |

## 2.5 運用方針（必須）

**専用機原則の厳格適用（Must have）**
- すべてのOpenClawインスタンスは、他の重要アプリ・ブラウザ・メール・銀行アプリが一切インストールされていない
  **専用ミニPC/NUC/Raspberry Pi 5/Mac Mini** のみで運用する
- メインPC・仕事用ノートPC・家族共有PCへのインストールは**絶対禁止**
- 専用機には最小限のOS（Ubuntu Server 24.04 LTS推奨）＋Docker＋Tailscaleのみインストール
- これにより、OpenClaw侵害時のblast radiusを「その専用機のみ」に限定する

## 3. 機能要件（FR）

### FR-1: インスタンス分離・独立運用
- 各専用ミニPCで独立したOpenClawインスタンスを運用
- インスタンス間の直接通信は原則禁止
- 1台侵害時に他インスタンスへの影響がゼロであること

### FR-2: 認証・アクセス制御
- インスタンス毎に独立したTelegram/Discordアカウント（共有禁止）
- Token認証（64文字以上ランダム）+ pairing allowlist
- グループチャットではrequireMention必須

### FR-3: 機密情報管理
- 環境変数への平文記述禁止
- Infisical CLIによるJIT注入（起動時のみ、実行後は消去）
- YubiKey + age暗号化オプション（高セキュリティ専用機向け）
- 定期ローテーション（最大90日、推奨30日）

### FR-4: スキル管理・プロンプト防御
- ClawHub直接利用禁止
- 自前Gitリポジトリのみ許可（pinned version必須）
- 導入前: VirusTotal + openclaw skill audit --deep + 人間レビュー
- 実行時: PromptGuard / LLM-as-Judge（スコア0.8以上でブロック）

### FR-5: 実行時最小権限
- ツールはデフォルトdenyからスタート
- 高リスクグループ（fs:write, exec, automation, browser, runtime）はTelegram承認必須
- networkは443/TCPのみ許可（ホワイトリストドメイン）

### FR-6: 監視・インシデント対応
- Falco（eBPF）によるsyscall/コンテナイベント監視
- Prometheus + Grafanaによるメトリクス可視化
- CRITICALアラートはTelegramに即時通知
- 緊急遮断モード（fail-closed）実装必須

### FR-7: 緊急遮断モード
- 発動条件: CRITICAL複数回（15分以内3回以上）+ secrets系同時発火
- 発動時: 全プロンプト入力ブロック + plugins凍結 + 高リスクツールdeny
- 解除条件: 原因調査完了 + 人間承認（Primary Operatorのみ）

## 4. 非機能要件（NFR）

### NFR-1: セキュリティ
- コンテナブレイクアウト耐性（Docker sandbox:all + cap_drop ALL + read_only FS）
- ゼロトラストネットワーク（Tailscale default-deny ACL）
- 秘密鍵は物理デバイス外に出ない（YubiKey PIVスロット）

### NFR-2: 可用性・運用性
- Dockerイメージ更新による簡易アップデート（pull + compose up）
- ダウンタイム最小（ローリング更新可）
- ログ量: 1日数GB以内（圧縮/ローテーション）

### NFR-3: パフォーマンス
- 承認ワークフローのレイテンシ影響: +5秒以内
- MiniPC（N100 8GB RAM）で快適動作

## 5. スコープ外（Phase 1）
- インターネット公開gateway（localhost/Tailscale限定のみ）
- ClawHub自動インストール機能
- モバイル/AndroidネイティブOpenClaw対応
- 大規模（10台超）クラスタ管理
- 企業向けRBAC/audit trail
- LLMモデル自体のfine-tuning/poisoning対策

## 6. 優先順位付け（MoSCoW法）
- **Must have**: インスタンス分離、認証分離、機密暗号化、スキルホワイトリスト、
  人間承認、高リスクtools deny、基本監視、専用機原則
- **Should have**: YubiKey/Vault統合、自動ローテーション、Falco syscall監視、
  Prometheusダッシュボード
- **Could have**: PromptGuard自動統合、週次audit自動レポート
- **Won't have (Phase 1)**: 公開Web UI、自動スキルレビューAI、federated multi-user
