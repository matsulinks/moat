# Security-System 全体アーキテクチャ統合 v1.0

## 1. 全体目的（再掲）

複数台の専用ミニPCでOpenClawを安全に並行運用するための多層防御システム。
1台の侵害が他インスタンス・クラウドサービス・個人情報に波及しないことを最優先目標とする。

**コア原則**（全レイヤー共通）
- 専用機原則の厳格適用
- デフォルトdeny + ゼロトラスト
- 人間インザループ（高リスク操作は承認必須）
- Fail-closed設計（疑わしいものは通さない）

## 2. 全7層構成図

```
[ユーザー (Telegram/Discord)]
         ↓ (TLS + Token Auth + Mention Required)
[Tailscale Mesh VPN — Layer 1]
   default-deny ACL / tag:openclaw-instance
         ↓
┌────────────────────────────────────────────────────┐
│         Dedicated Mini-PC x N (専用機原則)          │
│  ┌──────────────┐  ┌──────────────┐  ...           │
│  │ MiniPC #1    │  │ MiniPC #2    │                │
│  │ Layer 2:     │  │ Layer 2:     │                │
│  │ Docker       │  │ Docker       │                │
│  │ sandbox:all  │  │ sandbox:all  │                │
│  └──────┬───────┘  └──────┬───────┘                │
│         │                 │                        │
│  ┌──────▼─────────────────▼──────────┐             │
│  │       Infisical Server            │             │
│  │    Layer 4: 機密情報管理           │             │
│  │  (tag:infisical-server)           │             │
│  └───────────────────────────────────┘             │
│                                                    │
│  ┌──────────────────────────────────────┐          │
│  │       Central Monitoring             │          │
│  │  Prometheus + Grafana + Falco        │          │
│  │  Layer 7: 監視・インシデント対応      │          │
│  └──────────────────────────────────────┘          │
└────────────────────────────────────────────────────┘

（※ メインPC・仕事PCとは物理的に完全分離）
```

## 3. 各層のテキスト要約

| Layer | 名称 | 主要技術 | 役割 |
|-------|------|---------|------|
| 1 | ネットワーク分離 | Tailscale + default-deny ACL + tag制御 | 外部露出ゼロ、インスタンス間横移動阻止 |
| 2 | コンテナ/サンドボックス | Docker sandbox:all + non-root + read_only + cap_drop ALL | プロセス脱獄・権限昇格防止 |
| 3 | 認証・アクセス制御 | 独立Token + pairing allowlist + requireMention | 不正命令の入口遮断 |
| 4 | 機密情報管理 | Infisical JIT注入 + YubiKeyオプション + 定期ローテーション | 平文残存防止、芋づる漏洩阻止 |
| 5 | スキル・プロンプト防御 | ClawHub禁止 + 自前Git + PromptGuard + LLM-as-Judge + 緊急遮断 | サプライチェーン攻撃・prompt injection阻止 |
| 6 | 実行時最小権限 | default deny + elevated承認必須 + network 443のみ | たとえ突破されても被害を極限まで制限 |
| 7 | 監視・インシデント対応 | Falco + Prometheus + Grafana + Telegramアラート | 異常の早期発見・通知・被害限定 |

## 4. 典型的な実行フロー

```
1. ユーザー → Telegram/Discordでプロンプト送信
2. Layer 3: token + mention + pairing allowlist で認証通過
3. Layer 1: Tailscaleメッシュ経由で専用ミニPCに到達
4. Layer 5: PromptGuard + LLM-as-Judge で危険プロンプト判定
   → 危険: 即ブロック + アラート
   → 安全: 次へ
5. Layer 6: 必要ツール権限チェック
   → elevatedグループ: Telegram承認ワークフロー（30秒timeout=deny）
   → 承認: 実行 / 拒否・timeout: deny + ログ
6. OpenClaw Coreで実行
7. Layer 7: 全syscall・メトリクス監視
   → 異常検知: アラート（WARNING/CRITICAL）
   → CRITICAL複数 + secrets同時: 緊急遮断モード発動（fail-closed）
8. 結果をTelegramでユーザーへ返答（またはブロック通知）
```

## 5. 責任分界

| 処理フェーズ | 主担当Layer | 自動処理 | 人間承認が必要なケース | 緊急時（Primary Operator） |
|------------|-----------|---------|-------------------|--------------------------|
| 認証・到達 | 3/1 | token/pairing/ACL検証 | — | token revoke / allowlist修正 |
| プロンプト検証 | 5 | PromptGuard + LLM-as-Judge | — | Guard無効化 / 誤ブロック解除 |
| 権限チェック・承認 | 6 | default deny / 低リスク自動allow | elevatedツール（fs:write, exec, browser等） | 承認ボタン押下 / 一時allow発行 |
| 実行・監視 | 7 | Falco/Prometheus常時監視 | — | アラート対応 / 緊急遮断解除 |
| 緊急遮断モード | 5+7 | 条件満たしたら自動発動（fail-closed） | 解除（原因調査＋承認） | 調査・ログ確認・解除ボタン押下 |
| スキル導入/config変更 | 5/6 | — | 全スキル追加・権限緩和 | Gitレビュー・コミット・適用確認 |

**運用指針**:
- 自動処理: 低リスク・日常操作（80〜90%）
- 人間承認: 高リスク実行時のみ（10〜20%）
- 緊急時オペレーション: CRITICALアラート or 緊急遮断発動時のみ（<1%）
