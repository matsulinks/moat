# Layer 3: 認証・アクセス制御 仕様 v1.0

## 1. 目的
OpenClawへのアクセスを誰が・どのように・いつ制御するかを定義し、不正命令の入口を根本的に塞ぐ。
1アカウント乗っ取りで全インスタンスが機能不全になる最悪シナリオを排除する。

## 2. 基本原則
- **アカウント完全分離**: 各インスタンス毎に独立したTelegram/Discordアカウント（共有禁止）
- **ゼロトラスト認証**: token auth + pairing allowlist + requireMention必須
- **最小権限発行者**: 承認ワークフローはPrimary Operatorのみが最終承認可能
- **乗っ取り耐性**: 1アカウント侵害時、他インスタンスに影響を与えない設計
- **監査必須**: 全ログイン・コマンド発行をLayer 7でログ化

## 3. 認証方式

- **auth.mode**: "token"（推奨）
- **token生成**: 64文字以上ランダム文字列（Infisicalで管理・JIT注入）
- **requireMention**:
  - グループチャット: **true**（@botname なしのメッセージは無視 → 誤操作/スパム防止）
  - DM: 任意（環境依存）。操作性優先の場合false可だが推奨はtrue
- **pairing allowlist**: 初期ペアリング時にadmin-deviceのIDを明示登録
  → 以降はallowlist外からのpairing試行を完全ブロック
- **session管理**: `dmScope: "per-channel-peer"`（チャンネル・ピアごとに独立）
- **多要素的強化**: Telegram 2FA必須 + 端末保護（PIN/生体認証）
  ※ Bot運用ではSecret Chatを前提にしない（Telegram Bot APIは通常チャットベースのため）

## 4. config.yaml 推奨設定

```yaml
auth:
  mode: token
  token: "{{ INFISICAL_TOKEN_OPENCLAW_AUTH }}"
  requireMention: true                         # グループ必須、DMは任意
  pairing:
    allowlist:
      - "user_id:123456789"                    # Primary OperatorのTelegram ID
  session:
    dmScope: "per-channel-peer"
    dmPolicy: "pairing"
```

## 5. 承認者ロールとアクセス制御

- **Primary Operator（あなたのみ）**: 全インスタンスの承認権限を持つTelegramアカウント
  - Layer 6の高リスクツール呼び出し時に通知・ボタン承認
- **Secondary Viewer（監査用、オプション）**: ログ閲覧専用アカウント（read-only）
  - 承認権限なし、通知受信のみ
- **禁止事項**:
  - 同一Telegramアカウントを複数インスタンスで共有
  - OAuth連携や公開Botの使用（token漏洩リスク）

## 6. 乗っ取り耐性強化

- 各インスタンスのtoken・allowlistは独立（他インスタンスのtokenを共有しない）
- Infisicalプロジェクトもインスタンスごとに分離（`instance01-prod`, `instance02-prod`）
- 異常検知時: Layer 7でtoken使用元IP/デバイス異常検知 → 即時token revokeスクリプト

## 7. tokenローテーションSLO

| 種別 | 定期ローテーション | 緊急ローテーション手順 |
|------|--------------------|----------------------|
| OPENCLAW_AUTH_TOKEN | 最大90日（推奨30日）、Infisical Rotation Templatesで自動化 | 新token発行→Infisical登録→JIT注入で自動適用→旧token即時revoke→Layer 7で旧token使用検知 |

## 8. 実装・運用ガイドライン
1. 各専用ミニPCで別Telegram Bot作成 → tokenをInfisical登録
2. admin-deviceから各インスタンスに1回だけpairing
3. 週次でログイン元デバイス・承認履歴確認
4. token漏洩疑い時は即時新token発行 + 旧token無効化
