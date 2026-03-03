# Layer 1: ネットワーク分離 仕様

## 1. 目的
専用機原則を前提に、OpenClaw専用ミニPC群とInfisicalサーバーのネットワークをゼロトラストで厳格に保護する。
外部からの直接アクセスを100%遮断し、インスタンス間の不要な横移動を防止する。

## 2. 基本原則
- **Default Action**: deny（明示的に許可したもの以外すべて拒否）
- タグベース制御を全面採用
- 許可ポート: 原則443/TCP（HTTPS）のみ
- SSH・任意ポート・MagicDNS以外のサービス公開なし
- インターネット出口ノード（Exit Node）完全禁止

## 3. タグ定義

```json
"tagOwners": {
  "tag:openclaw-instance": ["your-admin-email@example.com"],
  "tag:infisical-server": ["your-admin-email@example.com"],
  "tag:admin-device": ["your-admin-email@example.com"]
}
```

- `tag:openclaw-instance` → すべてのOpenClaw専用ミニPC
- `tag:infisical-server` → Infisicalサーバー専用機
- `tag:admin-device` → 管理用デバイス（Primary Operatorのスマホ/ノートPC）

## 4. ACL JSON（完成版）

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:admin-device"],
      "dst": ["tag:infisical-server:443"]
    },
    {
      "action": "accept",
      "src": ["tag:openclaw-instance"],
      "dst": ["tag:infisical-server:443"]
    }
  ],
  "tagOwners": {
    "tag:openclaw-instance": ["your-admin-email@example.com"],
    "tag:infisical-server": ["your-admin-email@example.com"],
    "tag:admin-device": ["your-admin-email@example.com"]
  },
  "autoApprovers": {}
}
```

**ポイント**:
- インスタンス間通信は原則禁止（ログ集約等が必要な場合のみ後で最小限追加）
- 将来的にPrometheus収集が必要なら: `{"action":"accept","src":["tag:infisical-server"],"dst":["tag:openclaw-instance:9100"]}` を追加

## 5. インターネット出口ノード（Exit Node）の設定
ACL JSON外。Tailscale Admin Console > Fleet Settings で実施。
- すべてのノードの "Use as exit node" を **Disabled** に設定
- これにより侵害時でも外部C2通信を防止

## 6. 監査ログ
- Tailscale Admin Console > Logs > Audit Logs を有効化
- 保存期間: 90日（Tailscaleデフォルトを活用）
- 異常検知時: Tailscale API + webhookスクリプトでTelegramアラート連携
- 定期レビュー: 週1回以上

## 7. ACL更新・承認フロー
1. 変更前に Primary Operator へ Telegram で確認（人間承認）
2. Tailscale Admin Console または policy file（Git管理）で変更
3. 変更履歴はGitでバージョン管理
4. 緊急時ロールバック: 前回のpolicy fileを復元

## 8. 適用手順
```bash
# 各専用ミニPCで
tailscale up --authkey=tskey-xxxx --advertise-tags=tag:openclaw-instance
# 確認
tailscale status
# Infisicalサーバー機で
tailscale up --authkey=tskey-xxxx --advertise-tags=tag:infisical-server
```
