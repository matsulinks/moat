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

> **注意**: Exit Nodeを無効化しても専用機自身のインターネット通信は遮断されません。
> C2通信の防止には Tailscale ACL ではなく、後述の iptables アウトバウンド制御が必要です。

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
      "dst": ["tag:openclaw-instance:22", "tag:openclaw-instance:443"]
    },
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
- `tag:admin-device → tag:openclaw-instance:22` を追加（管理用SSH経路を確保）
- インスタンス間通信は原則禁止（ログ集約等が必要な場合のみ後で最小限追加）
- 将来的にPrometheus収集が必要なら: `{"action":"accept","src":["tag:infisical-server"],"dst":["tag:openclaw-instance:9100"]}` を追加

## 5. アウトバウンド通信制御（C2防止）

**Exit Nodeの無効化はC2防止にならない**。ホストOSのiptablesでアウトバウンドをホワイトリスト制御する。

```bash
# 既存ルールをフラッシュ（注意: SSH接続が切れないよう順序を守ること）
sudo iptables -F OUTPUT

# ループバック・Tailscale内部通信は許可
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -o tailscale0 -j ACCEPT

# 確立済み通信の応答は許可
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 許可するアウトバウンド宛先（ホワイトリスト）
# Infisical（secrets取得）
sudo iptables -A OUTPUT -p tcp --dport 443 -d YOUR_INFISICAL_SERVER_IP -j ACCEPT
# Tailscale（制御サーバー）
sudo iptables -A OUTPUT -p tcp --dport 443 -d controlplane.tailscale.com -j ACCEPT
# DNS（名前解決）
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# それ以外のアウトバウンドをすべてDROP
sudo iptables -A OUTPUT -j DROP

# 永続化（Debian/Ubuntu）
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

> **重要**: OpenClawコンテナが必要とするAPIエンドポイント（api.openai.com等）は
> Layer 6のアプリケーション層ホワイトリストで制御します。
> iptablesはOSレベルの最終防衛ラインとして機能します。

## 6. インターネット出口ノード（Exit Node）の設定
ACL JSON外。Tailscale Admin Console > Fleet Settings で実施。
- すべてのノードの Use as exit node を **Disabled** に設定
- ※ C2防止効果はない。誤ってExitNodeになることを防ぐための設定。

## 7. 監査ログ
- Tailscale Admin Console > Logs > Audit Logs を有効化
- 保存期間: 90日（Tailscaleデフォルトを活用）
- 異常検知時: Tailscale API + webhookスクリプトでTelegramアラート連携
- 定期レビュー: 週1回以上

## 8. ACL更新・承認フロー
1. 変更前に Primary Operator へ Telegram で確認（人間承認）
2. Tailscale Admin Console または policy file（Git管理）で変更
3. 変更履歴はGitでバージョン管理
4. 緊急時ロールバック: 前回のpolicy fileを復元

## 9. 適用手順
```bash
# 各専用ミニPCで
tailscale up --authkey=tskey-xxxx --advertise-tags=tag:openclaw-instance
# 確認
tailscale status
# Infisicalサーバー機で
tailscale up --authkey=tskey-xxxx --advertise-tags=tag:infisical-server
# iptablesアウトバウンド制御を適用（セクション5参照）
```
