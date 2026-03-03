# Layer 2: コンテナ/サンドボックス 仕様

## 目的
- sandbox.mode: "all" を強制し、プロセスを最大限隔離
- non-rootユーザー実行 + 権限制限（read-only FS中心）
- 高リスクcapabilitiesをすべてdrop
- ネットワークをカスタムbridgeネットワークに限定（host networkingは使用しない）
- secretsは外部注入（Infisical JIT or YubiKey復号後mount）を前提

**前提条件**
- Docker 24.0+ & Docker Compose v2+
- OpenClaw最新版（CVEパッチ適用済み）
- ホストOS: Ubuntu 24.04 LTS / Debian 12（SELinux/AppArmor有効推奨）
- 専用ユーザー: `sudo adduser --system --group --uid 10000 --no-create-home openclaw`
- ディレクトリ: `/opt/openclaw/instance01`（インスタンス毎に別フォルダ）

## docker-compose.yml（Infisical CLI統合・最終版）

```yaml
version: '3.9'

services:
  openclaw:
    image: ghcr.io/openclaw/openclaw:latest
    container_name: openclaw-instance01
    restart: unless-stopped

    # === 機密情報: Infisical CLI経由でJIT注入 ===
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        exec infisical run           --projectId YOUR_PROJECT_ID           --env=prod           -- /app/openclaw --config /app/config/config.yaml

    # === セキュリティ: 隔離強化 ===
    user: "10000:10000"
    read_only: true
    tmpfs:
      - /tmp:uid=10000,gid=10000,mode=700,size=128m,noexec,nosuid,nodev
      - /var/tmp:uid=10000,gid=10000,mode=700,size=64m,noexec,nosuid,nodev
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    # cap_add は原則使用しない。
    # OpenClawがCHOWN/SETUID/SETGIDを必要とする場合は、その必要性を確認した上で
    # 個別に追加すること。不明な場合は追加しない（最小権限の原則を優先）。

    # === ネットワーク: カスタムbridgeに限定 ===
    # network_mode: host は使用しない（コンテナ境界を弱めるため）
    # Tailscaleはホスト側で動作し、iptablesで通信制御する（Layer 1参照）
    networks:
      - openclaw-net

    # === リソース制限（DoS対策） ===
    # deploy.resources は docker stack deploy (Swarm) でのみ有効なため使用しない
    # 通常の docker compose では mem_limit / cpus を直接指定する
    mem_limit: 2g
    memswap_limit: 2g
    cpus: '1.0'

    # === ボリューム: read-only中心 ===
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data:rw
      - ./logs:/app/logs:rw
      - ./workspace:/app/workspace:ro

    # === 環境変数: Service Tokenのみ（Infisicalから他を注入） ===
    environment:
      - INFISICAL_SERVICE_TOKEN=${INFISICAL_SERVICE_TOKEN}
      - TZ=Asia/Tokyo

    # === ヘルスチェック ===
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8765/health"]
      interval: 30s
      timeout: 10s
      retries: 3

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  openclaw-net:
    driver: bridge
    internal: false   # アウトバウンドはiptablesで制御（Layer 1参照）
```

## network_mode: host を使わない理由

| 比較 | host networking | bridge networking（本仕様） |
|---|---|---|
| コンテナ境界 | ホストと共有（弱い） | 独立したネットワーク空間 |
| ポート公開 | ホストの全ポートが露出 | 明示的にexposeしたポートのみ |
| Tailscale連携 | 直接利用可能 | ホスト側Tailscale + iptablesで代替 |
| セキュリティ | 隔離が弱まる | cap_drop ALL と一貫した設計 |

Tailscaleはホスト側で動作させ、コンテナへのアクセスはiptablesルール（Layer 1参照）で制御する。

## cap_add についての注意

`cap_drop: ALL` の後に `cap_add` でCHOWN/SETUID/SETGIDを戻すことは最小権限の原則に反する。

- **まずcap_addなしで起動を試みる**
- 起動エラーが出た場合のみ、必要なcapabilityを個別に追加する
- 追加する場合はコメントに理由を明記する

## 使い方

```bash
# ホストで専用ユーザー作成
sudo adduser --system --group --uid 10000 --no-create-home openclaw
sudo mkdir -p /opt/openclaw/instance01/{config,data,logs,workspace}
sudo chown -R 10000:10000 /opt/openclaw/instance01

# .env作成（Service Tokenのみ記載）
echo "INFISICAL_SERVICE_TOKEN=st-xxxx" > /opt/openclaw/instance01/.env
chmod 600 /opt/openclaw/instance01/.env

# 起動
cd /opt/openclaw/instance01
docker compose up -d
```

## 注意点
- `container_name` はインスタンス毎にユニーク（instance01, instance02...）
- `user: "10000:10000"` はホストのUID/GIDに合わせる
- OPENCLAW_AUTH_TOKEN等の秘密はInfisicalからJIT注入（.envには絶対書かない）
- アウトバウンド通信制御はホスト側iptablesで行う（Layer 1参照）
