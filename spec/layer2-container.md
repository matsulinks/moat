# Layer 2: コンテナ/サンドボックス 仕様

## 目的
- sandbox.mode: "all" を強制し、プロセスを最大限隔離
- non-rootユーザー実行 + 権限制限（read-only FS中心）
- 高リスクcapabilitiesをすべてdrop
- ネットワークをlocalhost/Tailscale限定に制限
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
        exec infisical run \
          --projectId YOUR_PROJECT_ID \
          --env=prod \
          -- /app/openclaw --config /app/config/config.yaml

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
    cap_add:
      - CHOWN
      - SETGID
      - SETUID

    # === ネットワーク: Tailscale経由localhostのみ ===
    network_mode: "host"

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

    # === リソース制限（DoS対策） ===
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

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
- `network_mode: "host"` はTailscale経由localhostアクセス前提
