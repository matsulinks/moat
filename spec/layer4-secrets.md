# Layer 4: 機密情報管理 仕様

## 1. 概要

Phase 1推奨: **Infisical CLI entrypoint方式**（JIT注入）をメインに採用。
YubiKey + age暗号化はオプション（高セキュリティ専用機向け）。

## 2. Infisical CLI JIT注入方式（メイン）

### 2.1 フロー
1. ホストの `.env` に `INFISICAL_SERVICE_TOKEN`（read-only, 期限30日）を保存
2. Docker Compose起動時に `INFISICAL_SERVICE_TOKEN` をコンテナへ渡す
3. entrypointで `infisical run` が起動し、Secrets をenv varとして注入
4. OpenClaw起動 → 実行中は平文がコンテナ外に出ない

### 2.2 Infisical self-hosted セットアップ（推奨）
```yaml
# infisical-docker-compose.yml（Infisicalサーバー用）
services:
  infisical:
    image: infisical/infisical:latest
    ports:
      - "443:443"
    volumes:
      - ./infisical-data:/app/data
    environment:
      - POSTGRES_URL=postgres://...
      - ENCRYPTION_KEY=<random-256bit>
```

### 2.3 プロジェクト構成
- 各インスタンスで独立したプロジェクト: `instance01-prod`, `instance02-prod` ...
- Service Token: read-only, 有効期限30日, IP制限（Tailscale IPのみ）

### 2.4 自動ローテーション
- Infisical Rotation Templates（対応secret）または custom rotation script
- INFISICAL_SERVICE_TOKEN 自体のローテーション: 最大30日（手動 or 管理スクリプト）

## 3. YubiKey + age暗号化方式（オプション）

### 3.1 対象
- 「銀行系APIキーのみ扱う専用機」「オフライン重視のテスト機」など超高セキュリティ要件

### 3.2 概要フロー
```bash
# 初回セットアップ
age-plugin-yubikey --generate --slot 9d --pin-policy once --touch-policy always
# → recipient (公開部分) をメモ

# 暗号化
age -r <recipient> -o secrets.age secrets.env && rm secrets.env

# 起動時（YubiKey touch/PIN で復号）
age --decrypt -i yubikey:slot=9d secrets.age > /tmp/creds.env
docker compose --env-file /tmp/creds.env up -d
shred -u -z -n 3 /tmp/creds.env
```

### 3.3 トレードオフ
- 強み: 中央サーバー不要、ネットワーク露出ゼロ、鍵がデバイス外に出ない
- 弱み: 起動時YubiKey touch必須（24/7自動起動しにくい）、ローテーションが手動

## 4. セキュリティ考慮点
- INFISICAL_SERVICE_TOKEN はホストの `.env` に chmod 600 で保存
- Service Tokenはread-only権限のみ付与
- Infisical self-hostedの場合、サーバー自体をHTTPS + Tailscale経由でのみアクセス可能に
- Infisical Admin アクセスにはYubiKey認証を推奨（Phase 2）
