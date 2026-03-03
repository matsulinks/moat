# データスキーマ定義

## 1. Secrets スキーマ（Infisical管理）

### 1.1 インスタンス毎のSecrets（instance01-prod環境例）
```
OPENCLAW_AUTH_TOKEN    = <64文字以上ランダム文字列>
TELEGRAM_BOT_TOKEN     = <BotFatherから取得>
OPENAI_API_KEY         = sk-xxxx（OpenAI/互換API）
INFISICAL_SERVICE_TOKEN = st.xxxx（read-only, 有効期限30日）
```

### 1.2 ローテーションポリシー
| Secret名 | 定期ローテーション | 緊急時 |
|---------|----------------|--------|
| OPENCLAW_AUTH_TOKEN | 最大90日（推奨30日） | 即時revoke + 新規発行 |
| TELEGRAM_BOT_TOKEN | BotFather再発行（手動） | 即時無効化 |
| OPENAI_API_KEY | 最大90日 | 即時revoke |
| INFISICAL_SERVICE_TOKEN | 最大30日 | 即時revoke |

### 1.3 age暗号化ファイルスキーマ（YubiKey方式時）
```
# secrets.env（暗号化前、一時的にのみ存在）
OPENCLAW_AUTH_TOKEN=<value>
TELEGRAM_BOT_TOKEN=<value>
OPENAI_API_KEY=<value>

# 暗号化後
secrets.age（PIVスロット9d YubiKey鍵で暗号化）
```

## 2. Falcoアラート イベントスキーマ

### 2.1 Falcoイベント JSON形式
```json
{
  "time": "2026-03-03T12:34:56.789Z",
  "rule": "Shell in OpenClaw Container",
  "priority": "CRITICAL",
  "source": "syscall",
  "tags": ["openclaw", "mitre_execution", "container"],
  "output_fields": {
    "proc.name": "bash",
    "proc.cmdline": "/bin/bash",
    "container.name": "openclaw-instance01",
    "user.name": "root",
    "evt.type": "execve"
  },
  "hostname": "minipc-01"
}
```

### 2.2 Prometheusメトリクス スキーマ
```
# OpenClaw custom exporter（想定エンドポイント: /metrics）
openclaw_agent_executions_total{status="success|error", instance="instance01"} <count>
openclaw_execution_duration_seconds_bucket{le="0.1|1.0|10.0", instance="instance01"} <count>
openclaw_plugin_calls_total{status="success|failure", plugin="<name>", instance="instance01"} <count>
openclaw_llm_tokens_used_total{model="<model>", instance="instance01"} <count>

# Falco exporter
falco_events_total{priority="CRITICAL|WARNING|INFO", rule="<rule_name>", instance="instance01"} <count>

# Infisical exporter
infisical_auth_failures_total{environment="<env>", instance="instance01"} <count>
infisical_api_requests_total{status="200|401|429", instance="instance01"} <count>
```

## 3. 承認ワークフロー ログスキーマ

### 3.1 承認イベント記録形式
```json
{
  "timestamp": "2026-03-03T12:34:56Z",
  "request_hash": "sha256:<prompt+tool+args のハッシュ>",
  "tool_group": "fs:write",
  "tool_name": "file_write",
  "tool_args": "/tmp/output.txt",
  "prompt_summary": "<プロンプト要約>",
  "decision": "approved|denied|timeout",
  "operator_id": "telegram:123456789",
  "instance": "openclaw-instance01",
  "duration_ms": 15000
}
```

## 4. Tailscale ACL タグスキーマ

```json
{
  "tag:openclaw-instance": ["your-admin-email@example.com"],
  "tag:infisical-server": ["your-admin-email@example.com"],
  "tag:admin-device": ["your-admin-email@example.com"]
}
```

## 5. 設定ファイルスキーマ（config.yaml 主要フィールド）

```yaml
# OpenClaw インスタンス設定（最小権限版）
sandbox:
  mode: all                          # 必須: 最大隔離

auth:
  mode: token
  token: "{{ INFISICAL_TOKEN }}"    # Infisicalから注入
  requireMention: true               # グループでは必須
  pairing:
    allowlist:
      - "user_id:<your_telegram_id>"

tools:
  deny: [exec, runtime, automation, browser, "fs:write"]
  allow: ["fs:read", llm, network, memory, sessions]
  elevated:
    groups: ["fs:write", browser, automation]
    requireApproval: true
    approvalTimeout: 30s
  network:
    allowed_domains: ["api.openai.com", "api.infisical.com"]
    allowed_ports: [443]

plugins:
  allow:
    - git_repo: "https://github.com/your-org/openclaw-safe-skills.git"
      ref: "v1.0.0"
  deny:
    - source: clawhub
    - source: unknown

prompt:
  guard:
    enabled: true
    block_threshold: 0.8
```
