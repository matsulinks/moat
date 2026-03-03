# Monitoring and Detection Layer (Layer 7) Specification for Security-System

## 1. 目的
このドキュメントは、Security-SystemにおけるLayer 7（監視・検知・インシデント対応）の仕様を定義します。  
Layer 1（Tailscale ACLによるネットワーク分離）、Layer 2（Docker sandbox:all + non-root + cap_drop）、Layer 4（Infisical JIT注入 + YubiKeyオプション）で構築された防御を補完し、**異常挙動の早期検知・即時通知・迅速対応**を実現します。  
専用機原則を前提とし、OpenClawインスタンス、Infisicalサーバー、ホストOSレベルの脅威をカバー。検知漏れによるMTTR（Mean Time to Remediate）を最小化し、侵害の拡散を防ぎます。

---

## 2. 検知対象の優先リスト（脅威モデルに基づく）

| 優先度 | 検知対象カテゴリ | 具体例（異常挙動） | なぜ重要か（2026年脅威状況） | 推奨検知ツール |
|---|---|---|---|---|
| ★★★★★ | コンテナ内不審プロセス実行 | execveでbash/sh/zsh起動、curl/wgetによる外部通信、age/decryptコマンド異常使用 | Prompt injection/悪意スキルによるシェル脱獄・C2通信が最多。OpenClawの高権限実行は標的になりやすい。 | Falco (syscall) |
| ★★★★★ | secrets/credentialsへの異常アクセス | /app/credentials/* や /tmp/secrets.env へのread/write、age-plugin-yubikey複数失敗 | Infisical/YubiKey突破試行、credential exfilの起点。 | Falco (filesystem) + Prometheus |
| ★★★★☆ | コンテナブレイクアウト兆候 | privileged試行、setns/setuid/setgid、kernel module load、/proc異常アクセス | Docker/kernel脆弱性経由のホスト侵害リスク。 | Falco (default + custom) |
| ★★★★☆ | Tailscale ACL違反/拒否試行 | ACL rejectログ多発、未タグノード接続試行 | 侵害機からの横移動・外部プローブ検知に有効。 | Tailscale Audit Logs + Alert連携 |
| ★★★☆☆ | OpenClaw特有メトリクス異常 | error率急増、execution duration悪化、plugin failure増加、token利用急増 | Prompt injection暴走、悪意スキルDoS、異常ワークロードの兆候。 | Prometheus + custom exporter |
| ★★★☆☆ | Infisicalサーバー異常 | 認証失敗率上昇、Service Token利用元タグ異常、rate limit超過 | ブルートフォース/token leakの前兆。 | Prometheus + Falco |
| ★★☆☆☆ | ホストレベル異常 | CPU/メモリ/ディスク急上昇、未知プロセス、ネットワークフロー異常 | バックドアや資源枯渇の初期兆候検知。 | Node Exporter + Falco |

---

## 3. 推奨ツールスタック（仕様レベル）

- **Falco**（主力：eBPFベースsyscall/コンテナ監視）
  - デプロイ：各専用ミニPCにsystemdサービス or Dockerコンテナ常駐
  - 出力先：falcosidekick（Telegram / Prometheus webhook / JSONログ）
  - メトリクス露出：`prometheus_metrics_enabled=true`
  - ルール管理：default rules + `/etc/falco/falco_rules.local.yaml`
  - 優先モード：eBPF（低オーバーヘッド）

- **Prometheus**（メトリクス収集・蓄積）
  - scrape間隔：15秒
  - 主要ターゲット：
    - Node Exporter
    - cAdvisor
    - Falco exporter
    - OpenClaw custom exporter（`openclaw_agent_executions_total`, `openclaw_execution_duration_seconds`, `openclaw_plugin_calls_total`, `openclaw_llm_tokens_used_total` 等）
    - Infisical exporter（認証失敗率、API request数、rate limitイベント）
  - Alertmanager：閾値アラート生成 + Telegram webhook統合

- **Grafana**（可視化）
  - データソース：Prometheus（必須） + Loki（任意）
  - 必須ダッシュボード：
    - 全体健康（CRITICAL/WARNING件数、稼働インスタンス）
    - OpenClaw（error rate、latency p95、plugin failure rate、tokens/sec）
    - セキュリティ（secretsアクセス試行、shell spawn回数、ACL reject）
    - Infisical（認証失敗率、Service Token利用元タグ分布）

- **Alerting**
  - WARNING：Telegram
  - CRITICAL：Telegram + Slack（必要時 音声通知）

---

## 4. Falcoカスタムルール仕様（必須項目）

Falco default rules を有効化した上で、以下のcustom ruleを追加する。

### 4.1 ルール設計方針
- 条件式は必ず括弧で優先順位を明示する。
- 「検知しすぎ」を防ぐため、許可通信先をホワイトリスト化する。
- ルールの例外は `falco_rules.local.yaml` 内にコメント付きで管理する。

### 4.2 許可通信先（ホワイトリスト）
```yaml
# 例: 環境に合わせて更新
allowed_domains:
  - api.openai.com
  - docs.openclaw.ai
  - github.com
allowed_ips:
  - 100.64.0.0/10   # tailnet 内部
allowed_ports:
  - 443
  - 53
```

### 4.3 優先custom rule例（/etc/falco/falco_rules.local.yaml）

```yaml
- rule: Shell in OpenClaw Container
  desc: Detect shell execution inside OpenClaw container
  condition: >
    (spawned_process and container and
     (container.image.repository contains "openclaw") and
     (proc.name in (bash, sh, zsh, ash, dash, fish)))
  output: >
    Shell spawned in OpenClaw container
    (proc=%proc.name cmd=%proc.cmdline container=%container.name user=%user.name)
  priority: CRITICAL
  tags: [openclaw, mitre_execution, container]

- rule: Suspicious Outbound Tool in Container
  desc: Detect outbound communication tools to non-whitelisted destinations
  condition: >
    (spawned_process and container and
     (proc.name in (curl, wget, nc, telnet, netcat)) and
     (fd.rport exists) and
     not (fd.rport in (443, 53)))
  output: >
    Outbound tool executed to non-whitelisted destination
    (proc=%proc.name cmd=%proc.cmdline container=%container.name rport=%fd.rport)
  priority: WARNING
  tags: [openclaw, mitre_command_and_control]

- rule: Abnormal Secrets Access
  desc: Detect unauthorized read/write to credentials paths
  condition: >
    ((open_read or open_write) and container and
     (fd.name startswith "/app/credentials/") and
     not (proc.name in (openclaw, infisical-cli)))
  output: >
    Abnormal secrets access
    (file=%fd.name proc=%proc.name container=%container.name)
  priority: CRITICAL
  tags: [openclaw, credential_access]

- rule: Suspicious Decrypt Usage
  desc: Detect unusual decrypt operations
  condition: >
    (spawned_process and container and
     (proc.name in (age, age-plugin-yubikey)) and
     ((proc.cmdline contains "-d") or (proc.cmdline contains "--decrypt")) and
     (evt.type=execve))
  output: >
    Suspicious decrypt operation
    (cmd=%proc.cmdline container=%container.name)
  priority: WARNING
  tags: [openclaw, credential_access]
```

### 4.4 適用・検証
- `falco --list` でルールロード確認
- `falco-event-generator` で意図したアラートが発火するか検証
- 誤検知が多い場合は例外条件を追加し、根拠をコメントで残す

---

## 5. アラート仕様（閾値・エスカレーション）

### 5.1 通知フォーマット
`[CRITICAL] OpenClaw instance01: Shell spawned (cmd=/bin/bash pid=1234 container=openclaw-instance01 user=root)`

### 5.2 Alertmanagerルール例（alerts.yaml）
```yaml
groups:
  - name: openclaw-alerts
    rules:
      - alert: HighOpenClawErrorRate
        expr: rate(openclaw_agent_executions_total{status="error"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High execution error rate on {{ $labels.instance }}"

      - alert: SecretsAccessAnomaly
        expr: increase(falco_events_total{rule=~"Abnormal Secrets Access"}[5m]) > 3
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Multiple secrets access attempts detected on {{ $labels.instance }}"
```

### 5.3 エスカレーションフロー
1. 即時：Telegram（個人通知）
2. 5分未対応：Slack通知 + 音声通知（任意）
3. 15分未対応：メール通知 + 停止判断フローへ

### 5.4 自動停止の安全弁（必須）
`docker compose down` 等の自動停止は、**以下をすべて満たす場合のみ**候補とする。
- 条件A：CRITICALが15分以内に複数回（例：3回以上）
- 条件B：Secrets系アラート（`Abnormal Secrets Access`）が同時発火
- 条件C：運用担当者の明示承認（チャット承認 or runbook承認）

> 単一アラートで自動停止しない。可用性と誤停止リスクを優先する。

### 5.5 ログ保持期間
- Falco / Prometheus：30日以上
- Tailscale audit logs：90日以上

---

## 6. 実装・運用ガイドライン（Phase 1）

- Falco導入（eBPF優先）→ custom rules適用 → 再起動
- Prometheus scrape設定（OpenClaw `/metrics` 含む）
- Grafanaダッシュボード作成（インスタンス別健康、Falco履歴、OpenClaw性能、Infisical認証失敗）
- 週1回レビュー（アラート妥当性、誤検知率、閾値見直し）
- テスト手順：
  1. `falco-event-generator` で各ルールを疑似発火
  2. Alertmanagerの通知到達確認（Telegram/Slack）
  3. エスカレーション導線（5分/15分）を演習

---

## 7. 今後の拡張ポイント（Phase 2以降）

- Loki + GrafanaでFalcoログ全文検索
- OpenClawのLLM応答監査（異常プロンプト/出力ポリシー違反検知）
- SIEM統合（Graylog / Splunk）
- 必要に応じて商用EDR（例：CrowdStrike）連携

---

この仕様により、Security-SystemのLayer 7はDefense in Depthの運用レイヤとして成立し、検知から対応までの実効性を担保できる。