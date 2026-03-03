# 運用ダッシュボード 仕様（管理ポータル）

## 1. 概要

Security-Systemの運用状況を一元的に把握・操作するための管理ダッシュボード仕様。
Primary Operatorが日常運用・緊急対応を行うためのインターフェース。

**アクセス方法**: Tailscale経由のみ（Grafana: `http://infisical-server:3000`、外部公開禁止）

## 2. Grafanaダッシュボード 画面構成

### 2.1 メインダッシュボード: 全体健康状態

```
┌─────────────────────────────────────────────────────────────┐
│  Security-System — 全体健康状態 (2026-03-03 12:34 JST)       │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  稼働中      │ CRITICAL     │ WARNING      │ 緊急遮断中     │
│  3 / 3台     │ 0件          │ 2件          │ 0台            │
├──────────────┴──────────────┴──────────────┴────────────────┤
│  インスタンス別ステータス                                      │
│  [instance01: ✅正常]  [instance02: ✅正常]  [instance03: ✅正常] │
├──────────────────────────────────────────────────────────────┤
│  Falcoアラート数（直近1時間）: 時系列グラフ                    │
│  OpenClaw Execution Error Rate: 時系列グラフ                  │
│  Secrets Access試行数: カウンター                             │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 セキュリティ専用パネル

| パネル名 | メトリクス | 閾値 |
|---------|-----------|------|
| Shell Spawn回数 | falco_events_total{rule="Shell in OpenClaw Container"} | >0でWARNING |
| Secrets異常アクセス | falco_events_total{rule="Abnormal Secrets Access"} | >0でCRITICAL |
| ACL拒否試行 | Tailscale Audit Log reject件数 | >5/分でWARNING |
| コンテナブレイクアウト兆候 | falco_events_total{rule=~"container_escape.*"} | >0でCRITICAL |

### 2.3 OpenClaw パフォーマンスパネル

| パネル名 | メトリクス | 閾値 |
|---------|-----------|------|
| Execution Error Rate | rate(openclaw_agent_executions_total{status="error"}[5m]) | >0.1でWARNING |
| Execution Latency p95 | histogram_quantile(0.95, openclaw_execution_duration_seconds_bucket) | >10s でWARNING |
| Plugin Failure Rate | rate(openclaw_plugin_calls_total{status="failure"}[5m]) | >0.05でWARNING |
| LLM Tokens/sec | rate(openclaw_llm_tokens_used_total[1m]) | 異常急上昇でWARNING |

## 3. Telegram 管理コマンド仕様

Primary Operatorが使用するTelegramコマンド（管理Bot経由）:

| コマンド | 説明 |
|---------|------|
| `/status` | 全インスタンスの稼働状態を表示 |
| `/alerts` | 直近のFalco/Prometheusアラートを表示 |
| `/shutdown instance01` | instance01を緊急停止（要確認ダイアログ） |
| `/emergency_stop all` | 全インスタンス緊急遮断モード発動 |
| `/resume instance01` | instance01の緊急遮断解除（要原因報告） |
| `/rotate_token instance01` | instance01のAuth Tokenをローテーション |
| `/audit` | 直近の承認・拒否ログサマリーを表示 |

## 4. 日次/週次レポート（Telegram Bot自動送信）

### 4.1 日次サマリー（毎朝9:00 JST）
```
📊 Security-System 日次レポート 2026-03-03

稼働: 3/3台 ✅
CRITICAL: 0件
WARNING: 2件（詳細: Grafanaリンク）
承認実行: 5件
ツール拒否率: 87%

異常なし。継続監視中。
```

### 4.2 週次監査サマリー（毎週月曜9:00 JST）
- 全インスタンスの稼働率
- Falcoアラート件数・ルール別分布
- 承認/拒否率・KPI確認
- Token有効期限アラート
- 推奨アクション

## 5. インシデント対応ガイド

### 5.1 CRITICALアラート対応フロー
1. Telegram通知受信
2. Grafanaでアラート詳細確認（5分以内）
3. 原因判断:
   - 誤検知 → Falcoルールの例外追加
   - 実害の可能性 → 当該インスタンスを手動停止 (`/shutdown instance01`)
4. 調査・復旧後に報告ログ記録

### 5.2 緊急遮断モード 解除フロー
1. 原因調査完了（Falcoログ・承認ログ確認）
2. VirusTotal再スキャン（0件確認）
3. Telegramの解除ボタン押下
4. 解除後30分間は強化監視（アラート閾値を通常の50%に）
