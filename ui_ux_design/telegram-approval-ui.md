# Telegram承認ワークフロー UI仕様

## 1. 概要

OpenClawが高リスクツール（fs:write, exec, browser, automation等）を実行しようとした際に、
Primary Operatorに承認を求めるTelegramインタラクティブメッセージの仕様。

## 2. 承認リクエスト メッセージ形式

```
⚠️ 承認リクエスト — openclaw-instance01

🔧 ツール: file_write
📁 引数: /workspace/output.md
📋 プロンプト要約: ユーザーが会議メモのMarkdownファイル作成を要求

⏱️ タイムアウト: 30秒（自動拒否）
🔑 Request Hash: a3f8c2e1...

[✅ 承認] [❌ 拒否] [ℹ️ 詳細]
```

## 3. ボタン定義

| ボタン | アクション | 結果 |
|--------|---------|------|
| ✅ 承認 | `approved` | ツール実行許可（1回限り） |
| ❌ 拒否 | `denied` | ツール実行ブロック、ユーザーに通知 |
| ℹ️ 詳細 | `show_detail` | フルプロンプト・全引数を表示 |
| タイムアウト（30秒） | `timeout` | 自動拒否（denied扱い） |

## 4. CRITICALアラート通知形式

```
🚨 [CRITICAL] openclaw-instance01

Shell spawned in OpenClaw container
proc=bash cmd=/bin/bash container=openclaw-instance01 user=root

⏰ 2026-03-03 12:34:56 JST
🔗 Falco Rule: Shell in OpenClaw Container

[🛑 緊急遮断] [🔍 ログ確認]
```

## 5. 緊急遮断モード 通知形式

```
🔴 緊急遮断モード発動 — openclaw-instance01

発動理由:
• CRITICALアラート 3回（15分以内）
• Abnormal Secrets Access 同時検知

現在の状態:
• 全プロンプト入力: ブロック中
• plugins install/update: 凍結中
• 高リスクツール: 強制deny

[🔓 解除（要調査完了）]
```

## 6. 解除フロー

```
🔓 緊急遮断解除リクエスト — openclaw-instance01

解除前確認チェックリスト:
□ 原因特定済み
□ VirusTotal再スキャン完了（検出0件）
□ 異常挙動ログ確認済み
□ 安全確認完了

[✅ 解除承認] [❌ 継続維持]
```

## 7. インタラクション設計原則

- 承認ボタンは **Primary Operator（設定済みTelegram ID）のみ** 有効
- タイムアウト（30秒）はdenyとして記録
- 全ての承認/拒否はrequest hashと共にログに記録
- 承認は **1回限り有効**（同一request hashの再利用不可）
