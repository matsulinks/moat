# 実装スケジュール

## Phase 1 実装ロードマップ（優先順）

| 優先度 | 項目 | 目安 | 完了条件 |
|--------|------|------|---------|
| 1 | 1台専用ミニPCでのE2E構築 | 1〜2日 | Telegram→承認→実行→返答まで成功 |
| 2 | hardening-guides全テンプレート完成 | 1日 | Docker Compose・Infisical・Falco rules・config.yamlをGitにコミット |
| 3 | Layer 7監視ダッシュボード構築 | 1〜2日 | GrafanaでKPI表示＋テストアラート受信確認 |
| 4 | 緊急遮断モードの実装・テスト | 1日 | 手動/自動発動→全入力ブロック→解除まで確認 |
| 5 | 複数台（2〜3台）展開 + Tailscale連携 | 1〜2日 | 別インスタンスに別tokenで独立運用成功 |
| 6 | 運用マニュアル・チェックリスト作成 | 1日 | Markdownで1ファイルにまとめる |
| 7 | 継続的テストシナリオ自動化（任意） | 2〜3日 | GitHub Actionsで定期テストパス |

## E2Eテスト 検証シナリオ
1. **正常系**: 普通のプロンプト → 承認不要で即実行 → 結果返答
2. **高リスク系**: fs:writeやbrowserツール呼び出し → Telegram承認ボタン表示 → Approve/Deny
3. **悪意プロンプト**: 忘却命令・システム上書き系 → Layer 5でブロック + アラート
4. **緊急遮断**: Falcoでshell spawn複数検知 → 自動発動 → 全プロンプトブロック → 手動解除
5. **乗っ取りシミュレーション**: 1インスタンスのtoken漏洩 → 他インスタンスに影響なし確認

## Phase 2 拡張項目（将来）
- Loki + GrafanaでFalcoログ全文検索
- 自動スキル審査パイプライン（LLMベース）
- SIEM統合（Graylog/Splunk）
- Federated identity（チーム利用）
- Multi-region Vault replication
