# Security-System — プロジェクトインデックス

## 概要
複数台の専用ミニPCでOpenClawを安全に並行運用するための、多層防御（Defense in Depth）セキュリティシステム設計書。

**バージョン**: v1.0
**確定日**: 2026-03-03
**フェーズ**: Phase 1 仕様設計完了 → 実装フェーズへ移行可能

## ドキュメント構成

| ファイル | 内容 |
|---------|------|
| README.md | プロジェクト概要・コア原則 |
| schedule.md | 実装スケジュール（Phase 1） |
| requirements/main.md | 機能・非機能要件定義（MoSCoW法） |
| data_schema.md | データスキーマ（Secrets・アラート・Falcoイベント） |
| ui_ux_design/telegram-approval-ui.md | Telegram承認ワークフローUI仕様 |
| spec/architecture.md | 全体アーキテクチャ統合（7層構成図・実行フロー・責任分界） |
| spec/layer1-network.md | Layer 1: ネットワーク分離（Tailscale ACL） |
| spec/layer2-container.md | Layer 2: コンテナ/サンドボックス（Docker Hardening） |
| spec/layer3-auth.md | Layer 3: 認証・アクセス制御 |
| spec/layer4-secrets.md | Layer 4: 機密情報管理（Infisical + YubiKey） |
| spec/layer5-skill-defense.md | Layer 5: スキル・プロンプト防御 |
| spec/layer6-execution-privileges.md | Layer 6: 実行時最小権限 |
| spec/layer7-monitoring.md | Layer 7: 監視・インシデント対応（Falco + Prometheus） |
| test_and_evolution_strategy.md | テスト戦略・進化ロードマップ |
| lp_spec.md | 運用ダッシュボード（管理ポータル）仕様 |
| .cursorrules | OpenClaw実装コーディング規約 |

## コア原則（全レイヤー共通）
1. **専用機原則の厳格適用** — OpenClawは専用ミニPCのみで運用
2. **デフォルトdeny + ゼロトラスト** — 明示的にallowしたもの以外は禁止
3. **人間インザループ** — 高リスク操作は必ず人間承認
4. **Fail-closed設計** — Guard障害時は全入力をブロック
