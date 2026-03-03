# Security-System

## プロジェクト目的
OpenClawを複数台の専用ミニPCで安全に並行運用するための多層防御（Defense in Depth）セキュリティシステム。

1台の侵害が他インスタンス・クラウドサービス・個人情報に波及しないことを最優先目標とする。

## 解決する問題
- ClawJacked系攻撃（30,000超のexposed instance、悪意スキル流通）への対応
- prompt injection経由の横移動・credential exfil防止
- 複数台運用時の「1台全滅 → 全滅」連鎖を根本的に排除

## 対象環境
- ハードウェア: 専用Mini PC / NUC（N100, 8GB RAM推奨）
- OS: Ubuntu Server 24.04 LTS
- ネットワーク: Tailscaleメッシュ（公開ポートゼロ）
- インスタンス数: 2〜5台（Phase 1）

## 専用機原則（最重要ルール）
> すべてのOpenClawインスタンスは、他の重要アプリケーション・ブラウザ・メール・銀行アプリなどが
> 一切インストールされていない専用ミニPC/NUCのみで運用する。
> メインPC・仕事用ノートPC・家族共有PCへのインストールは絶対禁止。

## 7層 Defense in Depth 概要
| Layer | 名称 | 主技術 |
|-------|------|--------|
| 1 | ネットワーク分離 | Tailscale Mesh + default-deny ACL |
| 2 | コンテナ/サンドボックス | Docker sandbox:all + non-root + cap_drop ALL |
| 3 | 認証・アクセス制御 | インスタンス毎独立Token + pairing allowlist |
| 4 | 機密情報管理 | Infisical JIT注入 + YubiKeyオプション |
| 5 | スキル・プロンプト防御 | ClawHub禁止 + PromptGuard + LLM-as-Judge |
| 6 | 実行時最小権限 | tools default deny + Telegram承認 |
| 7 | 監視・インシデント対応 | Falco + Prometheus + Grafana + Telegram Alert |

## ステータス
- [x] Phase 1 仕様設計完了（v1.0）
- [ ] Phase 1 実装（1台E2Eテスト）
- [ ] Phase 1 複数台展開（2〜5台）
- [ ] Phase 2 拡張（SIEM統合、自動スキル審査等）
