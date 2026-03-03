# Layer 6: 実行時最小権限 仕様 v1.0

## 1. 目的
OpenClawの実行時ツール権限を最小限に抑え、侵害時の被害範囲を極限まで限定する。
docker sandbox（Layer 2）と組み合わせ、prompt injection突破後もファイル破壊・シェル脱獄・C2通信を阻止する。

## 2. 基本原則
- **デフォルトdeny**: すべてのツールグループを原則禁止
- **明示的allowのみ**: 必要なグループだけconfig.yamlで許可
- **人間インザループ**: 高リスクグループ（fs:write, exec, automation, browser等）はTelegram承認必須
- **コンテキスト依存制限**: プロンプト内容に応じて動的にdeny
- **全呼び出しログ**: 許可・拒否問わずツール実行を記録（Layer 7で監視）
- **例外審査**: 一時allowが必要な場合、人間レビュー + 期限付き（例：1時間）

## 3. ツールグループ分類とPhase 1推奨ポリシー

| グループ名 | 代表ツール例 | リスク | Phase 1推奨 | 理由 |
|-----------|------------|--------|-------------|------|
| fs:read | file_read, ls, cat | 中 | allow（workspace内read-only限定） | 作業ファイル参照に必須 |
| fs:write | file_write, mkdir, rm, edit | ★★★★★ | deny（承認必須、一時allowのみ） | データ破壊/ランサムの主経路 |
| exec | shell_exec, run_command | ★★★★★ | deny | シェル脱獄・C2の最大リスク |
| automation | cron, gateway, browser_automation | ★★★★☆ | deny（承認必須） | 自動操作・ブラウザ乗っ取り |
| runtime | python_exec, node_exec, eval | ★★★★★ | deny | コードインジェクション直撃 |
| network | http_get, web_search, web_fetch | ★★★☆☆ | allow（443のみ、ホワイトリスト） | C2防止のためホワイトリスト |
| llm | call_llm, generate_text | 低 | allow | OpenClawの中核機能 |
| browser | open_browser, screenshot, click | ★★★★☆ | deny（承認必須） | Cookie窃取・インジェクション |
| memory/sessions | memory_search, sessions_list | 中 | allow（read-only推奨） | コンテキスト保持に必要 |

## 4. config.yaml 推奨設定（最小権限版）

```yaml
tools:
  deny:
    - group: exec
    - group: runtime
    - group: automation
    - group: browser
    - group: "fs:write"

  allow:
    - group: "fs:read"
    - group: llm
    - group: network
    - group: memory
    - group: sessions

  elevated:
    groups:
      - "fs:write"
      - browser
      - automation
    allowFrom: ["human_approval"]
    requireApproval: true
    approvalTimeout: 30s

  network:
    # Layer 5（スキル管理）・Layer 7（監視）との整合を保つため、
    # 以下のドメインをホワイトリストに含める。
    # 不要なドメインは運用環境に合わせて削除すること。
    allowed_domains:
      - "api.openai.com"          # LLM API
      - "api.anthropic.com"       # LLM API（Anthropic使用時）
      - "api.infisical.com"       # secrets取得（Layer 4）
      - "github.com"              # スキルリポジトリ取得（Layer 5）
      - "raw.githubusercontent.com" # スキルファイル取得（Layer 5）
      - "www.virustotal.com"      # スキル導入前スキャン（Layer 5）
    allowed_ports:
      - 443   # HTTPS（原則）
      - 53    # DNS（名前解決。Layer 7 Falco監視でも必要）

  workspaceAccess: "ro"
```

## 5. 人間承認ワークフロー

- **トリガー**: elevatedグループのツール呼び出し時
- **承認方法**: Telegram interactive button（Approve / Deny / More Info）
- **承認内容表示**:
  - 呼び出し元プロンプト要約
  - ツール名 + 引数（例: file_write /tmp/test.txt）
  - 予想影響
- **タイムアウト**: 30秒（デフォルトdeny）
- **ログ**: 承認/拒否をrequest hash（SHA-256 of prompt+tool+args）付きで記録
- **複数承認**: critical操作は2段階承認を検討

## 6. 例外許可の審査フロー
1. 必要性確認（本当に必要か？代替手段なし？）
2. 人間レビュー（Telegramでプロンプト・引数確認）
3. 一時allow（期限付き：1時間 or 1セッション）
4. 適用後即時監視（Layer 7で異常検知）
5. 終了後自動deny復帰

## 7. 実装・運用ガイドライン（Phase 1）

### 導入手順
1. 全ツールdenyでスタート（`deny: ["*"]`相当）
2. 最小allow適用（fs:read, llm, network 443のみ）
3. 承認設定: elevatedグループに fs:write/browser/automation を登録
4. 監視連携: 全ツール呼び出しログをFalco/Prometheusへ転送（request hash含む）
5. テスト: 高リスクツール呼び出しでTelegramボタン表示・承認フロー確認

### ロールバック手順（設定ミス時）
1. 緊急: Gitから前回正常版をpull → `docker compose restart`
2. 一時全deny: `tools.deny: ["*"]` を適用 → 即時再起動
3. 復旧後レビュー: 変更理由・影響範囲をTelegramグループに報告

### 監査項目（週次チェック）
- 拒否されたツール呼び出し件数・理由分布
- 承認された操作のrequest hashとプロンプト内容サンプリング
- 誤拒否報告（ユーザーフィードバック）
- 例外許可の有効期限切れ確認
- Layer 7アラートとのクロスチェック

### KPI
- ツール拒否率: 80%以上（デフォルトdenyの効果測定）
- 承認率: 拒否率に対する承認割合（高すぎると権限緩和のサイン）
- 誤拒否率: 5%未満目標
- 重大インシデント件数: Layer 6突破による検知イベント（0件目標）

### 既知の制約と緩和策
- 運用負荷増加 → プロンプトテンプレート最適化で承認頻度を低減
- 承認遅延 → 低リスク操作はallowリスト拡大を検討
- 例外管理複雑化 → Git + レビュー必須で変更履歴を強制
