# Layer 5: スキル・プロンプト防御 仕様 v1.0

## 1. 目的
OpenClawのスキル導入経路とプロンプト入力を厳格に防御し、
サプライチェーン攻撃（悪意スキル混入）とprompt injection（悪意命令注入）を根本的に遮断する。

## 2. 基本原則
- **ClawHub直接利用禁止**: 公式スキルストアからの自動インストール一切禁止
- **ホワイトリスト運用**: 自前Gitリポジトリのみ許可（レビュー済み・pinned version）
- **多段階検証**: 導入前チェック（VirusTotal + 静的解析 + 人間レビュー）+ 実行時ガード
- **プロンプト境界防御**: 入力サニタイズ + PromptGuard + LLM-as-Judge
- **全ログ**: Layer 7で監視対象化

## 3. スキル導入フロー

1. **ClawHub検索・取得禁止** (configでブロック)
2. **自前Gitリポジトリ運用**
   - private Git（GitHub/GitLab self-hosted推奨）
   - 人間レビュー後コミット、version pinning必須
   - ※ GitHub へのアクセスは Layer 6 のネットワークホワイトリストに含めること
3. **導入前多段階検証**
   - VirusTotalスキャン（API or CLI）→ 検出0件
   - ※ www.virustotal.com へのアクセスは Layer 6 のネットワークホワイトリストに含めること
   - `openclaw skill audit --deep`
   - 静的解析: `grep -r "eval|exec|curl|rm -rf" <skill_dir>`
   - ステージングテスト（Dockerテスト環境）
4. **config.yaml スキル制限**
```yaml
plugins:
  allow:
    - git_repo: "https://github.com/your-org/openclaw-safe-skills.git"
      ref: "v1.2.3"
  deny:
    - source: clawhub
    - source: unknown
```

## 4. プロンプト防御

### 4.1 入力側ガード
- **PromptGuard / Lakera / Anthropic Guardrails** を事前レイヤーとして配置
- **LLM-as-Judge**: 別モデルで「このプロンプトは危険か？」を判定（スコア0.8以上でブロック）
- ブロックパターン例:
  - "ignore previous instructions"
  - "forget all rules"
  - "system prompt override"

### 4.2 実行時境界
- 記憶汚染防止: `session.dmPolicy: "pairing"` + `dmScope: "per-channel-peer"`
- 出力監視: LLM応答に危険コマンド検出時は即時ブロック + Layer 7アラート

### 4.3 config.yaml 設定
```yaml
prompt:
  guard:
    enabled: true
    model: "claude-3-5-sonnet-20241022"
    block_threshold: 0.8
  sanitize:
    remove_patterns:
      - "ignore previous instructions"
      - "forget all rules"
      - "system prompt override"
```

## 5. 緊急遮断モード（Fail-Closed設計）

### 5.1 発動条件（いずれか1つで発動）
- Layer 7でCRITICALアラート複数回（15分以内3回以上）
- PromptGuard / LLM-as-Judge が連続エラー（API障害）
- 悪意スキル疑い（VirusTotal再スキャンで検出 or 異常挙動ログ）
- 人間判断による緊急発動（Telegramコマンドでトリガー）

### 5.2 発動時の動作（fail-closed）
- 全新規プロンプト入力 → 即時ブロック（"システムメンテナンス中"返答）
- plugins install/update/load → 一時完全凍結
- 高リスクグループ（exec, fs:write, browser等）→ 自動deny
- Layer 7アラート: Telegramに「緊急遮断モード発動」通知

### 5.3 解除条件（必ず人間承認＋監査完了）
1. 原因調査完了（ログ・Falcoイベント・プロンプト履歴確認）
2. VirusTotal再スキャン0件・異常挙動なし
3. Primary OperatorのTelegram承認ボタン押下
4. 解除後即時監視強化（アラート閾値を一時低下）
5. 解除ログ記録（request hash付き）

## 6. 実装・運用ガイドライン（Phase 1）
- Gitリポジトリ初期設定: pinned versionでplugins install
- 導入審査フロー: Telegramグループでレビュー依頼 → 承認後コミット
- PromptGuardテスト: 悪意プロンプトサンプルでブロック確認
- 監査: 週次でスキル一覧・ハッシュ確認、プロンプトブロックログレビュー
- ロールバック: 悪意スキル疑い時は即時 `plugins remove` + コンテナ再起動
