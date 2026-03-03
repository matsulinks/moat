# 脅威インテリジェンス・ワクチン機能 仕様 v1.0

## 1. 目的

外部の脅威情報を定期取得し、新しい攻撃パターンを検知した際に
Falcoルール・iptablesルールを自動生成（ワクチン）して防御を更新する。
また自環境で検知した攻撃パターンを抗体として記録・展開する。

**生物学的ワクチンとの対応**:

| 生物 | 本システム |
|---|---|
| ウイルス侵入 | 攻撃パターン検知 |
| 免疫細胞が分析 | AIが攻撃を分析 |
| 抗体を生成 | 新Falcoルール/iptablesルールを生成 |
| 免疫記憶 | ルールDBに記録 |
| ワクチン接種 | 他インスタンスへ展開（オプション） |

## 2. アーキテクチャ

```
[外部脅威情報ソース]          [自環境での検知]
  CVE/NVD DB                    Falco CRITICAL
  Falcoコミュニティルール         Layer 6拒否ログ
  OpenClawアドバイザリ           AI仲裁エージェント
       ↓                              ↓
[取得・検証エンジン]          [攻撃パターン抽出]
  ・ホワイトリストURLのみ          ・AI分析
  ・SHA-256ハッシュ検証           ・既知パターンとの照合
  ・署名検証（可能な場合）              ↓
       ↓                    [抗体（ルール）生成]
[AI分析エンジン]─────────────→ ・Falcoカスタムルール
  ・新脅威の影響範囲評価           ・iptablesルール
  ・既存ルールとの重複チェック      ・config.yaml例外
  ・ルール生成の判断                    ↓
       ↓                    [ステージング検証]
[ユーザー承認]←───────────────  ・ドライラン実行
  Telegram通知                   ・既存ルールと競合チェック
  「新しい脅威を検知しました。        ↓
   防御ルールを更新しますか？」  [承認後に本番適用]
       ↓（承認）
[ルール適用・記録]
  ・Falco再ロード
  ・iptables更新
  ・ルールDBに記録
  ・（オプション）コミュニティ共有
```

## 3. 外部脅威情報ソース（ホワイトリスト）

取得できるURLはこのリストのみ。追加はユーザーが明示的に設定する。

```yaml
threat_intel_sources:
  # CVE・脆弱性情報
  - name: "NVD CVE Feed"
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    format: "json"
    verify_tls: true
    update_interval: "24h"

  # Falcoコミュニティルール
  - name: "Falco Community Rules"
    url: "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml"
    format: "yaml"
    verify_tls: true
    verify_hash: true          # SHA-256を公式サイトと照合
    update_interval: "24h"

  # OpenClawセキュリティアドバイザリ（将来）
  - name: "OpenClaw Advisory"
    url: "https://raw.githubusercontent.com/openclaw/security/main/advisories.json"
    format: "json"
    verify_tls: true
    update_interval: "6h"
```

**追加禁止**: ユーザー設定外のURLへのアクセスはコードレベルでブロック。

## 4. 取得・検証エンジン

### 4.1 ハッシュ検証フロー

```python
# 疑似コード
def fetch_and_verify(source):
    response = https_get(source.url)         # TLS必須
    content_hash = sha256(response.body)

    if source.verify_hash:
        expected_hash = fetch_official_hash(source)  # 公式サイトから取得
        if content_hash != expected_hash:
            alert("ハッシュ不一致: 取得をスキップ")
            return None

    return parse(response.body, source.format)
```

### 4.2 レート制限

- 最短取得間隔: 1時間（DoS防止）
- 失敗時リトライ: 最大3回、指数バックオフ
- 1回の取得でサイズ上限: 10MB

## 5. AI分析エンジン（ワクチン生成）

### 5.1 自環境での攻撃検知時

```
Falco CRITICAL イベント発生
      ↓
AIに送信（匿名化済み）:
  「コンテナ内でシェルが起動されました。
   プロセス名: bash, コマンド: [コマンド内容]
   この攻撃パターンに対するFalcoルールを生成してください」
      ↓
AI が返す:
  - 攻撃の分類（MITRE ATT&CK対応）
  - 新しいFalcoルール（YAML形式）
  - iptablesルール（必要な場合）
  - リスクレベル
```

### 5.2 外部情報から新脅威を検知時

```
NVD から新CVE取得（OpenClaw関連）
      ↓
AIに送信:
  「CVE-XXXX-XXXXX: OpenClaw X.X.X に影響する脆弱性です。
   現在の防御ルールで対応できているか評価し、
   不足があれば追加ルールを提案してください」
      ↓
AI が返す:
  - 既存ルールでの対応可否
  - 追加が必要なルール（YAML形式）
  - 緊急度評価
```

## 6. 生成ルールの品質管理

### 6.1 ステージング検証（自動）

```bash
# 生成されたFalcoルールのドライラン
falco --dry-run -r /tmp/generated_rule.yaml

# 構文チェック
falco --validate -r /tmp/generated_rule.yaml
```

### 6.2 競合チェック

- 既存ルールと同じ名前のルールがないか
- 既存の許可ルールを無効化しないか
- 過度に広い条件（`condition: always`等）を含まないか

### 6.3 人間レビューのガイドライン

Telegramに以下を通知してユーザーが確認:

```
🛡️ 新しい防御ルールの提案

検知内容: コンテナ内でのcurl実行（非ホワイトリスト宛先）
攻撃分類: C2通信試行（MITRE T1071）
リスク: HIGH

生成ルール:
  rule: Suspicious Curl in Container
  condition: spawned_process and proc.name=curl and ...
  priority: WARNING

適用しますか？ [適用] [却下] [詳細を見る]
```

## 7. ルールDB（ローカル記録）

```
/opt/openclaw/security/
  rules-db/
    applied/         # 適用済みルール
    rejected/        # 却下されたルール（理由付き）
    pending/         # 承認待ちルール
  intel-cache/       # 取得した脅威情報キャッシュ
  audit.log          # 全操作ログ
```

## 8. コミュニティ共有（オプション・デフォルトOFF）

自環境で発見した攻撃パターンを匿名化して共有する機能。
**デフォルトはOFF**。ユーザーが明示的に有効化した場合のみ動作。

```yaml
community_sharing:
  enabled: false      # デフォルトOFF
  share_endpoint: "https://security.openclaw.ai/submit"  # 将来実装
  anonymize: true     # 常にtrue固定（変更不可）
  share_what:
    - attack_pattern  # 攻撃パターンのみ
    # 共有しないもの: IP, ホスト名, ユーザー情報, コンテンツ
```

## 9. ユーザー設定（config.yaml）

```yaml
threat_intelligence:
  enabled: true
  sources:            # 上記ホワイトリストから選択
    - nvd_cve
    - falco_community
  update_schedule: "0 3 * * *"   # 毎日午前3時（cron形式）
  ai_api:
    provider: "openai"
    model: "gpt-4o"
    api_key: "{{ INFISICAL_OPENAI_API_KEY }}"
  approval_level: high_risk_only  # none / high_risk_only / all
  auto_apply_max_risk: "LOW"     # LOWリスクのみ自動適用（要承認設定時は無視）
  notification:
    telegram: true
```

## 10. セキュリティ考慮点

| リスク | 対策 |
|---|---|
| 汚染されたルールの自動適用 | ハッシュ検証 + 人間承認必須 |
| 取得先URLの改ざん | HTTPS + ホワイトリスト固定 |
| AI生成ルールに悪意ある条件 | ステージング検証 + 人間レビュー |
| 過度なAPI呼び出しコスト | レート制限 + キャッシュ活用 |
| 誤検知による過剰ブロック | LOW以上は人間承認必須 |
| コミュニティ共有での情報漏洩 | デフォルトOFF + 匿名化固定 |

## 11. 外部通信ホワイトリスト（本機能専用）

```yaml
threat_intel_whitelist:
  - "services.nvd.nist.gov:443"
  - "raw.githubusercontent.com:443"     # Falcoルール取得
  - "api.openai.com:443"                # AI分析
  # コミュニティ共有が有効な場合のみ追加:
  # - "security.openclaw.ai:443"
```
