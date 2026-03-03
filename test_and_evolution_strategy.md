# テスト戦略・進化ロードマップ

## 1. テスト戦略（Phase 1）

### 1.1 E2Eテストシナリオ

| シナリオ | 手順 | 期待結果 |
|---------|------|---------|
| 正常系 | Telegramから低リスクプロンプト送信 | 即時返答成功 |
| 高リスクツール | fs:writeツール呼び出し | Telegram承認ボタン表示 → Approve=実行/Deny=ブロック |
| 悪意プロンプト | 「ignore previous instructions」送信 | Layer 5でブロック + Telegramに警告 |
| Falcoルール検証 | falco-event-generator でshell spawn疑似発火 | Telegramにアラート到達 |
| 緊急遮断 | Telegramコマンドで手動発動 | 全プロンプトブロック → 手動解除成功 |
| 乗っ取りシミュレーション | 1インスタンスのtoken漏洩（意図的に旧token使用） | 他インスタンスに影響なし確認 |

### 1.2 完了定義（DoD: Definition of Done）
- [ ] Telegramから低リスクプロンプト → 即時返答成功
- [ ] 高リスクツール呼び出し → 承認ボタン表示 → Approve=実行/Deny=ブロック
- [ ] 悪意プロンプト（忘却命令等） → Layer 5でブロック + Telegramに警告
- [ ] Falcoテストアラート → Telegramに届く
- [ ] 緊急遮断モード手動発動 → 全入力ブロック → 手動解除成功
- [ ] docker logs / Falcoログ / Grafanaに異常なし
- [ ] 1台で上記すべてパス

### 1.3 Falcoルール検証手順
```bash
# Falco event-generatorインストール
docker run -it falcosecurity/event-generator run --all

# 特定ルールのみテスト
docker run -it falcosecurity/event-generator run shell_spawned_in_a_container
```

### 1.4 Prometheusアラートテスト
```bash
# Alertmanagerにテストアラート送信
curl -XPOST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{"labels":{"alertname":"TestAlert","severity":"critical","instance":"instance01"}}]'
```

## 2. 失敗しやすい箇所の事前確認リスト

- [ ] Tailscale ACLで `tag:openclaw-instance → infisical-server:443` が通るか（`tailscale ping` or `curl`テスト）
- [ ] Infisical Service Tokenの権限がread-onlyか
- [ ] Docker userが10000:10000で正しく動作するか（permission deniedが出ないか）
- [ ] config.yamlのtokenがInfisicalから正しく注入されているか（`docker logs`で確認）
- [ ] requireMentionがグループでtrue・DMで任意になっているか
- [ ] Falco eBPFが正しくロードされているか（`falco --version` & `lsmod | grep falco`）
- [ ] Telegram Botがオンラインでmentionに反応するか（`/my_id`でuser_id確認）

## 3. 進化ロードマップ

### Phase 1（現在）: 仕様設計完了 → 実装
- 1台E2E構築・検証
- 全Layer実装（Docker hardening + Infisical + Falco + Prometheus）
- 2〜5台展開

### Phase 2（将来拡張）
- Loki + GrafanaでFalcoログ全文検索
- OpenClawのLLM応答内容監査（異常プロンプト/出力検知）
- SIEM統合（Graylog/Splunk）または商用EDR（CrowdStrike等）
- 自動スキルレビューパイプライン（LLMベース）
- Multi-region Vault replication
- Federated identity（チーム利用）

## 4. 週次監査チェックリスト
- [ ] Falcoアラートログレビュー（誤検知チューニング）
- [ ] ツール拒否率・承認率確認（KPI）
- [ ] Tailscale Audit Logs確認
- [ ] Infisical Service Token有効期限確認（残り7日以下で更新）
- [ ] docker psで全インスタンス稼働確認
- [ ] Grafanaダッシュボードで異常値確認
