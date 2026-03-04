#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Moat — AI Security for self-hosted agents (single-file, stdlib only)."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
DEFAULT_RELEASES_API = "https://api.github.com/repos/matsulinks/moat/releases/latest"
DEFAULT_RULES_URL = "https://raw.githubusercontent.com/matsulinks/moat/main/community-rules.json"
DEFAULT_RULES_SHA_URL = "https://raw.githubusercontent.com/matsulinks/moat/main/community-rules.json.sha256"
DEFAULT_REPORT_ISSUE_URL = "https://github.com/matsulinks/moat/issues/new"
RELEASES_API = os.environ.get("MOAT_RELEASES_API", DEFAULT_RELEASES_API)
RULES_URL = os.environ.get("MOAT_RULES_URL", DEFAULT_RULES_URL)
RULES_SHA_URL = os.environ.get("MOAT_RULES_SHA_URL", DEFAULT_RULES_SHA_URL)
REPORT_ISSUE_URL = os.environ.get("MOAT_REPORT_ISSUE_URL", DEFAULT_REPORT_ISSUE_URL)
OUTPUT_DIR = Path("output")

COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_CYAN = "\033[96m"

# ─── i18n ────────────────────────────────────────────────────────────────────
CURRENT_LANG = "en"

STRINGS: dict[str, dict[str, str]] = {
    # Layer titles
    "title_layer1": {
        "en": "Network Isolation (Tailscale ACL + iptables)",
        "ja": "ネットワーク分離 (Tailscale ACL + iptables)",
        "zh": "网络隔离 (Tailscale ACL + iptables)",
        "ko": "네트워크 격리 (Tailscale ACL + iptables)",
        "de": "Netzwerkisolierung (Tailscale ACL + iptables)",
        "es": "Aislamiento de red (Tailscale ACL + iptables)",
        "pt": "Isolamento de rede (Tailscale ACL + iptables)",
    },
    "title_layer2": {
        "en": "Docker Hardening",
        "ja": "Docker ハードニング",
        "zh": "Docker 加固",
        "ko": "Docker 강화",
        "de": "Docker Hardening",
        "es": "Hardening de Docker",
        "pt": "Hardening do Docker",
    },
    "title_layer3": {
        "en": "Auth & Access Control",
        "ja": "認証・アクセス制御",
        "zh": "认证与访问控制",
        "ko": "인증 및 접근 제어",
        "de": "Authentifizierung & Zugriffskontrolle",
        "es": "Autenticación y control de acceso",
        "pt": "Autenticação e controle de acesso",
    },
    "title_layer4": {
        "en": "Secrets Management (Infisical)",
        "ja": "機密情報管理 (Infisical)",
        "zh": "机密信息管理 (Infisical)",
        "ko": "시크릿 관리 (Infisical)",
        "de": "Secrets Management (Infisical)",
        "es": "Gestión de secretos (Infisical)",
        "pt": "Gestão de segredos (Infisical)",
    },
    "title_layer5": {
        "en": "Skill & Prompt Defense",
        "ja": "スキル・プロンプト防御",
        "zh": "技能与提示词防御",
        "ko": "스킬 및 프롬프트 방어",
        "de": "Skill- & Prompt-Schutz",
        "es": "Defensa de skills y prompts",
        "pt": "Defesa de skills e prompts",
    },
    "title_layer6": {
        "en": "Runtime Least Privilege",
        "ja": "実行時最小権限",
        "zh": "运行时最小权限",
        "ko": "런타임 최소 권한",
        "de": "Minimale Laufzeitrechte",
        "es": "Mínimos privilegios en tiempo de ejecución",
        "pt": "Mínimo privilégio em tempo de execução",
    },
    "title_layer7": {
        "en": "Monitoring (Falco + Prometheus)",
        "ja": "監視 (Falco + Prometheus)",
        "zh": "监控 (Falco + Prometheus)",
        "ko": "모니터링 (Falco + Prometheus)",
        "de": "Überwachung (Falco + Prometheus)",
        "es": "Monitoreo (Falco + Prometheus)",
        "pt": "Monitoramento (Falco + Prometheus)",
    },
    "title_ai-m": {
        "en": "AI Arbitration Agent",
        "ja": "AI仲裁エージェント",
        "zh": "AI 仲裁代理",
        "ko": "AI 중재 에이전트",
        "de": "KI-Arbitrations-Agent",
        "es": "Agente de arbitraje IA",
        "pt": "Agente de arbitragem IA",
    },
    "title_ai-t": {
        "en": "Threat Intelligence & Vaccine",
        "ja": "脅威インテリジェンス・ワクチン",
        "zh": "威胁情报与疫苗",
        "ko": "위협 인텔리전스 및 백신",
        "de": "Bedrohungsintelligenz & Impfung",
        "es": "Inteligencia de amenazas y vacuna",
        "pt": "Inteligência de ameaças e vacina",
    },
    # Status labels
    "status_recommend": {
        "en": "Recommended", "ja": "推奨", "zh": "推荐",
        "ko": "권장", "de": "Empfohlen", "es": "Recomendado", "pt": "Recomendado",
    },
    "status_optional": {
        "en": "Optional", "ja": "任意", "zh": "可选",
        "ko": "선택", "de": "Optional", "es": "Opcional", "pt": "Opcional",
    },
    "status_skip": {
        "en": "Not Recommended", "ja": "非推奨", "zh": "不推荐",
        "ko": "비권장", "de": "Nicht empfohlen", "es": "No recomendado", "pt": "Não recomendado",
    },
    # Env summary
    "env_heading": {
        "en": "■ Detection Results", "ja": "■ 検出結果", "zh": "■ 检测结果",
        "ko": "■ 감지 결과", "de": "■ Erkennungsergebnisse",
        "es": "■ Resultados de detección", "pt": "■ Resultados da detecção",
    },
    "env_hardware": {
        "en": "Hardware", "ja": "ハードウェア", "zh": "硬件",
        "ko": "하드웨어", "de": "Hardware", "es": "Hardware", "pt": "Hardware",
    },
    "env_unknown": {
        "en": "Unknown", "ja": "不明", "zh": "未知",
        "ko": "알 수 없음", "de": "Unbekannt", "es": "Desconocido", "pt": "Desconhecido",
    },
    "installed": {
        "en": "Installed ✓", "ja": "インストール済み ✓", "zh": "已安装 ✓",
        "ko": "설치됨 ✓", "de": "Installiert ✓", "es": "Instalado ✓", "pt": "Instalado ✓",
    },
    "not_installed": {
        "en": "Not installed", "ja": "未インストール", "zh": "未安装",
        "ko": "미설치", "de": "Nicht installiert", "es": "No instalado", "pt": "Não instalado",
    },
    # Layer table
    "layer_table_heading": {
        "en": "■ Layer Settings (toggle ON/OFF by number or ID, Enter to confirm)",
        "ja": "■ レイヤー設定（番号かIDでON/OFF切り替え、Enterで確定）",
        "zh": "■ 层设置（输入编号或ID切换 ON/OFF，回车确认）",
        "ko": "■ 레이어 설정 (번호 또는 ID로 ON/OFF 전환, Enter로 확정)",
        "de": "■ Layer-Einstellungen (Nummer oder ID zum Umschalten, Enter zum Bestätigen)",
        "es": "■ Configuración de capas (número o ID para ON/OFF, Enter para confirmar)",
        "pt": "■ Configuração de camadas (número ou ID para ON/OFF, Enter para confirmar)",
    },
    "layer_gen_mac": {
        "en": "Output: tailscale-acl.json (iptables-setup.sh not generated)",
        "ja": "生成: tailscale-acl.json（iptables-setup.sh は生成しません）",
        "zh": "生成: tailscale-acl.json（不生成 iptables-setup.sh）",
        "ko": "생성: tailscale-acl.json (iptables-setup.sh 생성 안 함)",
        "de": "Ausgabe: tailscale-acl.json (iptables-setup.sh wird nicht generiert)",
        "es": "Salida: tailscale-acl.json (iptables-setup.sh no se genera)",
        "pt": "Saída: tailscale-acl.json (iptables-setup.sh não gerado)",
    },
    "layer_gen": {
        "en": "Output: ", "ja": "生成: ", "zh": "生成: ",
        "ko": "생성: ", "de": "Ausgabe: ", "es": "Salida: ", "pt": "Saída: ",
    },
    "layer_hint": {
        "en": "Enter=Generate / q=Quit",
        "ja": "Enter=生成開始 / q=終了",
        "zh": "Enter=生成 / q=退出",
        "ko": "Enter=생성 / q=종료",
        "de": "Enter=Generieren / q=Beenden",
        "es": "Enter=Generar / q=Salir",
        "pt": "Enter=Gerar / q=Sair",
    },
    "input_prompt": {
        "en": "Input: ", "ja": "入力: ", "zh": "输入: ",
        "ko": "입력: ", "de": "Eingabe: ", "es": "Entrada: ", "pt": "Entrada: ",
    },
    "invalid_input": {
        "en": "Invalid input.", "ja": "無効な入力です。", "zh": "无效输入。",
        "ko": "잘못된 입력입니다.", "de": "Ungültige Eingabe.",
        "es": "Entrada no válida.", "pt": "Entrada inválida.",
    },
    "layer_skip_locked": {
        "en": "This layer is not recommended for your environment and cannot be changed.",
        "ja": "このレイヤーは現在の環境では非推奨のため変更できません。",
        "zh": "此层在当前环境下不推荐，无法更改。",
        "ko": "이 레이어는 현재 환경에서 비권장이므로 변경할 수 없습니다.",
        "de": "Diese Schicht ist für Ihre Umgebung nicht empfohlen und kann nicht geändert werden.",
        "es": "Esta capa no es recomendada para tu entorno y no se puede cambiar.",
        "pt": "Esta camada não é recomendada para seu ambiente e não pode ser alterada.",
    },
    # Approval level
    "approval_heading": {
        "en": "Select approval level:", "ja": "承認レベルを選んでください:",
        "zh": "请选择审批级别:", "ko": "승인 레벨을 선택하세요:",
        "de": "Genehmigungsstufe wählen:", "es": "Selecciona el nivel de aprobación:",
        "pt": "Selecione o nível de aprovação:",
    },
    "approval_1": {
        "en": "  [1] Fully automatic (no approval)",
        "ja": "  [1] すべて自動（承認なし）",
        "zh": "  [1] 全自动（无需审批）",
        "ko": "  [1] 완전 자동 (승인 없음)",
        "de": "  [1] Vollautomatisch (keine Genehmigung)",
        "es": "  [1] Totalmente automático (sin aprobación)",
        "pt": "  [1] Totalmente automático (sem aprovação)",
    },
    "approval_2": {
        "en": "  [2] Approve high-risk only (recommended)",
        "ja": "  [2] 高リスクのみ承認（推奨）",
        "zh": "  [2] 仅审批高风险操作（推荐）",
        "ko": "  [2] 고위험만 승인 (권장)",
        "de": "  [2] Nur Hochrisiko genehmigen (empfohlen)",
        "es": "  [2] Solo aprobar alto riesgo (recomendado)",
        "pt": "  [2] Aprovar apenas alto risco (recomendado)",
    },
    "approval_3": {
        "en": "  [3] Approve all", "ja": "  [3] すべて承認",
        "zh": "  [3] 审批所有", "ko": "  [3] 모두 승인",
        "de": "  [3] Alle genehmigen", "es": "  [3] Aprobar todo", "pt": "  [3] Aprovar tudo",
    },
    "approval_prompt": {
        "en": "Choice (1/2/3, default 2): ", "ja": "選択 (1/2/3, デフォルト2): ",
        "zh": "选择 (1/2/3，默认2): ", "ko": "선택 (1/2/3, 기본값 2): ",
        "de": "Auswahl (1/2/3, Standard 2): ", "es": "Opción (1/2/3, por defecto 2): ",
        "pt": "Opção (1/2/3, padrão 2): ",
    },
    # Self update
    "update_checking": {
        "en": "Checking for latest version...", "ja": "最新バージョンを確認中...",
        "zh": "检查最新版本中...", "ko": "최신 버전 확인 중...",
        "de": "Neueste Version wird geprüft...", "es": "Verificando la última versión...",
        "pt": "Verificando a versão mais recente...",
    },
    "update_fetch_failed": {
        "en": "Failed to fetch update info: {exc}", "ja": "更新情報の取得に失敗しました: {exc}",
        "zh": "获取更新信息失败: {exc}", "ko": "업데이트 정보 가져오기 실패: {exc}",
        "de": "Update-Info konnte nicht abgerufen werden: {exc}",
        "es": "Error al obtener información de actualización: {exc}",
        "pt": "Falha ao buscar informações de atualização: {exc}",
    },
    "update_ref_url": {
        "en": "Reference URL: {url}", "ja": "参照URL: {url}", "zh": "参考URL: {url}",
        "ko": "참조 URL: {url}", "de": "Referenz-URL: {url}",
        "es": "URL de referencia: {url}", "pt": "URL de referência: {url}",
    },
    "update_env_hint": {
        "en": "Set MOAT_RELEASES_API env var to override.",
        "ja": "必要なら環境変数 MOAT_RELEASES_API でURLを変更してください。",
        "zh": "如需修改，请设置环境变量 MOAT_RELEASES_API。",
        "ko": "필요 시 MOAT_RELEASES_API 환경 변수로 URL을 변경하세요.",
        "de": "URL-Override: MOAT_RELEASES_API Umgebungsvariable setzen.",
        "es": "Usa la variable de entorno MOAT_RELEASES_API para cambiar la URL.",
        "pt": "Use a variável de ambiente MOAT_RELEASES_API para alterar a URL.",
    },
    "update_invalid_version": {
        "en": "Latest version info is invalid.", "ja": "最新バージョン情報が不正です。",
        "zh": "最新版本信息无效。", "ko": "최신 버전 정보가 올바르지 않습니다.",
        "de": "Neueste Versionsinformation ist ungültig.",
        "es": "La información de la última versión no es válida.",
        "pt": "As informações da versão mais recente são inválidas.",
    },
    "update_already_latest": {
        "en": "Already up to date (current: {current} / latest: {latest})",
        "ja": "すでに最新です（現在: {current} / 最新: {latest}）",
        "zh": "已是最新版本（当前: {current} / 最新: {latest}）",
        "ko": "이미 최신 버전입니다 (현재: {current} / 최신: {latest})",
        "de": "Bereits aktuell (aktuell: {current} / neueste: {latest})",
        "es": "Ya está actualizado (actual: {current} / último: {latest})",
        "pt": "Já está atualizado (atual: {current} / mais recente: {latest})",
    },
    "update_available": {
        "en": "New version available: {current} -> {latest}",
        "ja": "新しいバージョンがあります: {current} -> {latest}",
        "zh": "有新版本: {current} -> {latest}", "ko": "새 버전이 있습니다: {current} -> {latest}",
        "de": "Neue Version verfügbar: {current} -> {latest}",
        "es": "Nueva versión disponible: {current} -> {latest}",
        "pt": "Nova versão disponível: {current} -> {latest}",
    },
    "update_changes": {
        "en": "Changes (first 200 chars):", "ja": "変更概要（先頭200文字）:",
        "zh": "更新内容（前200字符）:", "ko": "변경 사항 (처음 200자):",
        "de": "Änderungen (erste 200 Zeichen):", "es": "Cambios (primeros 200 caracteres):",
        "pt": "Mudanças (primeiros 200 caracteres):",
    },
    "update_confirm": {
        "en": "Update? [y/N]: ", "ja": "更新しますか？ [y/N]: ",
        "zh": "是否更新？ [y/N]: ", "ko": "업데이트하시겠습니까? [y/N]: ",
        "de": "Aktualisieren? [y/N]: ", "es": "¿Actualizar? [y/N]: ", "pt": "Atualizar? [y/N]: ",
    },
    "update_cancelled": {
        "en": "Update cancelled.", "ja": "更新を中止しました。",
        "zh": "更新已取消。", "ko": "업데이트가 취소되었습니다.",
        "de": "Aktualisierung abgebrochen.", "es": "Actualización cancelada.", "pt": "Atualização cancelada.",
    },
    "update_no_asset": {
        "en": "Release assets setup.py / setup.py.sha256 not found.",
        "ja": "リリースアセットに setup.py / setup.py.sha256 が見つかりません。",
        "zh": "在发布资产中未找到 setup.py / setup.py.sha256。",
        "ko": "릴리스 자산에서 setup.py / setup.py.sha256을 찾을 수 없습니다.",
        "de": "Release-Assets setup.py / setup.py.sha256 nicht gefunden.",
        "es": "No se encontraron los archivos setup.py / setup.py.sha256 en los assets.",
        "pt": "Assets do release setup.py / setup.py.sha256 não encontrados.",
    },
    "update_dl_failed": {
        "en": "Failed to download update: {exc}", "ja": "更新ファイルの取得に失敗しました: {exc}",
        "zh": "下载更新失败: {exc}", "ko": "업데이트 다운로드 실패: {exc}",
        "de": "Update konnte nicht heruntergeladen werden: {exc}",
        "es": "Error al descargar la actualización: {exc}",
        "pt": "Falha ao baixar a atualização: {exc}",
    },
    "update_verify_failed": {
        "en": "SHA256 verification failed. Update cancelled.",
        "ja": "SHA256検証に失敗しました。更新を中止します。",
        "zh": "SHA256 验证失败。更新已取消。", "ko": "SHA256 검증 실패. 업데이트가 취소되었습니다.",
        "de": "SHA256-Überprüfung fehlgeschlagen. Aktualisierung abgebrochen.",
        "es": "Verificación SHA256 fallida. Actualización cancelada.",
        "pt": "Verificação SHA256 falhou. Atualização cancelada.",
    },
    "update_write_failed": {
        "en": "Failed to write update: {exc}", "ja": "ファイル更新に失敗しました: {exc}",
        "zh": "写入更新失败: {exc}", "ko": "업데이트 쓰기 실패: {exc}",
        "de": "Update konnte nicht geschrieben werden: {exc}",
        "es": "Error al escribir la actualización: {exc}",
        "pt": "Falha ao escrever a atualização: {exc}",
    },
    "update_done": {
        "en": "Updated. Backup saved to setup.py.bak.",
        "ja": "更新しました。setup.py.bak にバックアップを保存しました。",
        "zh": "已更新。备份已保存至 setup.py.bak。",
        "ko": "업데이트 완료. 백업이 setup.py.bak에 저장되었습니다.",
        "de": "Aktualisiert. Sicherung in setup.py.bak gespeichert.",
        "es": "Actualizado. Copia de seguridad guardada en setup.py.bak.",
        "pt": "Atualizado. Backup salvo em setup.py.bak.",
    },
    # Update rules
    "rules_fetching": {
        "en": "Fetching community rules...", "ja": "コミュニティルールを取得中...",
        "zh": "正在获取社区规则...", "ko": "커뮤니티 규칙 가져오는 중...",
        "de": "Community-Regeln werden abgerufen...", "es": "Obteniendo reglas de la comunidad...",
        "pt": "Buscando regras da comunidade...",
    },
    "rules_fetch_failed": {
        "en": "Failed to fetch rules: {exc}", "ja": "ルール取得に失敗しました: {exc}",
        "zh": "获取规则失败: {exc}", "ko": "규칙 가져오기 실패: {exc}",
        "de": "Regeln konnten nicht abgerufen werden: {exc}",
        "es": "Error al obtener reglas: {exc}", "pt": "Falha ao buscar regras: {exc}",
    },
    "rules_url": {
        "en": "Rules URL: {url}", "ja": "ルールURL: {url}", "zh": "规则URL: {url}",
        "ko": "규칙 URL: {url}", "de": "Regeln-URL: {url}",
        "es": "URL de reglas: {url}", "pt": "URL das regras: {url}",
    },
    "rules_sha_url": {
        "en": "SHA URL  : {url}", "ja": "SHA URL  : {url}", "zh": "SHA URL  : {url}",
        "ko": "SHA URL  : {url}", "de": "SHA URL  : {url}",
        "es": "SHA URL  : {url}", "pt": "SHA URL  : {url}",
    },
    "rules_env_hint": {
        "en": "Set MOAT_RULES_URL / MOAT_RULES_SHA_URL to override.",
        "ja": "必要なら MOAT_RULES_URL / MOAT_RULES_SHA_URL で変更してください。",
        "zh": "如需修改，请设置 MOAT_RULES_URL / MOAT_RULES_SHA_URL。",
        "ko": "MOAT_RULES_URL / MOAT_RULES_SHA_URL 환경 변수로 변경 가능합니다.",
        "de": "Zum Überschreiben MOAT_RULES_URL / MOAT_RULES_SHA_URL setzen.",
        "es": "Usa MOAT_RULES_URL / MOAT_RULES_SHA_URL para cambiar la URL.",
        "pt": "Use MOAT_RULES_URL / MOAT_RULES_SHA_URL para alterar.",
    },
    "rules_verify_failed": {
        "en": "SHA256 verification failed. Update cancelled.",
        "ja": "SHA256検証に失敗しました。更新を中止します。",
        "zh": "SHA256 验证失败。更新已取消。", "ko": "SHA256 검증 실패. 업데이트가 취소되었습니다.",
        "de": "SHA256-Überprüfung fehlgeschlagen. Aktualisierung abgebrochen.",
        "es": "Verificación SHA256 fallida. Actualización cancelada.",
        "pt": "Verificação SHA256 falhou. Atualização cancelada.",
    },
    "rules_parse_failed": {
        "en": "Failed to parse community-rules.json: {exc}",
        "ja": "community-rules.json の解析に失敗しました: {exc}",
        "zh": "解析 community-rules.json 失败: {exc}",
        "ko": "community-rules.json 파싱 실패: {exc}",
        "de": "community-rules.json konnte nicht geparst werden: {exc}",
        "es": "Error al analizar community-rules.json: {exc}",
        "pt": "Falha ao analisar community-rules.json: {exc}",
    },
    "rules_added": {
        "en": "New rules: {count}", "ja": "追加ルール数: {count}", "zh": "新增规则数: {count}",
        "ko": "추가된 규칙 수: {count}", "de": "Neue Regeln: {count}",
        "es": "Reglas nuevas: {count}", "pt": "Novas regras: {count}",
    },
    "rules_changed": {
        "en": "Changed rules: {count}", "ja": "変更ルール数: {count}", "zh": "更新规则数: {count}",
        "ko": "변경된 규칙 수: {count}", "de": "Geänderte Regeln: {count}",
        "es": "Reglas modificadas: {count}", "pt": "Regras alteradas: {count}",
    },
    "rules_confirm": {
        "en": "Apply? [y/N]: ", "ja": "適用しますか？ [y/N]: ",
        "zh": "是否应用？ [y/N]: ", "ko": "적용하시겠습니까? [y/N]: ",
        "de": "Anwenden? [y/N]: ", "es": "¿Aplicar? [y/N]: ", "pt": "Aplicar? [y/N]: ",
    },
    "rules_cancelled": {
        "en": "Update cancelled.", "ja": "更新を中止しました。",
        "zh": "更新已取消。", "ko": "업데이트가 취소되었습니다.",
        "de": "Aktualisierung abgebrochen.", "es": "Actualización cancelada.", "pt": "Atualização cancelada.",
    },
    "rules_done": {
        "en": "Updated to output/. See SETUP_GUIDE.md for Falco restart instructions.",
        "ja": "output/ に更新しました。falco再起動などの適用手順は SETUP_GUIDE.md を参照",
        "zh": "已更新至 output/。有关 Falco 重启步骤，请参阅 SETUP_GUIDE.md。",
        "ko": "output/에 업데이트되었습니다. Falco 재시작 등의 적용 절차는 SETUP_GUIDE.md 참조.",
        "de": "In output/ aktualisiert. Siehe SETUP_GUIDE.md für Falco-Neustart.",
        "es": "Actualizado en output/. Ver SETUP_GUIDE.md para reiniciar Falco.",
        "pt": "Atualizado em output/. Veja SETUP_GUIDE.md para reiniciar o Falco.",
    },
    # Windows / OS detection
    "win_not_supported": {
        "en": "Windows is not currently supported.", "ja": "Windows は現在サポート対象外です。",
        "zh": "当前不支持 Windows。", "ko": "현재 Windows는 지원되지 않습니다.",
        "de": "Windows wird derzeit nicht unterstützt.",
        "es": "Windows no está soportado actualmente.", "pt": "Windows não é suportado atualmente.",
    },
    "win_use_wsl": {
        "en": "Please use WSL2 (Windows Subsystem for Linux).",
        "ja": "WSL2（Windows Subsystem for Linux）を使用してください。",
        "zh": "请使用 WSL2（适用于 Linux 的 Windows 子系统）。",
        "ko": "WSL2(Windows Subsystem for Linux)를 사용하세요.",
        "de": "Bitte WSL2 (Windows Subsystem for Linux) verwenden.",
        "es": "Por favor, usa WSL2 (Windows Subsystem for Linux).",
        "pt": "Por favor, use o WSL2 (Windows Subsystem for Linux).",
    },
    "os_not_supported": {
        "en": "This OS is not supported.", "ja": "このOSはサポートされていません。",
        "zh": "此操作系统不受支持。", "ko": "이 OS는 지원되지 않습니다.",
        "de": "Dieses Betriebssystem wird nicht unterstützt.",
        "es": "Este sistema operativo no está soportado.",
        "pt": "Este sistema operacional não é suportado.",
    },
    # Web mode
    "web_started": {
        "en": "Browser mode started: {url}", "ja": "ブラウザモードを起動しました: {url}",
        "zh": "浏览器模式已启动: {url}", "ko": "브라우저 모드 시작: {url}",
        "de": "Browser-Modus gestartet: {url}", "es": "Modo navegador iniciado: {url}",
        "pt": "Modo navegador iniciado: {url}",
    },
    "web_quit": {
        "en": "Press Ctrl+C to quit.", "ja": "終了するには Ctrl+C を押してください。",
        "zh": "按 Ctrl+C 退出。", "ko": "종료하려면 Ctrl+C를 누르세요.",
        "de": "Zum Beenden Ctrl+C drücken.", "es": "Presiona Ctrl+C para salir.",
        "pt": "Pressione Ctrl+C para sair.",
    },
    "web_stopped": {
        "en": "Stopped.", "ja": "終了します。", "zh": "已退出。",
        "ko": "종료합니다.", "de": "Beendet.", "es": "Detenido.", "pt": "Encerrado.",
    },
    # AI key
    "ai_key_needed": {
        "en": "AI features require an OpenAI API key.",
        "ja": "AI機能にはOpenAI APIキーが必要です。",
        "zh": "AI 功能需要 OpenAI API 密钥。", "ko": "AI 기능에는 OpenAI API 키가 필요합니다.",
        "de": "KI-Funktionen erfordern einen OpenAI-API-Schlüssel.",
        "es": "Las funciones de IA requieren una clave de API de OpenAI.",
        "pt": "Os recursos de IA requerem uma chave de API da OpenAI.",
    },
    "ai_key_prompt": {
        "en": "Enter OPENAI_API_KEY (leave blank to skip AI features): ",
        "ja": "OPENAI_API_KEY を入力（未入力ならAI機能をスキップ）: ",
        "zh": "请输入 OPENAI_API_KEY（留空则跳过 AI 功能）: ",
        "ko": "OPENAI_API_KEY 입력 (비워두면 AI 기능 건너뜀): ",
        "de": "OPENAI_API_KEY eingeben (leer lassen für kein KI): ",
        "es": "Ingresa OPENAI_API_KEY (en blanco para omitir IA): ",
        "pt": "Digite OPENAI_API_KEY (vazio para pular IA): ",
    },
    "ai_skip": {
        "en": "Skipping AI features.", "ja": "AI機能をスキップします。",
        "zh": "跳过 AI 功能。", "ko": "AI 기능을 건너뜁니다.",
        "de": "KI-Funktionen werden übersprungen.", "es": "Omitiendo funciones de IA.",
        "pt": "Pulando recursos de IA.",
    },
    "ai_key_saved": {
        "en": "API key saved.", "ja": "APIキーを保存しました。",
        "zh": "API 密钥已保存。", "ko": "API 키가 저장되었습니다.",
        "de": "API-Schlüssel gespeichert.", "es": "Clave de API guardada.", "pt": "Chave de API salva.",
    },
    # Next steps
    "next_steps_heading": {
        "en": "Next steps:", "ja": "次にやること:",
        "zh": "下一步:", "ko": "다음 단계:",
        "de": "Nächste Schritte:", "es": "Próximos pasos:", "pt": "Próximas etapas:",
    },
    "next_step_docker": {
        "en": "Replace docker-compose.yml with the hardened version",
        "ja": "docker-compose.yml を既存構成と差し替える",
        "zh": "将 docker-compose.yml 替换为加固版本",
        "ko": "docker-compose.yml을 강화된 버전으로 교체",
        "de": "docker-compose.yml durch die gehärtete Version ersetzen",
        "es": "Reemplaza docker-compose.yml con la versión endurecida",
        "pt": "Substitua docker-compose.yml pela versão reforçada",
    },
    "next_step_tailscale": {
        "en": "Apply Tailscale ACL in the admin console",
        "ja": "Tailscale ACLを管理コンソールへ適用する",
        "zh": "在管理控制台中应用 Tailscale ACL",
        "ko": "관리 콘솔에서 Tailscale ACL 적용",
        "de": "Tailscale ACL in der Verwaltungskonsole anwenden",
        "es": "Aplica el ACL de Tailscale en la consola de administración",
        "pt": "Aplique o ACL do Tailscale no console de administração",
    },
    "next_step_iptables": {
        "en": "Run: sudo bash output/iptables-setup.sh",
        "ja": "sudo bash output/iptables-setup.sh を実行する",
        "zh": "运行: sudo bash output/iptables-setup.sh",
        "ko": "실행: sudo bash output/iptables-setup.sh",
        "de": "Ausführen: sudo bash output/iptables-setup.sh",
        "es": "Ejecuta: sudo bash output/iptables-setup.sh",
        "pt": "Execute: sudo bash output/iptables-setup.sh",
    },
    "next_step_config": {
        "en": "Place output/config.yaml in OpenClaw's config directory",
        "ja": "output/config.yaml をOpenClaw設定ディレクトリへ配置する",
        "zh": "将 output/config.yaml 放置到 OpenClaw 配置目录",
        "ko": "output/config.yaml을 OpenClaw 설정 디렉토리에 배치",
        "de": "output/config.yaml in OpenClaw's Konfigurationsverzeichnis platzieren",
        "es": "Coloca output/config.yaml en el directorio de configuración de OpenClaw",
        "pt": "Coloque output/config.yaml no diretório de configuração do OpenClaw",
    },
    "next_step_infisical": {
        "en": "Run: docker compose -f output/infisical-compose.yml up -d",
        "ja": "docker compose -f output/infisical-compose.yml up -d を実行する",
        "zh": "运行: docker compose -f output/infisical-compose.yml up -d",
        "ko": "실행: docker compose -f output/infisical-compose.yml up -d",
        "de": "Ausführen: docker compose -f output/infisical-compose.yml up -d",
        "es": "Ejecuta: docker compose -f output/infisical-compose.yml up -d",
        "pt": "Execute: docker compose -f output/infisical-compose.yml up -d",
    },
    "next_step_falco": {
        "en": "Deploy Falco rules and restart Falco",
        "ja": "Falcoルールを配置してFalcoを再起動する",
        "zh": "部署 Falco 规则并重启 Falco",
        "ko": "Falco 규칙을 배포하고 Falco 재시작",
        "de": "Falco-Regeln deployen und Falco neustarten",
        "es": "Despliega las reglas de Falco y reinicia Falco",
        "pt": "Implante as regras do Falco e reinicie o Falco",
    },
    "next_step_guide": {
        "en": "Follow SETUP_GUIDE.md step by step",
        "ja": "SETUP_GUIDE.md を見ながら1つずつ適用する",
        "zh": "按照 SETUP_GUIDE.md 逐步操作",
        "ko": "SETUP_GUIDE.md를 참고하여 단계별로 적용",
        "de": "SETUP_GUIDE.md Schritt für Schritt folgen",
        "es": "Sigue SETUP_GUIDE.md paso a paso",
        "pt": "Siga o SETUP_GUIDE.md passo a passo",
    },
    # Terminal mode
    "detecting": {
        "en": "[Detecting environment...]", "ja": "[環境を自動検出中...]",
        "zh": "[正在自动检测环境...]", "ko": "[환경 자동 감지 중...]",
        "de": "[Umgebung wird erkannt...]", "es": "[Detectando entorno automáticamente...]",
        "pt": "[Detectando ambiente automaticamente...]",
    },
    "quit_done": {
        "en": "Quit.", "ja": "終了しました。", "zh": "已退出。",
        "ko": "종료되었습니다.", "de": "Beendet.", "es": "Salida.", "pt": "Encerrado.",
    },
    "gen_done": {
        "en": "[✓] Generation complete", "ja": "[✓] 生成完了", "zh": "[✓] 生成完成",
        "ko": "[✓] 생성 완료", "de": "[✓] Generierung abgeschlossen",
        "es": "[✓] Generación completa", "pt": "[✓] Geração concluída",
    },
    # Report / Chat
    "report_opened": {
        "en": "GitHub Issue opened in browser. Review and submit.",
        "ja": "ブラウザでGitHub Issueが開きました。内容を確認して送信してください。",
        "zh": "已在浏览器中打开 GitHub Issue。请确认内容后提交。",
        "ko": "브라우저에서 GitHub Issue가 열렸습니다. 내용을 확인하고 제출하세요.",
        "de": "GitHub-Issue im Browser geöffnet. Bitte prüfen und absenden.",
        "es": "Se abrió un Issue de GitHub en el navegador. Revisa y envía.",
        "pt": "Issue do GitHub aberto no navegador. Revise e envie.",
    },
    "api_key_missing": {
        "en": "OpenAI API key not set. Set OPENAI_API_KEY to use AI features.",
        "ja": "OpenAI APIキーが未設定です。AI機能を使う場合は OPENAI_API_KEY を設定してください。",
        "zh": "未设置 OpenAI API 密钥。使用 AI 功能请设置 OPENAI_API_KEY。",
        "ko": "OpenAI API 키가 설정되지 않았습니다. AI 기능을 사용하려면 OPENAI_API_KEY를 설정하세요.",
        "de": "OpenAI-API-Schlüssel nicht gesetzt. Bitte OPENAI_API_KEY setzen.",
        "es": "Clave de API de OpenAI no configurada. Configura OPENAI_API_KEY.",
        "pt": "Chave de API da OpenAI não configurada. Configure OPENAI_API_KEY.",
    },
    "chat_failed": {
        "en": "Failed to get AI response: {exc}", "ja": "AI応答の取得に失敗しました: {exc}",
        "zh": "获取 AI 回复失败: {exc}", "ko": "AI 응답 가져오기 실패: {exc}",
        "de": "KI-Antwort konnte nicht abgerufen werden: {exc}",
        "es": "Error al obtener respuesta de IA: {exc}",
        "pt": "Falha ao obter resposta de IA: {exc}",
    },
    "sha256_not_found": {
        "en": "SHA256 value not found", "ja": "SHA256値が見つかりません",
        "zh": "未找到 SHA256 值", "ko": "SHA256 값을 찾을 수 없습니다",
        "de": "SHA256-Wert nicht gefunden", "es": "Valor SHA256 no encontrado",
        "pt": "Valor SHA256 não encontrado",
    },
    # Recommend layer reasons
    "reason_l1_installed": {
        "en": "Tailscale detected. ACL + traffic control is active.",
        "ja": "Tailscale検出済み。ACL + 通信制御が有効です。",
        "zh": "检测到 Tailscale。ACL + 流量控制已激活。",
        "ko": "Tailscale 감지됨. ACL + 트래픽 제어가 활성화됩니다.",
        "de": "Tailscale erkannt. ACL + Verkehrssteuerung aktiv.",
        "es": "Tailscale detectado. ACL + control de tráfico activo.",
        "pt": "Tailscale detectado. ACL + controle de tráfego ativo.",
    },
    "reason_l1_missing": {
        "en": "Tailscale not detected. Can be enabled after installation.",
        "ja": "Tailscale未検出。導入後に有効化できます。",
        "zh": "未检测到 Tailscale。安装后可启用。",
        "ko": "Tailscale 미감지. 설치 후 활성화 가능합니다.",
        "de": "Tailscale nicht erkannt. Nach Installation aktivierbar.",
        "es": "Tailscale no detectado. Se puede habilitar tras la instalación.",
        "pt": "Tailscale não detectado. Pode ser ativado após a instalação.",
    },
    "reason_l1_mac": {
        "en": " On macOS, iptables is Linux-only. Tailscale ACL only.",
        "ja": " macOSではiptablesはLinux専用です。Tailscale ACLのみ適用できます。",
        "zh": " 在 macOS 上，iptables 仅适用于 Linux。仅应用 Tailscale ACL。",
        "ko": " macOS에서는 iptables가 Linux 전용입니다. Tailscale ACL만 적용됩니다.",
        "de": " Auf macOS ist iptables nur für Linux. Nur Tailscale ACL anwendbar.",
        "es": " En macOS, iptables es solo para Linux. Solo se aplica Tailscale ACL.",
        "pt": " No macOS, iptables é apenas para Linux. Somente Tailscale ACL aplicável.",
    },
    "reason_l2_installed": {
        "en": "Docker detected. Hardening is recommended.",
        "ja": "Docker検出済み。ハードニング適用を推奨します。",
        "zh": "检测到 Docker。建议应用加固配置。",
        "ko": "Docker 감지됨. 강화 적용을 권장합니다.",
        "de": "Docker erkannt. Hardening wird empfohlen.",
        "es": "Docker detectado. Se recomienda aplicar hardening.",
        "pt": "Docker detectado. Hardening é recomendado.",
    },
    "reason_l2_missing": {
        "en": "Docker not detected. Can be enabled after installation.",
        "ja": "Docker未検出。導入後に有効化できます。",
        "zh": "未检测到 Docker。安装后可启用。",
        "ko": "Docker 미감지. 설치 후 활성화 가능합니다.",
        "de": "Docker nicht erkannt. Nach Installation aktivierbar.",
        "es": "Docker no detectado. Se puede habilitar tras la instalación.",
        "pt": "Docker não detectado. Pode ser ativado após a instalação.",
    },
    "reason_l3": {
        "en": "Auth layer is essential.", "ja": "認証レイヤーは必須です。",
        "zh": "认证层是必需的。", "ko": "인증 레이어는 필수입니다.",
        "de": "Authentifizierungsschicht ist unerlässlich.",
        "es": "La capa de autenticación es esencial.",
        "pt": "A camada de autenticação é essencial.",
    },
    "reason_l4_16gb": {
        "en": "Enough RAM. Suitable for Infisical.",
        "ja": "メモリ余裕あり。Infisical導入に適しています。",
        "zh": "内存充足。适合部署 Infisical。",
        "ko": "메모리 여유 있음. Infisical 도입에 적합합니다.",
        "de": "Genug RAM. Geeignet für Infisical.",
        "es": "RAM suficiente. Adecuado para Infisical.",
        "pt": "RAM suficiente. Adequado para Infisical.",
    },
    "reason_l4_8gb": {
        "en": "Works on 8GB+ but needs extra setup.",
        "ja": "8GB以上で動作可能ですが追加セットアップが必要です。",
        "zh": "8GB 以上可以运行，但需要额外设置。",
        "ko": "8GB 이상에서 작동 가능하지만 추가 설정이 필요합니다.",
        "de": "Läuft mit 8GB+, erfordert aber zusätzliche Einrichtung.",
        "es": "Funciona con 8GB+ pero requiere configuración adicional.",
        "pt": "Funciona com 8GB+ mas precisa de configuração extra.",
    },
    "reason_l4_low": {
        "en": "Insufficient RAM (<4GB). Not recommended.",
        "ja": "メモリ不足（4GB未満）のため非推奨です。",
        "zh": "内存不足（小于 4GB），不推荐使用。", "ko": "메모리 부족 (4GB 미만). 비권장입니다.",
        "de": "Unzureichender RAM (<4GB). Nicht empfohlen.",
        "es": "RAM insuficiente (<4GB). No recomendado.", "pt": "RAM insuficiente (<4GB). Não recomendado.",
    },
    "reason_l4_medium": {
        "en": "Add later if needed.", "ja": "必要に応じて後から追加してください。",
        "zh": "如有需要，可稍后添加。", "ko": "필요 시 나중에 추가할 수 있습니다.",
        "de": "Bei Bedarf später hinzufügen.", "es": "Agregar más tarde si es necesario.",
        "pt": "Adicionar mais tarde se necessário.",
    },
    "reason_l5": {
        "en": "Incurs additional API cost. Optional.",
        "ja": "追加APIコストが発生するため任意です。",
        "zh": "会产生额外 API 费用，为可选项。", "ko": "추가 API 비용이 발생합니다. 선택 사항입니다.",
        "de": "Verursacht zusätzliche API-Kosten. Optional.",
        "es": "Genera costos adicionales de API. Opcional.",
        "pt": "Incorre em custo adicional de API. Opcional.",
    },
    "reason_l6": {
        "en": "Least privilege layer is essential.", "ja": "最小権限レイヤーは必須です。",
        "zh": "最小权限层是必需的。", "ko": "최소 권한 레이어는 필수입니다.",
        "de": "Minimale-Rechte-Schicht ist unerlässlich.",
        "es": "La capa de mínimos privilegios es esencial.",
        "pt": "A camada de mínimo privilégio é essencial.",
    },
    "reason_l7_mac": {
        "en": "Falco is Linux-only. Not available on macOS.",
        "ja": "FalcoはLinux専用のためmacOSでは非対応です。",
        "zh": "Falco 仅支持 Linux，macOS 不可用。",
        "ko": "Falco는 Linux 전용이므로 macOS에서 사용 불가합니다.",
        "de": "Falco ist nur für Linux. Nicht auf macOS verfügbar.",
        "es": "Falco es solo para Linux. No disponible en macOS.",
        "pt": "Falco é apenas para Linux. Não disponível no macOS.",
    },
    "reason_l7_high": {
        "en": "Monitoring is recommended.", "ja": "監視運用を推奨します。",
        "zh": "建议启用监控。", "ko": "모니터링 운영을 권장합니다.",
        "de": "Überwachung wird empfohlen.", "es": "Se recomienda monitoreo.",
        "pt": "Monitoramento é recomendado.",
    },
    "reason_l7_medium": {
        "en": "Viable but monitor load. Optional.",
        "ja": "運用可能ですが負荷を見ながら導入してください。",
        "zh": "可以使用，但请注意负载。可选。",
        "ko": "사용 가능하지만 부하를 확인하며 도입하세요. 선택 사항.",
        "de": "Möglich, aber Last beachten. Optional.",
        "es": "Viable pero vigilar la carga. Opcional.",
        "pt": "Viável mas monitore a carga. Opcional.",
    },
    "reason_ait_mac": {
        "en": "On macOS, only partial functionality (no iptables).",
        "ja": "macOSではiptables除外で一部機能のみ利用可能です。",
        "zh": "在 macOS 上，仅部分功能可用（无 iptables）。",
        "ko": "macOS에서는 일부 기능만 사용 가능합니다 (iptables 제외).",
        "de": "Auf macOS nur eingeschränkte Funktionalität (kein iptables).",
        "es": "En macOS, solo funcionalidad parcial (sin iptables).",
        "pt": "No macOS, apenas funcionalidade parcial (sem iptables).",
    },
    "reason_aim": {
        "en": "Requires OpenAI API key.", "ja": "OpenAI APIキーが必要です。",
        "zh": "需要 OpenAI API 密钥。", "ko": "OpenAI API 키가 필요합니다.",
        "de": "OpenAI-API-Schlüssel erforderlich.", "es": "Requiere clave de API de OpenAI.",
        "pt": "Requer chave de API da OpenAI.",
    },
}


def _detect_lang() -> str:
    """Detect UI language from environment."""
    forced = os.environ.get("MOAT_LANG", "")
    if forced:
        code = forced[:2].lower()
        if code in STRINGS.get("env_heading", {}):
            return code
    for var in ("LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES"):
        val = os.environ.get(var, "")
        if val:
            code = val[:2].lower()
            if code in STRINGS.get("env_heading", {}):
                return code
    return "en"


def T(key: str, **kwargs: Any) -> str:
    """Return translated string for *key* in CURRENT_LANG."""
    lang_map = STRINGS.get(key)
    if lang_map is None:
        return key
    text = lang_map.get(CURRENT_LANG) or lang_map.get("en") or key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return text


LAYER_ORDER = [
    ("layer1", "Layer 1", "title_layer1", "tailscale-acl.json, iptables-setup.sh"),
    ("layer2", "Layer 2", "title_layer2", "docker-compose.yml"),
    ("layer3", "Layer 3", "title_layer3", "config.yaml (auth section)"),
    ("layer4", "Layer 4", "title_layer4", "infisical-compose.yml"),
    ("layer5", "Layer 5", "title_layer5", "config.yaml (plugins/prompt section)"),
    ("layer6", "Layer 6", "title_layer6", "config.yaml (tools section)"),
    ("layer7", "Layer 7", "title_layer7", "falco_rules.local.yaml, alerts.yaml"),
    ("ai-m", "AI-M", "title_ai-m", "config.yaml (ai_mediation section)"),
    ("ai-t", "AI-T", "title_ai-t", "config.yaml (threat_intelligence section)"),
]

LAYER1_ACL_JSON = textwrap.dedent(
    """
    {
      "acls": [
        {
          "action": "accept",
          "src": ["tag:admin-device"],
          "dst": ["tag:openclaw-instance:22", "tag:openclaw-instance:443"]
        },
        {
          "action": "accept",
          "src": ["tag:admin-device"],
          "dst": ["tag:infisical-server:443"]
        },
        {
          "action": "accept",
          "src": ["tag:openclaw-instance"],
          "dst": ["tag:infisical-server:443"]
        }
      ],
      "tagOwners": {
        "tag:openclaw-instance": ["your-admin-email@example.com"],
        "tag:infisical-server":  ["your-admin-email@example.com"],
        "tag:admin-device":      ["your-admin-email@example.com"]
      },
      "autoApprovers": {}
    }
    """
).strip() + "\n"

LAYER1_IPTABLES_SH = textwrap.dedent(
    """
    #!/bin/bash
    # OpenClaw アウトバウンド通信ホワイトリスト制御
    # Exit Nodeを無効にしてもC2通信は防止できないため、iptablesで制御する

    set -e

    echo "[*] iptablesアウトバウンドルールを設定中..."

    # 既存OUTPUTルールをフラッシュ
    iptables -F OUTPUT

    # ループバック・Tailscale内部は許可
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tailscale0 -j ACCEPT

    # 確立済み通信の応答は許可
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # DNS（名前解決）
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Tailscale制御サーバー
    iptables -A OUTPUT -p tcp --dport 443 -d controlplane.tailscale.com -j ACCEPT

    # Infisicalサーバー（YOUR_INFISICAL_IPを実際のIPに変更）
    iptables -A OUTPUT -p tcp --dport 443 -d YOUR_INFISICAL_IP -j ACCEPT

    # それ以外のアウトバウンドをDROP
    iptables -A OUTPUT -j DROP

    # 永続化
    apt install -y iptables-persistent
    netfilter-persistent save

    echo "[✓] iptablesルール設定完了"
    echo "[!] YOUR_INFISICAL_IP を実際のInfisicalサーバーIPに変更してください"
    """
).strip() + "\n"

LAYER4_INFISICAL_COMPOSE = textwrap.dedent(
    """
    version: '3.9'

    services:
      infisical:
        image: infisical/infisical:latest
        restart: unless-stopped
        ports:
          - "443:443"
        volumes:
          - ./infisical-data:/app/data
        environment:
          - POSTGRES_URL=postgres://infisical:CHANGE_THIS_PASSWORD@postgres:5432/infisical
          - ENCRYPTION_KEY=CHANGE_THIS_TO_RANDOM_256BIT_KEY
          - AUTH_SECRET=CHANGE_THIS_TO_RANDOM_SECRET
        depends_on:
          - postgres

      postgres:
        image: postgres:15-alpine
        restart: unless-stopped
        environment:
          - POSTGRES_USER=infisical
          - POSTGRES_PASSWORD=CHANGE_THIS_PASSWORD
          - POSTGRES_DB=infisical
        volumes:
          - ./postgres-data:/var/lib/postgresql/data
    """
).strip() + "\n"

LAYER7_FALCO_RULES = textwrap.dedent(
    """
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
    """
).strip() + "\n"

LAYER7_ALERTS = textwrap.dedent(
    """
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

          - alert: ShellInContainer
            expr: increase(falco_events_total{rule=~"Shell in OpenClaw Container"}[1m]) > 0
            for: 0m
            labels:
              severity: critical
            annotations:
              summary: "Shell spawned in OpenClaw container on {{ $labels.instance }}"
    """
).strip() + "\n"

APPROVAL_LEVEL_MAP = {
    "none": "none",
    "high_risk_only": "high_risk_only",
    "all": "all",
}

APPROVAL_YAML_TEMPLATE = textwrap.dedent(
    """
    approval:
      level: "{level}"   # "none" / "high_risk_only" / "all"
      # none           = 全自動（承認なし）
      # high_risk_only = HIGH/CRITICALのみ承認（推奨・デフォルト）
      # all            = 全操作承認
    """
)

LAYER3_CONFIG = textwrap.dedent(
    """
    # === Layer 3: 認証・アクセス制御 ===
    auth:
      mode: token
      token: "{{ INFISICAL_TOKEN_MOAT_AUTH }}"
      requireMention: true
      pairing:
        allowlist:
          - "user_id:YOUR_TELEGRAM_USER_ID"
      session:
        dmScope: "per-channel-peer"
        dmPolicy: "pairing"
    """
).strip()

LAYER5_CONFIG = textwrap.dedent(
    """
    # === Layer 5: スキル・プロンプト防御 ===
    plugins:
      allow:
        - git_repo: "https://github.com/your-org/openclaw-safe-skills.git"
          ref: "v1.0.0"
      deny:
        - source: clawhub
        - source: unknown

    prompt:
      guard:
        enabled: true
        model: "gpt-4o"
        block_threshold: 0.8
      sanitize:
        remove_patterns:
          - "ignore previous instructions"
          - "forget all rules"
          - "system prompt override"
    """
).strip()

LAYER6_CONFIG = textwrap.dedent(
    """
    # === Layer 6: 実行時最小権限 ===
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
        allowed_domains:
          - "api.openai.com"
          - "api.anthropic.com"
          - "api.infisical.com"
          - "github.com"
          - "raw.githubusercontent.com"
          - "www.virustotal.com"
        allowed_ports:
          - 443
          - 53    # DNS

      workspaceAccess: "ro"
    """
).strip()

AIM_CONFIG = textwrap.dedent(
    """
    # === AI仲裁エージェント ===
    ai_mediation:
      enabled: true
      report_mode: "clipboard"   # "github_issue" or "clipboard"
      github_token: "{{ INFISICAL_GITHUB_TOKEN }}"
      ai_api:
        provider: "openai"
        model: "gpt-4o"
        api_key: "{{ INFISICAL_OPENAI_API_KEY }}"
      anonymize: true
      require_approval: true
      notification:
        telegram: true
      whitelist:
        - "api.openai.com:443"
        - "api.github.com:443"
    """
).strip()

AIT_CONFIG = textwrap.dedent(
    """
    # === 脅威インテリジェンス・ワクチン ===
    threat_intelligence:
      enabled: true
      sources:
        - nvd_cve
        - falco_community
      update_schedule: "0 3 * * *"
      ai_api:
        provider: "openai"
        model: "gpt-4o"
        api_key: "{{ INFISICAL_OPENAI_API_KEY }}"
      require_approval: true
      notification:
        telegram: true
      whitelist:
        - "services.nvd.nist.gov:443"
        - "raw.githubusercontent.com:443"
        - "api.openai.com:443"
    """
).strip()
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Moat — AI Security</title>
  <style>
    /* ── Design tokens ─────────────────────────────────────── */
    :root {
      --bg:          #0b0f1a;
      --bg-card:     #101626;
      --bg-raised:   #151d30;
      --bg-hover:    #1a2438;
      --border:      #1f2e48;
      --border-hi:   #2d4470;
      --text:        #dde6f5;
      --text-2:      #7a90b8;
      --text-3:      #3e5278;
      --accent:      #3b82f6;
      --accent-2:    #60a5fa;
      --accent-glow: rgba(59,130,246,.14);
      --green:       #10b981;
      --green-dim:   rgba(16,185,129,.14);
      --amber:       #f59e0b;
      --amber-dim:   rgba(245,158,11,.14);
      --red:         #ef4444;
      --red-dim:     rgba(239,68,68,.14);
      --orange:      #f97316;
      --orange-dim:  rgba(249,115,22,.14);
      --yellow:      #eab308;
      --yellow-dim:  rgba(234,179,8,.14);
      --blue:        #3b82f6;
      --blue-dim:    rgba(59,130,246,.14);
      --radius:      8px;
      --radius-lg:   12px;
      --radius-xl:   16px;
      --mono:        ui-monospace,'Cascadia Code','SF Mono',Consolas,monospace;
    }
    *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
    html { scroll-behavior: smooth; }
    body {
      font-family: 'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }
    a { color: var(--accent-2); text-decoration: none; }
    a:hover { text-decoration: underline; }
    button { cursor: pointer; font-family: inherit; }

    /* ── Header ─────────────────────────────────────────────── */
    .site-header {
      position: sticky; top: 0; z-index: 200;
      background: rgba(11,15,26,.92);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 12px 20px;
      display: flex; align-items: center; gap: 14px;
    }
    .logo-mark {
      width: 36px; height: 36px; border-radius: 9px;
      background: linear-gradient(135deg,#2563eb,#06b6d4);
      display: flex; align-items: center; justify-content: center;
      font-size: 20px; flex-shrink: 0;
      box-shadow: 0 0 14px rgba(6,182,212,.3);
    }
    .site-header h1 { font-size: 17px; font-weight: 700; letter-spacing: -.3px; }
    .site-header p  { font-size: 11px; color: var(--text-2); margin-top: 1px; }

    /* ── Layout ──────────────────────────────────────────────── */
    .page { max-width: 860px; margin: 0 auto; padding: 32px 16px 96px; }
    .section-label {
      font-size: 10px; font-weight: 700; letter-spacing: .1em;
      text-transform: uppercase; color: var(--text-3);
      margin-bottom: 10px;
    }
    .mt-28 { margin-top: 28px; }

    /* ── Card base ───────────────────────────────────────────── */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
    }

    /* ── Skeleton loader ─────────────────────────────────────── */
    .skel {
      background: linear-gradient(90deg,var(--bg-card) 25%,var(--bg-raised) 50%,var(--bg-card) 75%);
      background-size: 200% 100%;
      animation: shimmer 1.4s infinite;
      border-radius: var(--radius);
    }
    @keyframes shimmer { to { background-position: -200% 0; } }

    /* ── Pulse dot ───────────────────────────────────────────── */
    .dot-pulse {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 6px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 50% { opacity: .4; } }

    /* ── Env panel ───────────────────────────────────────────── */
    .env-panel { padding: 18px 20px; margin-bottom: 28px; }
    .env-panel-head {
      display: flex; align-items: center; gap: 9px; margin-bottom: 14px;
    }
    .env-panel-head h2 { font-size: 13px; font-weight: 600; }
    .env-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 8px;
    }
    .env-item {
      display: flex; align-items: center; gap: 9px;
      padding: 9px 11px;
      background: rgba(255,255,255,.03);
      border-radius: var(--radius);
    }
    .env-item-icon { font-size: 15px; flex-shrink: 0; }
    .env-item-label { font-size: 10px; color: var(--text-3); margin-bottom: 1px; }
    .env-item-val   { font-family: var(--mono); font-size: 11px; color: var(--text); }
    .ok  { color: var(--green) !important; }
    .dim { color: var(--text-2) !important; }

    /* ── Layer cards ─────────────────────────────────────────── */
    .layers-grid { display: flex; flex-direction: column; gap: 10px; margin-bottom: 28px; }
    .layer-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 14px 18px;
      display: flex; align-items: center; gap: 14px;
      transition: border-color .2s, background .2s;
    }
    .layer-card:hover   { border-color: var(--border-hi); background: var(--bg-hover); }
    .layer-card.is-on   { border-color: rgba(59,130,246,.35); background: rgba(59,130,246,.04); }
    .layer-num {
      font-family: var(--mono); font-size: 10px; font-weight: 700;
      color: var(--text-3); min-width: 28px; text-align: center;
    }
    .layer-body { flex: 1; min-width: 0; }
    .layer-name-row {
      display: flex; align-items: center; gap: 7px;
      flex-wrap: wrap; margin-bottom: 3px;
    }
    .layer-name  { font-size: 13px; font-weight: 600; }
    .layer-desc  { font-size: 12px; color: var(--text-2); margin-bottom: 3px; }
    .layer-files { font-family: var(--mono); font-size: 11px; color: var(--text-3); }

    /* Badges */
    .badge {
      font-size: 10px; font-weight: 700; padding: 2px 8px;
      border-radius: 20px; white-space: nowrap;
    }
    .badge-rec  { background: var(--green-dim);  color: var(--green);  border: 1px solid rgba(16,185,129,.3); }
    .badge-opt  { background: var(--amber-dim);  color: var(--amber);  border: 1px solid rgba(245,158,11,.3); }
    .badge-skip { background: var(--red-dim);    color: var(--red);    border: 1px solid rgba(239,68,68,.3); }

    /* Toggle */
    .toggle-wrap { display: flex; flex-direction: column; align-items: center; gap: 3px; flex-shrink: 0; }
    .toggle { position: relative; width: 44px; height: 24px; }
    .toggle input { opacity: 0; width: 0; height: 0; position: absolute; }
    .t-track {
      position: absolute; inset: 0;
      background: #1e2d4a;
      border-radius: 24px;
      transition: background .25s;
    }
    .t-thumb {
      position: absolute; top: 3px; left: 3px;
      width: 18px; height: 18px;
      background: #5a7099;
      border-radius: 50%;
      transition: transform .25s cubic-bezier(.4,0,.2,1), background .25s;
      box-shadow: 0 1px 4px rgba(0,0,0,.5);
    }
    .toggle input:checked ~ .t-track { background: var(--green); }
    .toggle input:checked ~ .t-thumb { transform: translateX(20px); background: #fff; }
    .toggle input:focus-visible ~ .t-track { outline: 2px solid var(--accent); outline-offset: 2px; }
    .t-label { font-size: 10px; font-weight: 700; color: var(--text-3); }

    /* ── Approval level ──────────────────────────────────────── */
    .approval-card { padding: 18px 20px; margin-bottom: 28px; }
    .approval-card h3 { font-size: 13px; font-weight: 600; margin-bottom: 3px; }
    .approval-card .sub { font-size: 12px; color: var(--text-2); margin-bottom: 14px; }
    .approval-list { display: flex; flex-direction: column; gap: 7px; }
    .approval-opt {
      display: flex; align-items: center; gap: 12px;
      padding: 11px 14px;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      cursor: pointer;
      transition: border-color .2s, background .2s;
      user-select: none;
    }
    .approval-opt:hover  { border-color: var(--border-hi); background: rgba(255,255,255,.02); }
    .approval-opt.chosen { border-color: var(--accent); background: var(--accent-glow); }
    .approval-opt input[type="radio"] { accent-color: var(--accent); width: 15px; height: 15px; flex-shrink: 0; }
    .approval-opt-text strong { font-size: 13px; display: block; margin-bottom: 1px; }
    .approval-opt-text span   { font-size: 11px; color: var(--text-2); }
    .rec-pill {
      margin-left: auto; font-size: 10px; padding: 2px 8px;
      border-radius: 20px;
      background: rgba(59,130,246,.15);
      color: var(--accent-2);
      border: 1px solid rgba(59,130,246,.3);
    }

    /* ── Generate button ─────────────────────────────────────── */
    .gen-btn {
      width: 100%; padding: 15px;
      background: linear-gradient(135deg,#2563eb,#0891b2);
      color: #fff; border: none; border-radius: var(--radius-lg);
      font-size: 15px; font-weight: 700; letter-spacing: .03em;
      box-shadow: 0 4px 24px rgba(37,99,235,.35);
      transition: opacity .2s, transform .1s;
      margin-bottom: 36px;
    }
    .gen-btn:hover { opacity: .9; transform: translateY(-1px); }
    .gen-btn:active { transform: translateY(0); }
    .gen-btn:disabled { opacity: .5; cursor: not-allowed; transform: none; }

    /* ── Alert cards ─────────────────────────────────────────── */
    .alerts-area { display: flex; flex-direction: column; gap: 12px; margin-bottom: 28px; }
    .alert-card {
      border-radius: var(--radius-lg);
      border: 1px solid;
      overflow: hidden;
    }
    .alert-card[data-risk="CRITICAL"] { border-color: #b91c1c; background: linear-gradient(to right,rgba(185,28,28,.1),rgba(185,28,28,.03)); }
    .alert-card[data-risk="HIGH"]     { border-color: #c2410c; background: linear-gradient(to right,rgba(194,65,12,.1),rgba(194,65,12,.03)); }
    .alert-card[data-risk="MEDIUM"]   { border-color: #a16207; background: linear-gradient(to right,rgba(161,98,7,.1),rgba(161,98,7,.03)); }
    .alert-card[data-risk="LOW"]      { border-color: #1d4ed8; background: linear-gradient(to right,rgba(29,78,216,.1),rgba(29,78,216,.03)); }
    /* risk strip on left */
    .alert-card[data-risk="CRITICAL"]::before { content:''; display:block; position:absolute; left:0; top:0; width:3px; height:100%; background:#ef4444; border-radius:12px 0 0 12px; }
    .alert-card { position: relative; }

    .alert-main { padding: 15px 18px; }
    .alert-title-row {
      display: flex; align-items: center; gap: 9px; margin-bottom: 7px;
    }
    .alert-icon { font-size: 18px; }
    .alert-title { font-size: 14px; font-weight: 700; flex: 1; }
    .alert-card[data-risk="CRITICAL"] .alert-title { color: #fca5a5; }
    .alert-card[data-risk="HIGH"]     .alert-title { color: #fdba74; }
    .alert-card[data-risk="MEDIUM"]   .alert-title { color: #fde68a; }
    .alert-card[data-risk="LOW"]      .alert-title { color: #93c5fd; }
    .risk-badge {
      font-size: 10px; font-weight: 800; padding: 2px 8px;
      border-radius: 20px; letter-spacing: .05em;
    }
    .alert-card[data-risk="CRITICAL"] .risk-badge { background: rgba(239,68,68,.2); color: #fca5a5; border: 1px solid rgba(239,68,68,.4); }
    .alert-card[data-risk="HIGH"]     .risk-badge { background: rgba(249,115,22,.2); color: #fdba74; border: 1px solid rgba(249,115,22,.4); }
    .alert-card[data-risk="MEDIUM"]   .risk-badge { background: rgba(234,179,8,.2);  color: #fde68a; border: 1px solid rgba(234,179,8,.4); }
    .alert-card[data-risk="LOW"]      .risk-badge { background: rgba(59,130,246,.2); color: #93c5fd; border: 1px solid rgba(59,130,246,.4); }
    .toggle-detail-btn {
      background: none; border: 1px solid rgba(255,255,255,.12);
      color: var(--text-2); padding: 4px 10px;
      border-radius: 6px; font-size: 11px;
      transition: background .2s;
    }
    .toggle-detail-btn:hover { background: rgba(255,255,255,.07); }
    .alert-body { font-size: 13px; color: var(--text-2); margin-bottom: 13px; line-height: 1.6; }
    .alert-actions { display: flex; gap: 7px; flex-wrap: wrap; }
    .a-btn {
      padding: 7px 13px; border-radius: 6px;
      font-size: 12px; font-weight: 600; border: none;
      transition: opacity .2s, transform .1s;
    }
    .a-btn:hover { opacity: .82; transform: translateY(-1px); }
    .a-btn-allow  { background: var(--green); color: #fff; }
    .a-btn-block  { background: rgba(255,255,255,.09); color: var(--text); border: 1px solid rgba(255,255,255,.14) !important; }
    .a-btn-ai     { background: none; color: var(--accent-2); border: 1px solid rgba(96,165,250,.4) !important; }
    .a-btn-ai:hover { background: var(--accent-glow); }
    .a-btn-report {
      background: none;
      color: var(--text-2);
      border: 1px dashed rgba(255,255,255,.22) !important;
      font-size: 11px;
      padding: 6px 10px;
    }
    .a-btn-report:hover { color: var(--text); border-color: rgba(255,255,255,.35) !important; }

    /* Alert detail panel */
    .alert-detail {
      border-top: 1px solid rgba(255,255,255,.07);
      background: rgba(0,0,0,.22);
      padding: 13px 18px;
      display: none;
    }
    .alert-detail.open { display: block; }
    .detail-label {
      font-size: 10px; font-weight: 700; letter-spacing: .09em;
      text-transform: uppercase; color: var(--text-3); margin-bottom: 9px;
    }
    .detail-kv {
      display: grid; grid-template-columns: auto 1fr;
      gap: 4px 14px; font-family: var(--mono); font-size: 12px;
    }
    .dk { color: var(--text-3); }
    .dv { color: var(--text); }
    .copy-btn {
      margin-top: 11px; float: right;
      background: none; border: 1px solid rgba(255,255,255,.12);
      color: var(--text-2); padding: 4px 11px;
      border-radius: 6px; font-size: 11px;
      transition: background .2s;
    }
    .copy-btn:hover { background: rgba(255,255,255,.07); }

    /* AI Chat panel */
    .ai-chat {
      border-top: 1px solid rgba(255,255,255,.07);
      background: rgba(0,0,0,.28);
      display: none;
    }
    .ai-chat.open { display: block; }
    .chat-head {
      padding: 11px 18px 0;
      display: flex; align-items: center; justify-content: space-between;
    }
    .chat-title { font-size: 12px; font-weight: 600; color: var(--accent-2); }
    .chat-close {
      background: none; border: none; color: var(--text-3);
      font-size: 16px; padding: 0 4px; line-height: 1;
      transition: color .2s;
    }
    .chat-close:hover { color: var(--text); }
    .chat-hint { font-size: 10px; color: var(--text-3); padding: 3px 18px 8px; }
    .chat-messages {
      height: 210px; overflow-y: auto;
      padding: 6px 18px 12px;
      display: flex; flex-direction: column; gap: 9px;
    }
    .chat-messages::-webkit-scrollbar { width: 3px; }
    .chat-messages::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    .bubble {
      max-width: 84%; padding: 8px 12px;
      border-radius: 12px; font-size: 13px; line-height: 1.55;
    }
    .bubble-you {
      background: rgba(59,130,246,.18); color: var(--text);
      align-self: flex-end;
      border: 1px solid rgba(59,130,246,.28);
      border-bottom-right-radius: 3px;
    }
    .bubble-ai {
      background: rgba(255,255,255,.05); color: var(--text-2);
      align-self: flex-start;
      border: 1px solid rgba(255,255,255,.08);
      border-bottom-left-radius: 3px;
    }
    .bubble-ai-name { font-size: 10px; font-weight: 700; color: var(--accent-2); display: block; margin-bottom: 3px; }
    .chat-input-row { display: flex; gap: 7px; padding: 0 18px 15px; }
    .chat-input {
      flex: 1; background: rgba(255,255,255,.05);
      border: 1px solid var(--border); border-radius: 8px;
      color: var(--text); padding: 8px 11px;
      font-size: 13px; font-family: inherit;
    }
    .chat-input:focus { outline: none; border-color: var(--accent); }
    .chat-send {
      background: var(--accent); border: none;
      border-radius: 8px; color: #fff;
      padding: 8px 14px; font-size: 12px; font-weight: 700;
      transition: opacity .2s;
    }
    .chat-send:hover { opacity: .85; }

    /* Typing indicator */
    .typing-dot {
      display: inline-block; width: 6px; height: 6px;
      border-radius: 50%; background: var(--text-3); margin: 0 2px;
      animation: blink 1.2s infinite;
    }
    .typing-dot:nth-child(2) { animation-delay: .2s; }
    .typing-dot:nth-child(3) { animation-delay: .4s; }
    @keyframes blink { 50% { opacity: .15; } }

    /* ── Screen 2: Complete ──────────────────────────────────── */
    #screen-complete { display: none; }
    .complete-hero { text-align: center; padding: 44px 16px 32px; }
    .complete-icon { font-size: 56px; margin-bottom: 14px; }
    .complete-hero h2 { font-size: 22px; font-weight: 700; margin-bottom: 7px; }
    .complete-hero p  { font-size: 13px; color: var(--text-2); }
    .files-card { overflow: hidden; margin-bottom: 22px; }
    .files-head { padding: 13px 18px; border-bottom: 1px solid var(--border); font-size: 13px; font-weight: 600; }
    .file-row {
      display: flex; align-items: center; gap: 11px;
      padding: 11px 18px; border-bottom: 1px solid var(--border);
      transition: background .2s;
    }
    .file-row:last-child { border-bottom: none; }
    .file-row:hover { background: rgba(255,255,255,.02); }
    .file-icon { font-size: 15px; }
    .file-name { font-family: var(--mono); font-size: 12px; flex: 1; }
    .file-layer { font-size: 10px; color: var(--text-3); font-family: var(--mono); }
    .dl-btn {
      padding: 5px 12px;
      background: rgba(59,130,246,.1);
      border: 1px solid rgba(59,130,246,.3);
      border-radius: 6px; color: var(--accent-2);
      font-size: 12px; font-weight: 600; text-decoration: none;
      transition: background .2s;
    }
    .dl-btn:hover { background: rgba(59,130,246,.2); text-decoration: none; }
    .steps-card { padding: 18px 20px; margin-bottom: 22px; }
    .steps-card h3 { font-size: 13px; font-weight: 600; margin-bottom: 14px; }
    .step-row {
      display: flex; gap: 12px;
      padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,.05);
    }
    .step-row:last-child { border-bottom: none; }
    .step-num {
      width: 24px; height: 24px; border-radius: 50%;
      background: var(--accent-glow); border: 1px solid var(--accent);
      color: var(--accent-2); font-size: 11px; font-weight: 800;
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0; margin-top: 1px;
    }
    .step-title { font-size: 13px; font-weight: 600; display: block; margin-bottom: 2px; }
    .step-desc  { font-size: 12px; color: var(--text-2); }
    .step-desc code {
      font-family: var(--mono); background: rgba(255,255,255,.08);
      padding: 1px 5px; border-radius: 4px; font-size: 11px;
    }
    .restart-btn {
      width: 100%; padding: 13px;
      background: none; border: 1px solid var(--border);
      border-radius: var(--radius-lg); color: var(--text-2);
      font-size: 13px;
      transition: border-color .2s, color .2s;
    }
    .restart-btn:hover { border-color: var(--border-hi); color: var(--text); }

    /* ── Spinner ─────────────────────────────────────────────── */
    .spin {
      display: inline-block; width: 14px; height: 14px;
      border: 2px solid rgba(255,255,255,.3);
      border-top-color: #fff; border-radius: 50%;
      animation: rot .55s linear infinite;
      vertical-align: middle; margin-right: 7px;
    }
    @keyframes rot { to { transform: rotate(360deg); } }

    /* ── Footer ──────────────────────────────────────────────── */
    .site-footer {
      text-align: center; padding: 22px;
      font-size: 11px; color: var(--text-3);
      border-top: 1px solid var(--border);
    }
    .site-footer a { color: var(--text-2); }
    .site-footer a:hover { color: var(--text); }

    /* ── Responsive ──────────────────────────────────────────── */
    @media (max-width: 560px) {
      .page { padding: 20px 12px 80px; }
      .layer-card { padding: 11px 13px; gap: 9px; }
      .layer-num { min-width: 22px; }
      .approval-opt { padding: 9px 11px; }
      .gen-btn { font-size: 14px; padding: 13px; }
      .env-grid { grid-template-columns: 1fr 1fr; }
      .alert-actions { gap: 5px; }
      .a-btn { padding: 6px 10px; font-size: 11px; }
    }
    @media (max-width: 360px) {
      .env-grid { grid-template-columns: 1fr; }
    }

    /* ── Utility ─────────────────────────────────────────────── */
    .hidden { display: none !important; }
  </style>
</head>
<body>

<!-- ═══════════════════════════════════════════════════════════
     HEADER
════════════════════════════════════════════════════════════ -->
<header class="site-header">
  <div class="logo-mark" aria-hidden="true">🦞</div>
  <div>
    <h1>Moat</h1>
    <p>AI Security for self-hosted agents</p>
  </div>
</header>

<!-- ═══════════════════════════════════════════════════════════
     SCREEN 1 — MAIN WIZARD
════════════════════════════════════════════════════════════ -->
<div id="screen-main">
<div class="page">

  <!-- ── Live alert area (shown when events occur) ── -->
  <div id="live-alerts" class="alerts-area" style="display:none;"></div>

  <!-- ── Environment panel ── -->
  <div class="section-label">環境検出結果</div>
  <div class="card env-panel" id="env-panel">
    <div class="env-panel-head">
      <div class="dot-pulse" id="env-dot"></div>
      <h2 id="env-title">検出中...</h2>
    </div>
    <div class="env-grid" id="env-grid">
      <div class="skel" style="height:40px;"></div>
      <div class="skel" style="height:40px;"></div>
      <div class="skel" style="height:40px;"></div>
      <div class="skel" style="height:40px;"></div>
    </div>
  </div>

  <!-- ── Layer cards ── -->
  <div class="section-label">セキュリティレイヤー</div>
  <div class="layers-grid" id="layers-grid"><!-- rendered by JS --></div>

  <!-- ── Approval level ── -->
  <div class="section-label mt-28">承認レベル</div>
  <div class="card approval-card">
    <h3>自動処理の範囲</h3>
    <p class="sub">セキュリティイベントをどこまで自動で処理するか選択してください</p>
    <div class="approval-list">
      <label class="approval-opt" data-val="none">
        <input type="radio" name="approval" value="none">
        <div class="approval-opt-text">
          <strong>すべて自動</strong>
          <span>煩わしくない。ただし誤検知リスクあり</span>
        </div>
      </label>
      <label class="approval-opt chosen" data-val="high_risk_only">
        <input type="radio" name="approval" value="high_risk_only" checked>
        <div class="approval-opt-text">
          <strong>高リスクのみ確認</strong>
          <span>CRITICAL / HIGH イベントのみ人間が承認。日常操作は自動</span>
        </div>
        <span class="rec-pill">推奨</span>
      </label>
      <label class="approval-opt" data-val="all">
        <input type="radio" name="approval" value="all">
        <div class="approval-opt-text">
          <strong>すべて確認</strong>
          <span>最も安全。すべての操作に人間の承認が必要</span>
        </div>
      </label>
    </div>
  </div>

  <!-- ── Generate button ── -->
  <button class="gen-btn" id="gen-btn" onclick="generateConfig()">
    設定ファイルを生成する →
  </button>

  <!-- ── Demo: alert card preview ── -->
  <div class="section-label">アラートプレビュー（デモ）</div>
  <div class="alerts-area" id="demo-alerts"><!-- rendered by JS --></div>

</div><!-- /.page -->
<footer class="site-footer">
  <a href="https://github.com/matsulinks/moat" target="_blank" rel="noopener">
    ⭐ GitHub: matsulinks/moat
  </a>
  &nbsp;·&nbsp; Moat v0.1.0
</footer>
</div><!-- /#screen-main -->


<!-- ═══════════════════════════════════════════════════════════
     SCREEN 2 — GENERATION COMPLETE
════════════════════════════════════════════════════════════ -->
<div id="screen-complete">
<div class="page">

  <div class="complete-hero">
    <div class="complete-icon">✅</div>
    <h2>設定ファイルを生成しました</h2>
    <p>以下のファイルをダウンロードして、手順にしたがって適用してください</p>
  </div>

  <div class="section-label">生成されたファイル</div>
  <div class="card files-card" id="files-panel"><!-- rendered by JS --></div>

  <div class="section-label mt-28">次にやること</div>
  <div class="card steps-card">
    <h3>セットアップ手順</h3>
    <div id="steps-list"><!-- rendered by JS --></div>
  </div>

  <button class="restart-btn" onclick="restartWizard()">↩ 最初からやり直す</button>

</div><!-- /.page -->
<footer class="site-footer">
  <a href="https://github.com/matsulinks/moat" target="_blank" rel="noopener">
    ⭐ GitHub: matsulinks/moat
  </a>
</footer>
</div><!-- /#screen-complete -->


<!-- ═══════════════════════════════════════════════════════════
     JAVASCRIPT
════════════════════════════════════════════════════════════ -->
<script>
/* ── Data ────────────────────────────────────────────────── */
const LAYERS = [
  { id:'layer1', num:'1', name:'ネットワーク分離',
    badge:'rec', label:'✅ 推奨',
    desc:'Tailscale ACL + iptables で C2 通信も遮断します',
    files:'tailscale-acl.json, iptables-setup.sh', on:true },
  { id:'layer2', num:'2', name:'Docker ハードニング',
    badge:'rec', label:'✅ 推奨',
    desc:'docker-compose.yml を差し替えるだけでコンテナを強化',
    files:'docker-compose.yml', on:true },
  { id:'layer3', num:'3', name:'認証・アクセス制御',
    badge:'rec', label:'✅ 推奨',
    desc:'必須設定。config.yaml の auth セクションを生成します',
    files:'config.yaml', on:true },
  { id:'layer4', num:'4', name:'機密情報管理 (Infisical)',
    badge:'opt', label:'⚠️ 任意',
    desc:'別サーバーが必要。8 GB RAM で動作可能',
    files:'infisical-compose.yml', on:false },
  { id:'layer5', num:'5', name:'スキル・プロンプト防御',
    badge:'opt', label:'⚠️ 任意',
    desc:'LLM-as-Judge は追加 API コストが発生します',
    files:'config.yaml (追記)', on:false },
  { id:'layer6', num:'6', name:'実行時最小権限',
    badge:'rec', label:'✅ 推奨',
    desc:'必須設定。デフォルト deny でツール実行を制御',
    files:'config.yaml (追記)', on:true },
  { id:'layer7', num:'7', name:'監視 (Falco + Prometheus)',
    badge:'opt', label:'⚠️ 任意',
    desc:'Pi 5 で動作可能ですが重め。後から追加もできます',
    files:'falco_rules.local.yaml, alerts.yaml', on:false },
  { id:'ai-m', num:'AI-M', name:'AI 仲裁エージェント',
    badge:'opt', label:'⚠️ 任意',
    desc:'衝突検知 → AI 分析 → 開発 AI に匿名レポート',
    files:'config.yaml (追記)', on:false },
  { id:'ai-t', num:'AI-T', name:'脅威インテリジェンス・ワクチン',
    badge:'opt', label:'⚠️ 任意',
    desc:'CVE フィード → AI 分析 → Falco ルール自動生成',
    files:'config.yaml (追記)', on:false },
];

const DEMO_EVENTS = [
  { risk:'CRITICAL', icon:'🚨',
    title:'不審なネットワーク送信がブロックされました',
    body:'worker-ai が外部の未知サービスへのデータ送信を試みましたが、Layer 6 のセキュリティ設定によりブロックされました。',
    details:{ Event:'layer6_network_denied', Risk:'CRITICAL', Agent:'worker-ai', Tool:'http_post', Dst:'api.unknown-service.com:443', Time:'' } },
  { risk:'MEDIUM', icon:'⚠️',
    title:'ソフトがブロックされています',
    body:'worker-ai が外部サービスへの接続を試みましたが、ホワイトリスト外のため遮断されました。',
    details:{ Event:'layer6_network_denied', Risk:'MEDIUM', Agent:'worker-ai', Tool:'http_get', Dst:'api.unknown-service.com:443', Time:'' } },
];

/* ── State ───────────────────────────────────────────────── */
const S = {
  layers: Object.fromEntries(LAYERS.map(l => [l.id, l.on])),
  approval: 'high_risk_only',
};

/* ── Render layer cards ──────────────────────────────────── */
function renderLayers() {
  document.getElementById('layers-grid').innerHTML = LAYERS.map(l => {
    const on = S.layers[l.id];
    return `
<div class="layer-card ${on ? 'is-on' : ''}" id="card-${l.id}">
  <div class="layer-num">${l.num}</div>
  <div class="layer-body">
    <div class="layer-name-row">
      <span class="layer-name">${l.name}</span>
      <span class="badge badge-${l.badge}">${l.label}</span>
    </div>
    <div class="layer-desc">${l.desc}</div>
    <div class="layer-files">📄 ${l.files}</div>
  </div>
  <div class="toggle-wrap">
    <label class="toggle" aria-label="${l.name} の ON/OFF">
      <input type="checkbox" ${on ? 'checked' : ''} onchange="toggleLayer('${l.id}',this.checked)">
      <span class="t-track"></span>
      <span class="t-thumb"></span>
    </label>
    <span class="t-label" id="tlabel-${l.id}">${on ? 'ON' : 'OFF'}</span>
  </div>
</div>`;
  }).join('');
}

function toggleLayer(id, on) {
  S.layers[id] = on;
  const card = document.getElementById('card-' + id);
  card.classList.toggle('is-on', on);
  document.getElementById('tlabel-' + id).textContent = on ? 'ON' : 'OFF';
}

/* ── Approval level ──────────────────────────────────────── */
document.querySelectorAll('input[name="approval"]').forEach(r => {
  r.addEventListener('change', () => {
    S.approval = r.value;
    document.querySelectorAll('.approval-opt').forEach(el => el.classList.remove('chosen'));
    r.closest('.approval-opt').classList.add('chosen');
  });
});

/* ── Env panel ───────────────────────────────────────────── */
function renderEnv(env) {
  document.getElementById('env-dot').style.animation = 'none';
  document.getElementById('env-title').textContent = '検出完了';
  const rows = [
    { icon:'💻', label:'ハードウェア', val: env.hardware || '不明' },
    { icon:'🧠', label:'RAM',          val: env.ram || '—' },
    { icon:'🐧', label:'OS',           val: env.os || '—' },
    { icon:'🐳', label:'Docker',       val: env.docker  ? env.docker + ' ✓' : '未インストール', cls: env.docker  ? 'ok' : 'dim' },
    { icon:'🔒', label:'Tailscale',    val: env.tailscale  ? 'インストール済み ✓' : '未インストール', cls: env.tailscale  ? 'ok' : 'dim' },
    { icon:'🦅', label:'Falco',        val: env.falco      ? 'インストール済み ✓' : '未インストール', cls: env.falco      ? 'ok' : 'dim' },
    { icon:'📊', label:'Prometheus',   val: env.prometheus ? 'インストール済み ✓' : '未インストール', cls: env.prometheus ? 'ok' : 'dim' },
  ];
  document.getElementById('env-grid').innerHTML = rows.map(r => `
<div class="env-item">
  <span class="env-item-icon">${r.icon}</span>
  <div>
    <div class="env-item-label">${r.label}</div>
    <div class="env-item-val ${r.cls || ''}">${r.val}</div>
  </div>
</div>`).join('');
}

/* ── Alert card factory ──────────────────────────────────── */
function makeAlertCard(ev, idx) {
  if (!ev.details.Time) ev.details.Time = new Date().toLocaleString('ja-JP');
  const kvHTML = Object.entries(ev.details)
    .map(([k,v]) => `<span class="dk">${k}</span><span class="dv">${v}</span>`)
    .join('');
  const div = document.createElement('div');
  div.className = 'alert-card';
  div.dataset.risk = ev.risk;
  div.dataset.idx = idx;
  div.innerHTML = `
<div class="alert-main">
  <div class="alert-title-row">
    <span class="alert-icon">${ev.icon}</span>
    <span class="alert-title">${ev.title}</span>
    <span class="risk-badge">${ev.risk}</span>
    <button class="toggle-detail-btn" onclick="toggleDetail(this,${idx})">詳細 ▼</button>
  </div>
  <div class="alert-body">${ev.body}</div>
  <div class="alert-actions" id="aact-${idx}">
    <button class="a-btn a-btn-allow" onclick="doAllow(${idx})">✓ 許可する</button>
    <button class="a-btn a-btn-block" onclick="doBlock(${idx})">🚫 ブロックのまま</button>
    <button class="a-btn a-btn-report" onclick="openReport(${idx})">📤 報告</button>
    <button class="a-btn a-btn-ai"    onclick="toggleChat(${idx})">💬 AIに聞く</button>
  </div>
</div>
<div class="alert-detail" id="adet-${idx}">
  <div class="detail-label">技術的な詳細</div>
  <div class="detail-kv">${kvHTML}</div>
  <button class="copy-btn" onclick="copyDetail(${idx})">📋 この内容をコピー</button>
  <div style="clear:both;"></div>
</div>
<div class="ai-chat" id="achat-${idx}">
  <div class="chat-head">
    <span class="chat-title">💬 このエラーについて AI に質問できます</span>
    <button class="chat-close" onclick="toggleChat(${idx})">✕</button>
  </div>
  <p class="chat-hint">技術詳細は自動で添付されています</p>
  <div class="chat-messages" id="amsgs-${idx}">
    <div class="bubble bubble-ai">
      <span class="bubble-ai-name">AI</span>
      このセキュリティイベントについて何でも聞いてください。
    </div>
  </div>
  <div class="chat-input-row">
    <input class="chat-input" id="ainput-${idx}" type="text"
           placeholder="メッセージを入力..."
           onkeydown="if(event.key==='Enter')sendMsg(${idx})">
    <button class="chat-send" onclick="sendMsg(${idx})">送信</button>
  </div>
</div>`;
  return div;
}

function toggleDetail(btn, idx) {
  const d = document.getElementById('adet-' + idx);
  const open = d.classList.toggle('open');
  btn.textContent = open ? '詳細 ▲' : '詳細 ▼';
}

function toggleChat(idx) {
  const c = document.getElementById('achat-' + idx);
  const open = c.classList.toggle('open');
  if (open) setTimeout(() => document.getElementById('ainput-' + idx).focus(), 40);
}

function doAllow(idx) {
  document.getElementById('aact-' + idx).innerHTML =
    '<span style="color:var(--green);font-size:13px;">✓ 許可しました — ホワイトリストに追加されます</span>';
}
function doBlock(idx) {
  document.getElementById('aact-' + idx).innerHTML =
    '<span style="color:var(--text-2);font-size:13px;">🚫 ブロックを継続します</span> ' +
    '<button class="a-btn a-btn-report" onclick="openReport(' + idx + ')">📤 コミュニティに報告</button>';
}

function openReport(idx) {
  const ev = DEMO_EVENTS[idx];
  if (!ev) return;
  fetch('/api/report', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(ev.details)
  }).then(r => r.json()).then(d => {
    if (d.url) window.open(d.url, '_blank');
  });
}

function copyDetail(idx) {
  const ev = DEMO_EVENTS[idx];
  if (!ev) return;
  const txt = Object.entries(ev.details).map(([k,v]) => k + ': ' + v).join('\n');
  navigator.clipboard.writeText(txt).then(() => {
    const btn = document.querySelector('#adet-' + idx + ' .copy-btn');
    if (btn) { btn.textContent = '✓ コピーしました'; setTimeout(() => btn.textContent = '📋 この内容をコピー', 2000); }
  });
}

async function sendMsg(idx) {
  const input = document.getElementById('ainput-' + idx);
  const msgs  = document.getElementById('amsgs-' + idx);
  const text  = input.value.trim();
  if (!text) return;
  input.value = '';

  /* User bubble */
  const uBubble = document.createElement('div');
  uBubble.className = 'bubble bubble-you';
  uBubble.textContent = text;
  msgs.appendChild(uBubble);
  msgs.scrollTop = msgs.scrollHeight;

  /* AI typing bubble */
  const aBubble = document.createElement('div');
  aBubble.className = 'bubble bubble-ai';
  aBubble.innerHTML = '<span class="bubble-ai-name">AI</span>'
    + '<span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>';
  msgs.appendChild(aBubble);
  msgs.scrollTop = msgs.scrollHeight;

  const ctx = DEMO_EVENTS[idx] ? DEMO_EVENTS[idx].details : {};
  try {
    const res  = await fetch('/api/chat', { method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ message: text, context: ctx }) });
    const data = await res.json();
    aBubble.innerHTML = '<span class="bubble-ai-name">AI</span>' + (data.reply || '応答を取得できませんでした');
  } catch(_) {
    aBubble.innerHTML = '<span class="bubble-ai-name">AI</span>サーバーに接続できませんでした。';
  }
  msgs.scrollTop = msgs.scrollHeight;
}

/* ── Generate config ─────────────────────────────────────── */
async function generateConfig() {
  const btn = document.getElementById('gen-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>生成中...';

  const selected = Object.entries(S.layers).filter(([,v]) => v).map(([k]) => k);
  let data;
  try {
    const res = await fetch('/api/generate', { method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ layers: selected, approval_level: S.approval }) });
    data = await res.json();
  } catch(_) {
    data = { files: mockFiles(selected), success: true };
  }

  btn.disabled = false;
  btn.innerHTML = '設定ファイルを生成する →';
  showComplete(data, selected);
}

function mockFiles(sel) {
  const f = [];
  if (sel.includes('layer1')) { f.push({name:'tailscale-acl.json',layer:'Layer 1'}); f.push({name:'iptables-setup.sh',layer:'Layer 1'}); }
  if (sel.includes('layer2')) f.push({name:'docker-compose.yml', layer:'Layer 2'});
  if (sel.some(x => ['layer3','layer5','layer6'].includes(x))) f.push({name:'config.yaml', layer:'Layer 3/5/6'});
  if (sel.includes('layer4')) f.push({name:'infisical-compose.yml', layer:'Layer 4'});
  if (sel.includes('layer7')) { f.push({name:'falco_rules.local.yaml',layer:'Layer 7'}); f.push({name:'alerts.yaml',layer:'Layer 7'}); }
  f.push({name:'SETUP_GUIDE.md', layer:'ガイド'});
  return f;
}

/* ── Complete screen ─────────────────────────────────────── */
function showComplete(data, sel) {
  document.getElementById('screen-main').style.display = 'none';
  document.getElementById('screen-complete').style.display = 'block';
  window.scrollTo(0,0);

  const files = data.files || mockFiles(sel);
  document.getElementById('files-panel').innerHTML =
    `<div class="files-head">📦 ${files.length} 個のファイルが生成されました</div>` +
    files.map(f => `
<div class="file-row">
  <span class="file-icon">📄</span>
  <span class="file-name">${f.name}</span>
  <span class="file-layer">${f.layer}</span>
  <a class="dl-btn" href="/download/${f.name}">⬇ DL</a>
</div>`).join('');

  const steps = buildSteps(sel);
  document.getElementById('steps-list').innerHTML = steps.map((s,i) => `
<div class="step-row">
  <div class="step-num">${i+1}</div>
  <div>
    <span class="step-title">${s.t}</span>
    <span class="step-desc">${s.d}</span>
  </div>
</div>`).join('');
}

function buildSteps(sel) {
  const s = [];
  if (sel.includes('layer2')) s.push({t:'docker-compose.yml を配置', d:'既存ファイルをバックアップしてから差し替えてください'});
  if (sel.includes('layer1')) {
    s.push({t:'Tailscale ACL を適用', d:'Tailscale 管理コンソールで <code>tailscale-acl.json</code> を貼り付けてください'});
    s.push({t:'iptables ルールを有効化', d:'<code>sudo bash iptables-setup.sh</code> を実行してください'});
  }
  if (sel.some(x => ['layer3','layer5','layer6'].includes(x)))
    s.push({t:'config.yaml を配置', d:'OpenClaw 設定ディレクトリに配置して再起動してください'});
  if (sel.includes('layer4'))
    s.push({t:'Infisical を起動', d:'<code>docker compose -f infisical-compose.yml up -d</code>'});
  if (sel.includes('layer7'))
    s.push({t:'Falco ルールを適用', d:'<code>/etc/falco/</code> に配置して Falco を再起動してください'});
  s.push({t:'動作確認', d:'OpenClaw を再起動して <code>SETUP_GUIDE.md</code> の手順を確認してください'});
  return s;
}

function restartWizard() {
  document.getElementById('screen-complete').style.display = 'none';
  document.getElementById('screen-main').style.display = 'block';
  window.scrollTo(0,0);
}

/* ── Init ────────────────────────────────────────────────── */
async function init() {
  renderLayers();

  /* Load environment info */
  try {
    const res = await fetch('/api/env');
    const env = await res.json();
    renderEnv(env);
    /* Update layer recommendations based on env */
    if (env.recommend) applyRecommendations(env.recommend);
  } catch(_) {
    /* Demo fallback */
    renderEnv({
      hardware:'Raspberry Pi 5', ram:'8 GB',
      os:'Debian GNU/Linux 13 (trixie)',
      docker:'v29.2.1', tailscale:true, falco:false, prometheus:false,
    });
  }

  /* Render demo alert cards */
  const demoArea = document.getElementById('demo-alerts');
  DEMO_EVENTS.forEach((ev, i) => demoArea.appendChild(makeAlertCard(ev, i)));
}

function applyRecommendations(rec) {
  /* rec: { layer_id: 'RECOMMEND' | 'OPTIONAL' | 'SKIP' } */
  LAYERS.forEach(l => {
    if (!rec[l.id]) return;
    const on = rec[l.id] === 'RECOMMEND';
    S.layers[l.id] = on;
  });
  renderLayers();
}

init();
</script>
</body>
</html>"""

def _run(cmd: str) -> str:
    try:
        out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except Exception:
        return ""


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:
        return ""


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _parse_docker_version() -> str:
    out = _run("docker --version")
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def _get_containers() -> list[str]:
    if not _which("docker"):
        return []
    out = _run("docker ps --format {{.Names}}")
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def detect_os_type() -> str:
    """'linux' / 'mac' / 'windows' / 'unknown' を返す"""
    s = platform.system().lower()
    if s == "linux":
        return "linux"
    if s == "darwin":
        return "mac"
    if s == "windows":
        return "windows"
    return "unknown"


def detect_env_linux() -> dict[str, Any]:
    cpuinfo = _read_text("/proc/cpuinfo")
    model = "Linux Host"
    for line in cpuinfo.splitlines():
        if line.startswith("Model"):
            model = line.split(":", 1)[1].strip()
            break

    meminfo = _read_text("/proc/meminfo")
    mem_kb = 0
    m = re.search(r"^MemTotal:\s+(\d+)\s+kB", meminfo, re.M)
    if m:
        mem_kb = int(m.group(1))
    ram_gb = int(round(mem_kb / 1024 / 1024)) if mem_kb else 0

    os_release = _read_text("/etc/os-release")
    pretty_name = "Linux"
    for line in os_release.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty_name = line.split("=", 1)[1].strip().strip('"')
            break

    docker = _which("docker")
    tailscale = _which("tailscale")
    falco = _which("falco")
    prometheus = _which("prometheus")
    grafana = _which("grafana-server")
    infisical = _which("infisical")

    return {
        "hardware": model,
        "ram_gb": ram_gb,
        "os": pretty_name,
        "kernel": _run("uname -r"),
        "docker": docker,
        "docker_version": _parse_docker_version() if docker else "",
        "tailscale": tailscale,
        "falco": falco,
        "prometheus": prometheus,
        "grafana": grafana,
        "infisical": infisical,
        "containers": _get_containers() if docker else [],
        "os_type": "linux",
    }


def detect_env_mac() -> dict[str, Any]:
    # TODO Phase 2: macOS対応
    # hardware : system_profiler SPHardwareDataType | grep "Model Name"
    # ram_gb   : sysctl -n hw.memsize  (bytes → GB)
    # os       : sw_vers -productVersion
    # kernel   : uname -r
    # docker   : which docker + docker --version  (Linux同様)
    # tailscale: which tailscale                  (Linux同様)
    # falco    : 非対応 → 常にFalse（eBPFはLinuxのみ）
    # iptables : 非対応 → 常にFalse（macOSはpfを使うが今回はSkip）
    # prometheus: which prometheus                (Homebrewで入る)
    return {
        "hardware": _run("sysctl -n hw.model") or "Mac",
        "ram_gb": int(int(_run("sysctl -n hw.memsize") or 0) / 1024**3),
        "os": "macOS " + (_run("sw_vers -productVersion") or ""),
        "kernel": _run("uname -r") or "",
        "docker": bool(_run("which docker")),
        "docker_version": _parse_docker_version(),
        "tailscale": bool(_run("which tailscale")),
        "falco": False,
        "prometheus": bool(_run("which prometheus")),
        "grafana": False,
        "infisical": bool(_run("which infisical")),
        "containers": _get_containers(),
        "os_type": "mac",
    }


def detect_env_windows() -> dict[str, Any]:
    # TODO Phase 2: Windows対応
    # 現バージョンではWSL2使用を案内して終了
    print("=" * 50)
    print(T("win_not_supported"))
    print(T("win_use_wsl"))
    print("https://learn.microsoft.com/en-us/windows/wsl/install")
    print("=" * 50)
    sys.exit(0)


def detect_env() -> dict[str, Any]:
    os_type = detect_os_type()
    if os_type == "linux":
        return detect_env_linux()
    if os_type == "mac":
        return detect_env_mac()
    if os_type == "windows":
        return detect_env_windows()
    print(T("os_not_supported"))
    sys.exit(1)


def recommend_layers(env: dict[str, Any]) -> dict[str, dict[str, Any]]:
    # ─────────────────────────────────────────────────────
    # OS別レイヤー対応状況
    # Layer | Linux | macOS       | Windows
    # ------+-------+-------------+------------------
    #   1   |  ✅   | △TailscaleのみFALCO対応(iptables除外) | 非対応(Phase2)
    #   2   |  ✅   | ✅          | 非対応(Phase2)
    #   3   |  ✅   | ✅          | 非対応(Phase2)
    #   4   |  ✅   | ✅          | 非対応(Phase2)
    #   5   |  ✅   | ✅          | 非対応(Phase2)
    #   6   |  ✅   | ✅          | 非対応(Phase2)
    #   7   |  ✅   | ❌FalcoはLinuxのみ | 非対応(Phase2)
    # AI-M  |  ✅   | ✅          | 非対応(Phase2)
    # AI-T  |  ✅   | △iptablesルール除外 | 非対応(Phase2)
    # ─────────────────────────────────────────────────────

    ram = int(env.get("ram_gb", 0) or 0)
    os_type = env.get("os_type", "unknown")
    rec: dict[str, dict[str, Any]] = {}

    if env.get("tailscale"):
        rec["layer1"] = {"status": "recommend", "reason": T("reason_l1_installed"), "default": True}
    else:
        rec["layer1"] = {"status": "optional", "reason": T("reason_l1_missing"), "default": False}
    if os_type == "mac":
        rec["layer1"]["reason"] += T("reason_l1_mac")

    if env.get("docker"):
        rec["layer2"] = {"status": "recommend", "reason": T("reason_l2_installed"), "default": True}
    else:
        rec["layer2"] = {"status": "optional", "reason": T("reason_l2_missing"), "default": False}

    rec["layer3"] = {"status": "recommend", "reason": T("reason_l3"), "default": True}

    if ram >= 16:
        rec["layer4"] = {"status": "recommend", "reason": T("reason_l4_16gb"), "default": True}
    elif ram >= 8:
        rec["layer4"] = {"status": "optional", "reason": T("reason_l4_8gb"), "default": False}
    elif ram < 4:
        rec["layer4"] = {"status": "skip", "reason": T("reason_l4_low"), "default": False}
    else:
        rec["layer4"] = {"status": "optional", "reason": T("reason_l4_medium"), "default": False}

    rec["layer5"] = {"status": "optional", "reason": T("reason_l5"), "default": False}
    rec["layer6"] = {"status": "recommend", "reason": T("reason_l6"), "default": True}

    if os_type == "mac":
        rec["layer7"] = {"status": "skip", "reason": T("reason_l7_mac"), "default": False}
    elif ram >= 16:
        rec["layer7"] = {"status": "recommend", "reason": T("reason_l7_high"), "default": True}
    elif ram >= 8:
        rec["layer7"] = {"status": "optional", "reason": T("reason_l7_medium"), "default": False}
    elif ram < 4:
        rec["layer7"] = {"status": "skip", "reason": T("reason_l4_low"), "default": False}
    else:
        rec["layer7"] = {"status": "optional", "reason": T("reason_l4_medium"), "default": False}

    rec["ai-m"] = {"status": "optional", "reason": T("reason_aim"), "default": False}
    if os_type == "mac":
        rec["ai-t"] = {"status": "optional", "reason": T("reason_ait_mac"), "default": False}
    else:
        rec["ai-t"] = {"status": "optional", "reason": T("reason_aim"), "default": False}

    return rec


def _status_to_color(status: str) -> str:
    if status == "recommend":
        return COLOR_GREEN
    if status == "optional":
        return COLOR_YELLOW
    return COLOR_RED


def _status_label(status: str) -> str:
    if status == "recommend":
        return T("status_recommend")
    if status == "optional":
        return T("status_optional")
    return T("status_skip")


def _status_badge(status: str, selected: bool) -> str:
    if status == "recommend":
        c = COLOR_GREEN
        icon = "✅"
    elif status == "optional":
        c = COLOR_YELLOW
        icon = "⚠️"
    else:
        c = COLOR_RED
        icon = "❌"
    onoff = "ON " if selected else "OFF"
    return f"{c}[{icon} {onoff}]{COLOR_RESET}"


def print_env_summary(env: dict[str, Any]) -> None:
    docker_text = f"v{env.get('docker_version')} ✓" if env.get("docker") and env.get("docker_version") else T("not_installed")
    print(f"\n{T('env_heading')}")
    print(f"  {T('env_hardware'):<13}: {env.get('hardware', T('env_unknown'))}")
    print(f"  RAM          : {env.get('ram_gb', 0)} GB")
    print(f"  OS           : {env.get('os', T('env_unknown'))}")
    print(f"  Docker       : {docker_text}")
    print(f"  Tailscale    : {T('installed') if env.get('tailscale') else T('not_installed')}")
    print(f"  Falco        : {T('installed') if env.get('falco') else T('not_installed')}")
    print(f"  Prometheus   : {T('installed') if env.get('prometheus') else T('not_installed')}")


def _print_layer_table(rec: dict[str, dict[str, Any]], selected: dict[str, bool], env: dict[str, Any]) -> None:
    print(f"\n{T('layer_table_heading')}\n")
    for idx, (layer_id, short_name, title_key, files) in enumerate(LAYER_ORDER, start=1):
        info = rec[layer_id]
        status = info["status"]
        line = f"  {idx}. {short_name:<6} {_status_badge(status, selected[layer_id])}  {T(title_key)}"
        print(line)
        print(f"      {_status_to_color(status)}{_status_label(status)}{COLOR_RESET}: {info['reason']}")
        if layer_id == "layer1" and env.get("os_type") == "mac":
            print(f"      {T('layer_gen_mac')}")
        else:
            print(f"      {T('layer_gen')}{files}")
    print(f"\n  {T('layer_hint')}")


def select_layers_terminal(env: dict[str, Any], rec: dict[str, dict[str, Any]]) -> list[str] | None:
    selected = {layer_id: bool(info.get("default", False)) for layer_id, info in rec.items()}

    index_map: dict[str, str] = {}
    for i, (layer_id, *_rest) in enumerate(LAYER_ORDER, start=1):
        index_map[str(i)] = layer_id
        index_map[layer_id] = layer_id

    while True:
        _print_layer_table(rec, selected, env)
        cmd = input(f"\n{T('input_prompt')}").strip().lower()
        if cmd == "":
            break
        if cmd == "q":
            return None
        target = index_map.get(cmd)
        if not target:
            print(T("invalid_input"))
            continue
        if rec[target]["status"] == "skip":
            print(T("layer_skip_locked"))
            continue
        selected[target] = not selected[target]

    return [lid for lid, on in selected.items() if on]


def choose_approval_level() -> str:
    print(f"\n{T('approval_heading')}\n")
    print(T("approval_1"))
    print(T("approval_2"))
    print(T("approval_3"))
    choice = input(T("approval_prompt")).strip()
    if choice == "1":
        return "none"
    if choice == "3":
        return "all"
    return "high_risk_only"


def _write_file(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        current = path.stat().st_mode
        path.chmod(current | 0o111)


def build_docker_compose(layer4_on: bool) -> str:
    if layer4_on:
        return textwrap.dedent(
            """
            version: '3.9'

            services:
              openclaw:
                image: ghcr.io/openclaw/openclaw:latest
                container_name: openclaw-instance01
                restart: unless-stopped

                # Infisical CLIでJIT注入
                entrypoint: ["/bin/sh", "-c"]
                command:
                  - |
                    exec infisical run \\
                      --projectId YOUR_PROJECT_ID \\
                      --env=prod \\
                      -- /app/openclaw --config /app/config/config.yaml

                user: "10000:10000"
                read_only: true
                tmpfs:
                  - /tmp:uid=10000,gid=10000,mode=700,size=128m,noexec,nosuid,nodev
                  - /var/tmp:uid=10000,gid=10000,mode=700,size=64m,noexec,nosuid,nodev
                security_opt:
                  - no-new-privileges:true
                cap_drop:
                  - ALL
                # cap_addは使用しない。OpenClawが必要とする場合のみ個別に追加すること。

                # hostネットワークは使用しない（コンテナ境界を弱めるため）
                # Tailscaleはホスト側で動作し、iptablesで通信制御する
                networks:
                  - openclaw-net

                # リソース制限（deploy.resourcesはSwarmモード専用のため使用しない）
                mem_limit: 2g
                memswap_limit: 2g
                cpus: '1.0'

                volumes:
                  - ./config:/app/config:ro
                  - ./data:/app/data:rw
                  - ./logs:/app/logs:rw
                  - ./workspace:/app/workspace:ro

                environment:
                  - INFISICAL_SERVICE_TOKEN=${INFISICAL_SERVICE_TOKEN}
                  - TZ=Asia/Tokyo

                healthcheck:
                  test: ["CMD", "curl", "-f", "http://localhost:8765/health"]
                  interval: 30s
                  timeout: 10s
                  retries: 3

                logging:
                  driver: "json-file"
                  options:
                    max-size: "10m"
                    max-file: "3"

            networks:
              openclaw-net:
                driver: bridge
            """
        ).strip() + "\n"

    return textwrap.dedent(
        """
        version: '3.9'

        services:
          openclaw:
            image: ghcr.io/openclaw/openclaw:latest
            container_name: openclaw-instance01
            restart: unless-stopped

            user: "10000:10000"
            read_only: true
            tmpfs:
              - /tmp:uid=10000,gid=10000,mode=700,size=128m,noexec,nosuid,nodev
              - /var/tmp:uid=10000,gid=10000,mode=700,size=64m,noexec,nosuid,nodev
            security_opt:
              - no-new-privileges:true
            cap_drop:
              - ALL
            # cap_addは使用しない。OpenClawが必要とする場合のみ個別に追加すること。

            # hostネットワークは使用しない（コンテナ境界を弱めるため）
            # Tailscaleはホスト側で動作し、iptablesで通信制御する
            networks:
              - openclaw-net

            # リソース制限（deploy.resourcesはSwarmモード専用のため使用しない）
            mem_limit: 2g
            memswap_limit: 2g
            cpus: '1.0'

            volumes:
              - ./config:/app/config:ro
              - ./data:/app/data:rw
              - ./logs:/app/logs:rw
              - ./workspace:/app/workspace:ro

            environment:
              # Infisicalを使う場合はLayer4を有効にしてください
              - TZ=Asia/Tokyo

            healthcheck:
              test: ["CMD", "curl", "-f", "http://localhost:8765/health"]
              interval: 30s
              timeout: 10s
              retries: 3

            logging:
              driver: "json-file"
              options:
                max-size: "10m"
                max-file: "3"

        networks:
          openclaw-net:
            driver: bridge
        """
    ).strip() + "\n"


def build_config_yaml(selected_layers: set[str], approval_level: str) -> str:
    sections = [APPROVAL_YAML_TEMPLATE.format(level=APPROVAL_LEVEL_MAP.get(approval_level, "high_risk_only")).strip()]
    if "layer3" in selected_layers:
        sections.append(LAYER3_CONFIG)
    if "layer5" in selected_layers:
        sections.append(LAYER5_CONFIG)
    if "layer6" in selected_layers:
        sections.append(LAYER6_CONFIG)
    if "ai-m" in selected_layers:
        sections.append(AIM_CONFIG)
    if "ai-t" in selected_layers:
        sections.append(AIT_CONFIG)
    return "\n\n".join(sections).strip() + "\n"


def build_setup_guide(selected_layers: set[str], env: dict[str, Any], approval_level: str) -> str:
    selected = ", ".join(sorted(selected_layers)) if selected_layers else "なし"
    os_type = env.get("os_type", "unknown")
    parts = [
        "# Moat — AI Security Setup Guide",
        "",
        f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"OS: {env.get('os', '不明')} ({os_type})",
        f"RAM: {env.get('ram_gb', 0)} GB",
        f"選択レイヤー: {selected}",
        f"承認レベル: {approval_level}",
        "",
        "## 今回有効化した内容",
    ]

    if not selected_layers:
        parts.append("- 今回はレイヤーを選択していません。")
    else:
        if "layer1" in selected_layers:
            parts.append("- Layer 1: Tailscale ACL を適用してください。")
            if os_type != "mac":
                parts.append("- Layer 1: `sudo bash iptables-setup.sh` を実行してください。")
        if "layer2" in selected_layers:
            parts.append("- Layer 2: `docker-compose.yml` を既存構成と入れ替えて再起動してください。")
        if {"layer3", "layer5", "layer6", "ai-m", "ai-t"} & selected_layers:
            parts.append("- config.yaml をOpenClawの設定ディレクトリへ配置してください。")
        if "layer4" in selected_layers:
            parts.append("- Layer 4: `docker compose -f infisical-compose.yml up -d` で起動してください。")
        if "layer7" in selected_layers and os_type != "mac":
            parts.append("- Layer 7: Falco ルールを `/etc/falco/` に配置して再起動してください。")

    parts.extend([
        "",
        "## 後から追加する場合",
    ])
    for layer_id, short_name, title, files in LAYER_ORDER:
        if layer_id in selected_layers:
            continue
        parts.extend(
            [
                f"<details><summary>{short_name}: {title}</summary>",
                "",
                f"生成対象: {files}",
                "ウィザードを再実行し、このレイヤーをONにして再生成してください。",
                "",
                "</details>",
                "",
            ]
        )

    parts.extend(
        [
            "## 次にやること",
            "1. 生成されたファイルを安全な場所にバックアップする",
            "2. 1レイヤーずつ適用して、問題がないことを確認する",
            "3. 変更後はOpenClawを再起動し、エラーがないか確認する",
        ]
    )

    return "\n".join(parts).strip() + "\n"


def generate_files(selected_layers: list[str], approval_level: str, env: dict[str, Any]) -> list[dict[str, str]]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    selected = set(selected_layers)
    files: list[dict[str, str]] = []

    if "layer1" in selected:
        _write_file(OUTPUT_DIR / "tailscale-acl.json", LAYER1_ACL_JSON)
        files.append({"name": "tailscale-acl.json", "layer": "Layer 1"})
        if env.get("os_type") != "mac":
            _write_file(OUTPUT_DIR / "iptables-setup.sh", LAYER1_IPTABLES_SH, executable=True)
            files.append({"name": "iptables-setup.sh", "layer": "Layer 1"})

    if "layer2" in selected:
        docker_yaml = build_docker_compose(layer4_on=("layer4" in selected))
        _write_file(OUTPUT_DIR / "docker-compose.yml", docker_yaml)
        files.append({"name": "docker-compose.yml", "layer": "Layer 2"})

    if {"layer3", "layer5", "layer6", "ai-m", "ai-t"} & selected:
        cfg = build_config_yaml(selected, approval_level)
        _write_file(OUTPUT_DIR / "config.yaml", cfg)
        files.append({"name": "config.yaml", "layer": "Layer 3/5/6"})

    if "layer4" in selected:
        _write_file(OUTPUT_DIR / "infisical-compose.yml", LAYER4_INFISICAL_COMPOSE)
        files.append({"name": "infisical-compose.yml", "layer": "Layer 4"})

    if "layer7" in selected and env.get("os_type") != "mac":
        _write_file(OUTPUT_DIR / "falco_rules.local.yaml", LAYER7_FALCO_RULES)
        _write_file(OUTPUT_DIR / "alerts.yaml", LAYER7_ALERTS)
        files.append({"name": "falco_rules.local.yaml", "layer": "Layer 7"})
        files.append({"name": "alerts.yaml", "layer": "Layer 7"})

    guide = build_setup_guide(selected, env, approval_level)
    _write_file(OUTPUT_DIR / "SETUP_GUIDE.md", guide)
    files.append({"name": "SETUP_GUIDE.md", "layer": "ガイド"})

    return files


def _y_or_n(prompt: str) -> bool:
    return input(prompt).strip().lower() == "y"


def _to_upper_recommend(rec: dict[str, dict[str, Any]]) -> dict[str, str]:
    out = {}
    for lid, info in rec.items():
        status = info.get("status", "optional")
        if status == "recommend":
            out[lid] = "RECOMMEND"
        elif status == "skip":
            out[lid] = "SKIP"
        else:
            out[lid] = "OPTIONAL"
    return out


def _fetch_json(url: str, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "OpenClaw-Setup-Wizard"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_bytes(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "OpenClaw-Setup-Wizard"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_sha256_line(text: str) -> str:
    m = re.search(r"\b([a-fA-F0-9]{64})\b", text)
    if not m:
        raise ValueError(T("sha256_not_found"))
    return m.group(1).lower()


def _version_tuple(v: str) -> tuple[int, ...]:
    cleaned = v.strip().lstrip("vV")
    nums = [int(x) for x in re.findall(r"\d+", cleaned)]
    return tuple(nums) if nums else (0,)


def self_update() -> None:
    print(T("update_checking"))
    try:
        rel = _fetch_json(RELEASES_API)
    except Exception as exc:
        print(T("update_fetch_failed", exc=exc))
        print(T("update_ref_url", url=RELEASES_API))
        print(T("update_env_hint"))
        return

    latest_tag = str(rel.get("tag_name", "")).strip()
    latest_ver = latest_tag.lstrip("vV")
    if not latest_ver:
        print(T("update_invalid_version"))
        return

    if _version_tuple(latest_ver) <= _version_tuple(VERSION):
        print(T("update_already_latest", current=VERSION, latest=latest_ver))
        return

    body = str(rel.get("body", ""))
    print(f"\n{T('update_available', current=VERSION, latest=latest_ver)}")
    print(T("update_changes"))
    print((body[:200] + "...") if len(body) > 200 else body)

    if not _y_or_n(f"\n{T('update_confirm')}"):
        print(T("update_cancelled"))
        return

    assets = {a.get("name"): a.get("browser_download_url") for a in rel.get("assets", [])}
    setup_url = assets.get("setup.py")
    sha_url = assets.get("setup.py.sha256")
    if not setup_url or not sha_url:
        print(T("update_no_asset"))
        return

    try:
        sha_text = _fetch_bytes(sha_url).decode("utf-8", errors="ignore")
        expected = _parse_sha256_line(sha_text)
        new_data = _fetch_bytes(setup_url)
        got = hashlib.sha256(new_data).hexdigest().lower()
    except Exception as exc:
        print(T("update_dl_failed", exc=exc))
        return

    if got != expected:
        print(T("update_verify_failed"))
        return

    target = Path(__file__).resolve()
    backup = target.with_name("setup.py.bak")
    try:
        shutil.copy2(target, backup)
        target.write_bytes(new_data)
    except Exception as exc:
        print(T("update_write_failed", exc=exc))
        return

    print(T("update_done"))


def _normalize_rule_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("rules", "items", "data"):
            if isinstance(payload.get(key), list):
                return [x for x in payload[key] if isinstance(x, dict)]
        return []
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    return []


def _rule_key(rule: dict[str, Any]) -> str:
    for key in ("id", "name", "rule", "title"):
        val = rule.get(key)
        if isinstance(val, str) and val.strip():
            return f"{key}:{val.strip()}"
    digest = hashlib.sha256(json.dumps(rule, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    return f"hash:{digest}"


def update_rules() -> None:
    print(T("rules_fetching"))
    try:
        data = _fetch_bytes(RULES_URL)
        sha_text = _fetch_bytes(RULES_SHA_URL).decode("utf-8", errors="ignore")
    except Exception as exc:
        print(T("rules_fetch_failed", exc=exc))
        print(T("rules_url", url=RULES_URL))
        print(T("rules_sha_url", url=RULES_SHA_URL))
        print(T("rules_env_hint"))
        return

    expected = _parse_sha256_line(sha_text)
    got = hashlib.sha256(data).hexdigest().lower()
    if got != expected:
        print(T("rules_verify_failed"))
        return

    try:
        new_payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        print(T("rules_parse_failed", exc=exc))
        return

    old_path = OUTPUT_DIR / "community-rules.json"
    old_payload: Any = []
    if old_path.exists():
        try:
            old_payload = json.loads(old_path.read_text(encoding="utf-8"))
        except Exception:
            old_payload = []

    old_rules = _normalize_rule_list(old_payload)
    new_rules = _normalize_rule_list(new_payload)
    old_map = {_rule_key(r): r for r in old_rules}
    new_map = {_rule_key(r): r for r in new_rules}

    added = len([k for k in new_map if k not in old_map])
    changed = len([k for k in new_map if k in old_map and new_map[k] != old_map[k]])

    print(T("rules_added", count=added))
    print(T("rules_changed", count=changed))

    if not _y_or_n(T("rules_confirm")):
        print(T("rules_cancelled"))
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    old_path.write_bytes(data)
    (OUTPUT_DIR / "community-rules.json.sha256").write_text(f"{expected}\n", encoding="utf-8")

    print(T("rules_done"))


def extract_domain(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""

    text = raw
    if "://" not in text:
        text = "https://" + text

    try:
        parsed = urllib.parse.urlparse(text)
        host = parsed.hostname or ""
    except Exception:
        host = ""

    if not host:
        return ""

    ip_match = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
    if ip_match:
        return ""
    return host.lower()


def anonymize_event(event: dict[str, Any]) -> dict[str, Any]:
    """送信前に個人情報を除去する"""
    safe = {
        "event_type": event.get("event") or event.get("Event", ""),
        "risk": event.get("risk") or event.get("Risk", ""),
        "tool": event.get("tool") or event.get("Tool", ""),
        "dst_domain": extract_domain(event.get("dst") or event.get("Dst", "")),
        "os_family": event.get("os_family", ""),
        "hw_family": event.get("hw_family", ""),
        "timestamp": (event.get("time") or event.get("Time", ""))[:10],
    }
    return safe


def build_report_url(event: dict[str, Any]) -> str:
    anon = anonymize_event(event)
    title = f"[threat-report] {anon['event_type']} / {anon['risk']} / {anon['dst_domain']}"
    body = "\n".join(f"- **{k}**: {v}" for k, v in anon.items())
    body += "\n\n<!-- この内容はOpenClawが自動生成しました。送信前に内容を確認してください -->"
    url = (
        REPORT_ISSUE_URL
        + "?labels=threat-report"
        + "&title=" + urllib.parse.quote(title)
        + "&body=" + urllib.parse.quote(body)
    )
    return url


def open_report_url(event: dict[str, Any]) -> None:
    url = build_report_url(event)
    webbrowser.open(url)
    print(T("report_opened"))


def _chat_with_openai(message: str, context: dict[str, Any]) -> str:
    api_key = (
        (context.get("api_key") if isinstance(context, dict) else None)
        or _read_text(str(OUTPUT_DIR / "OPENAI_API_KEY.txt")).strip()
        or ""
    )
    api_key = api_key or _run("printenv OPENAI_API_KEY")
    if not api_key:
        return T("api_key_missing")

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "You are a security assistant for OpenClaw. Give short, practical answers in the user's language, avoiding jargon.",
            },
            {
                "role": "system",
                "content": "Technical context (hidden from user):\n" + json.dumps(context, ensure_ascii=False),
            },
            {"role": "user", "content": message},
        ],
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return T("chat_failed", exc=exc)


class SetupHTTPRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/health":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/":
            self._send_html(200, HTML_TEMPLATE)
            return

        if path == "/api/env":
            env = detect_env()
            rec = recommend_layers(env)
            payload = {
                "hardware": env.get("hardware", ""),
                "ram": f"{env.get('ram_gb', 0)} GB",
                "os": env.get("os", ""),
                "docker": env.get("docker_version") if env.get("docker") else False,
                "tailscale": bool(env.get("tailscale")),
                "falco": bool(env.get("falco")),
                "prometheus": bool(env.get("prometheus")),
                "recommend": _to_upper_recommend(rec),
            }
            self._send_json(200, payload)
            return

        if path == "/api/recommend":
            env = detect_env()
            rec = recommend_layers(env)
            self._send_json(200, _to_upper_recommend(rec))
            return

        if path.startswith("/download/"):
            name = Path(path.replace("/download/", "", 1)).name
            target = OUTPUT_DIR / name
            if not target.exists() or not target.is_file():
                self._send_json(404, {"error": "file_not_found"})
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/generate":
            layers = body.get("layers", [])
            if not isinstance(layers, list):
                layers = []
            layers = [str(x) for x in layers]
            approval_level = str(body.get("approval_level") or "high_risk_only")
            if approval_level not in APPROVAL_LEVEL_MAP:
                approval_level = "high_risk_only"

            if any(x in layers for x in ("ai-m", "ai-t")):
                has_key = bool(_run("printenv OPENAI_API_KEY"))
                if not has_key:
                    layers = [x for x in layers if x not in {"ai-m", "ai-t"}]

            env = detect_env()
            files = generate_files(layers, approval_level, env)
            self._send_json(200, {"success": True, "files": files})
            return

        if path == "/api/chat":
            msg = str(body.get("message") or "").strip()
            ctx = body.get("context") if isinstance(body.get("context"), dict) else {}
            if not msg:
                self._send_json(400, {"reply": "メッセージが空です。"})
                return
            reply = _chat_with_openai(msg, ctx)
            self._send_json(200, {"reply": reply})
            return

        if path == "/api/report":
            url = build_report_url(body)
            self._send_json(200, {"url": url})
            return

        self._send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def run_web_mode(port: int = 8765, no_browser: bool = False) -> None:
    env = detect_env()
    rec = recommend_layers(env)
    default_layers = [lid for lid, info in rec.items() if info.get("default") and info.get("status") != "skip"]
    generate_files(default_layers, "high_risk_only", env)

    server = HTTPServer(("127.0.0.1", port), SetupHTTPRequestHandler)
    url = f"http://localhost:{port}"
    print(T("web_started", url=url))
    print(T("web_quit"))
    # サービス起動（非対話）ではブラウザ自動起動をスキップする。
    if no_browser or os.environ.get("MOAT_NO_BROWSER") == "1" or not sys.stdout.isatty():
        pass
    else:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{T('web_stopped')}")
    finally:
        server.server_close()


def _ensure_ai_key_if_needed(selected_layers: list[str]) -> list[str]:
    need_ai = any(x in selected_layers for x in ("ai-m", "ai-t"))
    if not need_ai:
        return selected_layers

    api_key = _run("printenv OPENAI_API_KEY")
    if api_key:
        return selected_layers

    print(f"\n{T('ai_key_needed')}")
    typed = input(T("ai_key_prompt")).strip()
    if not typed:
        print(T("ai_skip"))
        return [x for x in selected_layers if x not in {"ai-m", "ai-t"}]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "OPENAI_API_KEY.txt").write_text(typed + "\n", encoding="utf-8")
    print(T("ai_key_saved"))
    return selected_layers


def print_next_steps(selected_layers: list[str], env: dict[str, Any]) -> None:
    selected = set(selected_layers)
    steps: list[str] = []
    if "layer2" in selected:
        steps.append(T("next_step_docker"))
    if "layer1" in selected:
        steps.append(T("next_step_tailscale"))
        if env.get("os_type") != "mac":
            steps.append(T("next_step_iptables"))
    if {"layer3", "layer5", "layer6", "ai-m", "ai-t"} & selected:
        steps.append(T("next_step_config"))
    if "layer4" in selected:
        steps.append(T("next_step_infisical"))
    if "layer7" in selected and env.get("os_type") != "mac":
        steps.append(T("next_step_falco"))
    steps.append(T("next_step_guide"))

    print(f"\n{T('next_steps_heading')}")
    for i, step in enumerate(steps, start=1):
        print(f"  {i}. {step}")


def run_terminal_mode() -> None:
    print("=== Moat — AI Security for self-hosted agents ===")
    print(f"Version: {VERSION}")
    print(f"\n{T('detecting')}")
    env = detect_env()
    rec = recommend_layers(env)
    print_env_summary(env)

    selected_layers = select_layers_terminal(env, rec)
    if selected_layers is None:
        print(T("quit_done"))
        return

    selected_layers = _ensure_ai_key_if_needed(selected_layers)
    approval_level = choose_approval_level()

    files = generate_files(selected_layers, approval_level, env)

    print(f"\n{T('gen_done')}")
    for item in files:
        print(f"  - output/{item['name']} ({item['layer']})")

    print_next_steps(selected_layers, env)



def main() -> None:
    parser = argparse.ArgumentParser(description="Moat — AI Security for self-hosted agents")
    parser.add_argument("--web", action="store_true", help="Browser mode (localhost:8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--update", action="store_true", help="Update setup.py to latest version")
    parser.add_argument("--update-rules", action="store_true", help="Update security rules only")
    parser.add_argument("--lang", default="", help="UI language: en/ja/zh/ko/de/es/pt (default: auto-detect)")
    args = parser.parse_args()

    global CURRENT_LANG
    lang = (args.lang or "").strip().lower()[:2] if args.lang else ""
    CURRENT_LANG = lang if lang in STRINGS.get("env_heading", {}) else _detect_lang()

    if args.update:
        self_update()
        return
    if args.update_rules:
        update_rules()
        return
    if args.web:
        run_web_mode(8765, no_browser=args.no_browser)
        return

    run_terminal_mode()


if __name__ == "__main__":
    main()
