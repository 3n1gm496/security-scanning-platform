#!/usr/bin/env python3
"""
Quick API verification script to test all implemented features.
"""
import os
import sys
import sqlite3

# Set test database
os.environ["DASHBOARD_DB_PATH"] = "./verify_test.db"

# Import after setting env var
from rbac import init_rbac_tables, create_api_key, Role, list_api_keys
from webhooks import init_webhook_tables, create_webhook, list_webhooks, WebhookEvent
from export import export_to_json, export_to_csv, export_to_sarif, export_to_html

print("=" * 80)
print("VERIFICA FUNZIONALITÀ API")
print("=" * 80)

# 1. Init database
print("\n1. Inizializzazione database...")
init_rbac_tables()
init_webhook_tables()
print("   ✅ Database inizializzato")

# 2. Test RBAC + API Keys
print("\n2. Test RBAC + API Keys...")
key, prefix = create_api_key(name="Test Admin", role=Role.ADMIN, created_by="test")
print(f"   ✅ API Key creata: {prefix}")
keys = list_api_keys()
print(f"   ✅ {len(keys)} API key(s) nel database")

# 3. Test Webhooks
print("\n3. Test Webhooks...")
webhook_id = create_webhook(
    name="Test Webhook",
    url="https://example.com/hook",
    events=[WebhookEvent.SCAN_COMPLETED],
    secret="test_secret"
)
print(f"   ✅ Webhook creato: ID {webhook_id}")
webhooks = list_webhooks()
print(f"   ✅ {len(webhooks)} webhook(s) nel database")

# 4. Test Export
print("\n4. Test Export multi-format...")
test_findings = [
    {
        "id": 1,
        "tool": "trivy",
        "severity": "critical",
        "message": "Test vulnerability",
        "target": "container:test"
    }
]

json_export = export_to_json(test_findings)
print(f"   ✅ Export JSON: {len(json_export)} caratteri")

csv_export = export_to_csv(test_findings)
print(f"   ✅ Export CSV: {len(csv_export)} caratteri")

sarif_export = export_to_sarif(test_findings)
print(f"   ✅ Export SARIF: {len(sarif_export)} caratteri")

html_export = export_to_html(test_findings)
print(f"   ✅ Export HTML: {len(html_export)} caratteri")

# Cleanup
os.unlink("./verify_test.db")

print("\n" + "=" * 80)
print("✅ TUTTE LE FUNZIONALITÀ VERIFICATE CON SUCCESSO!")
print("=" * 80)
sys.exit(0)
