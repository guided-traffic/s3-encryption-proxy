#!/bin/bash

# Renovate Token Setup Script
# Dieses Script hilft beim Setup des RENOVATE_TOKEN Secrets

echo "🔧 Renovate Token Setup für s3-encryption-proxy"
echo "================================================"
echo ""

echo "📝 Schritt 1: Personal Access Token erstellen"
echo "1. Gehe zu: https://github.com/settings/tokens/new"
echo "2. Token Name: 'Renovate Bot - s3-encryption-proxy'"
echo "3. Expiration: 1 year (oder gewünschte Dauer)"
echo "4. Wähle folgende Scopes:"
echo "   ✓ repo (Full control of private repositories)"
echo "   ✓ workflow (Update GitHub Action workflows)"
echo "   ✓ admin:repo_hook (Repository hooks)"
echo ""

echo "📋 Schritt 2: Token als Secret hinzufügen"
echo "1. Gehe zu: https://github.com/guided-traffic/s3-encryption-proxy/settings/secrets/actions"
echo "2. Klicke 'New repository secret'"
echo "3. Name: RENOVATE_TOKEN"
echo "4. Value: [Dein erstellter Token]"
echo ""

echo "🚀 Schritt 3: Workflow testen"
echo "1. Gehe zu: https://github.com/guided-traffic/s3-encryption-proxy/actions"
echo "2. Wähle 'Renovate' Workflow"
echo "3. Klicke 'Run workflow'"
echo "4. Wähle 'debug' als Log Level für ersten Test"
echo ""

echo "✅ Nach erfolgreichem Setup wird Renovate:"
echo "   • Täglich um 2:00 UTC nach Updates suchen"
echo "   • Patch Updates automatisch mergen"
echo "   • Major Updates zur manuellen Überprüfung erstellen"
echo "   • Ein Dependency Dashboard Issue erstellen"
echo ""

echo "📚 Weitere Informationen: .github/RENOVATE_SETUP.md"
