#!/bin/bash
# Webセキュリティ診断ツール 実行スクリプト（Mac/Linux用）

set -e

echo "========================================"
echo "Webセキュリティ診断ツール 実行"
echo "========================================"
echo ""

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 成功メッセージ
success() {
    echo -e "${GREEN}✓${NC} $1"
}

# エラーメッセージ
error() {
    echo -e "${RED}❌${NC} $1"
}

# 警告メッセージ
warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 仮想環境の確認
if [ ! -d "venv" ]; then
    error "仮想環境が見つかりません"
    echo ""
    echo "先に setup.sh を実行してください:"
    echo "1. ./setup.sh を実行"
    echo "2. セットアップ完了後、再度このスクリプトを実行"
    echo ""
    exit 1
fi

# 仮想環境有効化
echo "仮想環境を有効化中..."
source venv/bin/activate
success "仮想環境を有効化しました"

# 診断対象ファイルの確認
if [ ! -f "targets.csv" ]; then
    error "targets.csv ファイルが見つかりません"
    echo ""
    echo "targets.csv ファイルを作成してください:"
    echo ""
    echo "--- targets.csv の例 ---"
    echo "url,site_name,priority,notes"
    echo "https://example.com,サンプルサイト,高,重要サイト"
    echo "https://test.com,テストサイト,中,開発環境"
    echo "----------------------"
    echo ""
    echo "上記の内容でファイルを作成し、診断したいURLに変更してください。"
    echo ""
    exit 1
fi

echo "targets.csv の内容を確認中..."
echo ""
echo "--- 診断対象URL ---"
cat targets.csv
echo ""
echo "------------------"
echo ""

read -p "上記のURLで診断を開始しますか？ (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "診断をキャンセルしました。"
    echo "targets.csv を編集してから再度実行してください。"
    exit 0
fi

echo ""
echo "診断を開始します..."
echo "結果は output フォルダに保存されます。"
echo ""

# 出力ディレクトリ作成
mkdir -p output

# 現在時刻取得（ファイル名用）
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Python パス設定
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# 診断実行
if python -m src.main targets.csv -o "output/result_${TIMESTAMP}"; then
    echo ""
    echo "========================================"
    echo "診断完了！"
    echo "========================================"
    echo ""
    echo "結果ファイル:"
    ls -la "output/result_${TIMESTAMP}/"
    echo ""
    echo "詳細は output/result_${TIMESTAMP} フォルダを確認してください。"
else
    echo ""
    error "診断中にエラーが発生しました"
    echo ""
    echo "トラブルシューティング:"
    echo "1. インターネット接続を確認"
    echo "2. targets.csv の URL が正しいか確認"
    echo "3. logs/audit.log でエラー詳細を確認"
    exit 1
fi

echo ""
