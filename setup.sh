#!/bin/bash
# Webセキュリティ診断ツール セットアップスクリプト（Mac/Linux用）

set -e

echo "========================================"
echo "Webセキュリティ診断ツール セットアップ"
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

echo "1. Python インストール確認中..."
if command -v python3 &> /dev/null; then
    success "Python が見つかりました"
    python3 --version
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    success "Python が見つかりました"
    python --version
    PYTHON_CMD="python"
else
    error "Python が見つかりません"
    echo ""
    echo "Python をインストールしてください:"
    echo "macOS: brew install python3"
    echo "Ubuntu: sudo apt-get install python3 python3-pip"
    echo "または https://www.python.org/downloads/ からダウンロード"
    exit 1
fi

echo ""
echo "2. pip の確認..."
if command -v pip3 &> /dev/null; then
    success "pip3 が見つかりました"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    success "pip が見つかりました"
    PIP_CMD="pip"
else
    error "pip が見つかりません"
    echo "pip をインストールしてください"
    exit 1
fi

echo ""
echo "3. 仮想環境作成中..."
if [ -d "venv" ]; then
    success "仮想環境は既に存在します"
else
    $PYTHON_CMD -m venv venv
    success "仮想環境を作成しました"
fi

echo ""
echo "4. 仮想環境を有効化中..."
source venv/bin/activate
success "仮想環境を有効化しました"

echo ""
echo "5. 必要なライブラリをインストール中..."
echo "   （初回は数分かかる場合があります）"
pip install -r requirements.txt --quiet
success "ライブラリのインストールが完了しました"

echo ""
echo "6. ChromeDriver の確認..."
if command -v chromedriver &> /dev/null; then
    success "ChromeDriver が見つかりました"
else
    warning "ChromeDriver が見つかりません"
    echo ""
    echo "ChromeDriver を自動ダウンロード中..."

    # OS判定
    OS_TYPE="unknown"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="mac64"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux64"
    fi

    if [ "$OS_TYPE" != "unknown" ]; then
        python3 -c "
import requests
import zipfile
import os
import stat
from pathlib import Path

try:
    # 最新バージョン取得
    response = requests.get('https://chromedriver.storage.googleapis.com/LATEST_RELEASE')
    version = response.text.strip()

    # ダウンロード
    os_type = '$OS_TYPE'
    url = f'https://chromedriver.storage.googleapis.com/{version}/chromedriver_{os_type}.zip'
    response = requests.get(url)

    # 保存・展開
    with open('chromedriver.zip', 'wb') as f:
        f.write(response.content)

    with zipfile.ZipFile('chromedriver.zip', 'r') as zip_ref:
        zip_ref.extractall('.')

    os.remove('chromedriver.zip')

    # 実行権限付与
    chromedriver_path = Path('chromedriver')
    if chromedriver_path.exists():
        st = os.stat(chromedriver_path)
        os.chmod(chromedriver_path, st.st_mode | stat.S_IEXEC)
        print('✓ ChromeDriver のダウンロードが完了しました')
    else:
        print('❌ ChromeDriver のダウンロードに失敗しました')

except Exception as e:
    print(f'❌ ChromeDriver のダウンロードに失敗しました: {e}')
    print('手動でダウンロードしてください:')
    print('https://chromedriver.chromium.org/')
"
    else
        warning "自動ダウンロードできません。手動でダウンロードしてください:"
        echo "https://chromedriver.chromium.org/"
    fi
fi

echo ""
echo "7. 設定ファイルの確認..."
if [ -f ".env" ]; then
    success "環境設定ファイル（.env）が存在します"
else
    if [ -f "env.example" ]; then
        cp env.example .env
        success "環境設定ファイル（.env）を作成しました"
        echo "   必要に応じて .env ファイルを編集してAPIキーを設定してください"
    else
        warning "環境設定ファイルのテンプレートが見つかりません"
    fi
fi

echo ""
echo "========================================"
echo "セットアップ完了！"
echo "========================================"
echo ""
echo "次の手順:"
echo "1. targets.csv ファイルに診断したいURLを記入"
echo "2. ./run.sh を実行して診断開始"
echo ""
echo "詳細な使用方法は以下のファイルを参照:"
echo "- README.md"
echo "- docs/20250918_非エンジニア向け使用ガイド_v1.md"
echo ""
