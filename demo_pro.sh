#!/bin/bash
# Hashcat Mode Detector Pro - デモスクリプト

echo "============================================"
echo " Hashcat Mode Detector Pro - デモ"
echo "============================================"
echo ""

echo "【1】基本的な使い方"
echo "   ./hashcat_pro.py <ハッシュ値>"
echo ""
python3 hashcat_pro.py "5f4dcc3b5aa765d61d8327deb882cf99"

echo ""
echo "============================================"
echo ""
read -p "[Enter] で次へ..."

echo "【2】詳細モード（CTFヒント表示）"
echo "   ./hashcat_pro.py -d <ハッシュ値>"
echo ""
python3 hashcat_pro.py -d "5f4dcc3b5aa765d61d8327deb882cf99"

echo ""
echo "============================================"
echo ""
read -p "[Enter] で次へ..."

echo "【3】異なるハッシュタイプの例"
echo ""

echo "▶ SHA-1"
python3 hashcat_pro.py "356a192b7913b04c54574d18c28d46e6395428ab"

echo ""
read -p "[Enter] で次へ..."

echo "▶ sha512crypt (Linux)"
python3 hashcat_pro.py '$6$rounds=5000$salt$hash...'

echo ""
read -p "[Enter] で次へ..."

echo "▶ bcrypt (WordPress等)"
python3 hashcat_pro.py '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'

echo ""
echo "============================================"
echo ""
read -p "[Enter] で次へ..."

echo "【4】ファイルから読み込み"
echo "   ./hashcat_pro.py -f sample_hashes_ctf.txt -d"
echo ""
echo "サンプルハッシュファイルの内容:"
cat sample_hashes_ctf.txt | head -20
echo ""

echo "============================================"
echo ""
echo "【5】よく使うCTFハッシュタイプ"
echo "============================================"
echo ""
echo "最頻出:"
echo "  - MD5 (mode 0): 32文字16進数"
echo "  - SHA-1 (mode 100): 40文字16進数"
echo "  - SHA-256 (mode 1400): 64文字16進数"
echo "  - NTLM (mode 1000): Windows認証"
echo ""
echo "Unix/Linux系:"
echo "  - sha512crypt (mode 1800): $6$ で始まる"
echo "  - md5crypt (mode 500): $1$ で始まる"
echo "  - bcrypt (mode 3200): $2a$ で始まる"
echo ""
echo "Web系:"
echo "  - phpass (mode 400): WordPress等"
echo "  - Django (mode 10000): Pythonフレームワーク"
echo "  - JWT (mode 16500): Web認証トークン"
echo ""
echo "ネットワーク系:"
echo "  - NetNTLMv2 (mode 5600): Windows認証"
echo "  - WPA/WPA2 (mode 22000): Wi-Fi"
echo ""

echo "============================================"
echo ""
echo "【6】CTF攻略の基本フロー"
echo "============================================"
echo ""
echo "Step 1: ハッシュタイプを特定"
echo "  ./hashcat_pro.py -d <hash>"
echo ""
echo "Step 2: 適切な攻撃方法を選択"
echo "  高速ハッシュ → 辞書攻撃"
echo "  低速ハッシュ → マスク攻撃で短いパスワードから"
echo ""
echo "Step 3: hashcatで実行"
echo "  hashcat -m <mode> -a 0 hash.txt rockyou.txt"
echo ""
echo "Step 4: ルール適用で変換パターンを試す"
echo "  hashcat -m <mode> -a 0 hash.txt rockyou.txt -r best64.rule"
echo ""

echo "============================================"
echo " デモ終了"
echo "============================================"
echo ""
echo "詳細は README_hashcat_pro.md を参照してください"
echo ""
