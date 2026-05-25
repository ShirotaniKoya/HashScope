# Hashcat Mode Detector Pro - CTF Edition

ハッシュ値からhashcatのハッシュモードを自動判定し、CTF攻略に役立つ詳細情報を提供する高機能ツール

## 🎯 特徴

### 基本機能
- ✅ **数百種類のハッシュタイプに対応** - 主要なハッシュアルゴリズムを網羅
- ✅ **優先度による自動ソート** - よく使われるタイプを優先表示（⭐マーク）
- ✅ **クラック速度の目安** - 高速/中速/低速/非常に低速で表示
- ✅ **用途説明** - 各ハッシュが何に使われるかを説明
- ✅ **CTFヒント** - 詳細モードでCTF攻略のヒントを表示

### 入力方法
- 📝 **コマンドライン引数** - 単一ハッシュを直接指定
- 📄 **ファイル読み込み** - 複数ハッシュの一括処理
- 💬 **インタラクティブモード** - 対話的にハッシュを入力

### CTF特化機能
- 💡 **CTFクイックガイド** - ハッシュタイプに応じた攻略アドバイス
- 🎓 **詳細説明モード** - 背景知識とCTFでの出現パターン
- ⚡ **攻撃方法の提案** - 辞書攻撃/マスク攻撃の使い分けガイド

## 📦 インストール

依存関係なし（Python 3標準ライブラリのみ使用）

```bash
# 実行権限を付与
chmod +x hashcat_pro.py
```

## 🚀 使用方法

### 基本的な使い方

```bash
# 単一ハッシュを判定
./hashcat_pro.py 5f4dcc3b5aa765d61d8327deb882cf99

# または
python3 hashcat_pro.py 5f4dcc3b5aa765d61d8327deb882cf99
```

**出力例:**
```
🔍 検出された可能性のあるハッシュタイプ: 5件

⭐ [1] モード 0: MD5
    説明: 32文字の16進数
    クラック速度: 高速
    📌 用途: 最も一般的なハッシュ。Webアプリ、パスワード保存、ファイル整合性チェックなど幅広く使用
    コマンド例:
      hashcat -m 0 -a 0 hash.txt rockyou.txt
```

### 詳細モード（CTFヒント表示）

```bash
# -d または --detail オプション
./hashcat_pro.py -d e10adc3949ba59abbe56e057f20f883e
```

**詳細モードの出力例:**
```
⭐ [1] モード 0: MD5
    説明: 32文字の16進数
    クラック速度: 高速
    📌 用途: 最も一般的なハッシュ。Webアプリ、パスワード保存、ファイル整合性チェックなど幅広く使用
    💡 CTFヒント: CTFで最頻出。辞書攻撃やレインボーテーブルが有効。
                  online MD5データベースで即座に解読できる場合も多い
    コマンド例:
      hashcat -m 0 -a 0 hash.txt rockyou.txt
```

### ファイルから読み込み

```bash
# ファイルに保存されたハッシュを解析
./hashcat_pro.py -f hashes.txt

# 詳細モード
./hashcat_pro.py -f hashes.txt -d
```

**ファイル形式例（hashes.txt）:**
```
# コメント行は無視されます
5f4dcc3b5aa765d61d8327deb882cf99
356a192b7913b04c54574d18c28d46e6395428ab
$1$salt$qJH7.N4xYta3aEG/dfqo/0
$6$rounds=5000$salt$hash...
```

### 全候補を表示

```bash
# デフォルトは上位3件のみ表示
# --all オプションで全候補を表示
./hashcat_pro.py --all 5f4dcc3b5aa765d61d8327deb882cf99
```

### インタラクティブモード

```bash
# 引数なしで起動
./hashcat_pro.py
```

**インタラクティブモードのコマンド:**
```
Hash> 5f4dcc3b5aa765d61d8327deb882cf99
[検出結果が表示される]

Hash> detail
詳細モード: ON

Hash> all
全候補表示: ON

Hash> file hashes.txt
[ファイルから読み込み]

Hash> exit
終了します。
```

## 📚 対応ハッシュタイプ（主要なもの）

### Raw Hash（生ハッシュ）
| モード | 名前 | 特徴 | CTF頻出度 |
|-------|------|------|----------|
| 0 | MD5 | 32文字、最頻出 | ⭐⭐⭐⭐⭐ |
| 100 | SHA-1 | 40文字、Git等で使用 | ⭐⭐⭐⭐⭐ |
| 1400 | SHA-256 | 64文字、現代標準 | ⭐⭐⭐⭐⭐ |
| 1700 | SHA-512 | 128文字、高強度 | ⭐⭐⭐⭐ |
| 1000 | NTLM | Windows認証 | ⭐⭐⭐⭐ |

### Unix/Linux Password
| モード | 名前 | 特徴 | CTF頻出度 |
|-------|------|------|----------|
| 500 | md5crypt | $1$ で始まる | ⭐⭐⭐⭐ |
| 1800 | sha512crypt | $6$ で始まる、最も強力 | ⭐⭐⭐⭐⭐ |
| 7400 | sha256crypt | $5$ で始まる | ⭐⭐⭐ |
| 3200 | bcrypt | $2a$ で始まる、非常に遅い | ⭐⭐⭐⭐ |

### Web Application
| モード | 名前 | 特徴 | CTF頻出度 |
|-------|------|------|----------|
| 400 | phpass | WordPress等、$P$ で始まる | ⭐⭐⭐⭐ |
| 10000 | Django PBKDF2 | pbkdf2_sha256$ で始まる | ⭐⭐⭐ |
| 7900 | Drupal7 | $S$ で始まる | ⭐⭐⭐ |

### Network Protocol
| モード | 名前 | 特徴 | CTF頻出度 |
|-------|------|------|----------|
| 5600 | NetNTLMv2 | Windows認証、長い形式 | ⭐⭐⭐⭐ |
| 13100 | Kerberos TGS | $krb5tgs$ で始まる | ⭐⭐⭐ |
| 22000 | WPA/WPA2 | WPA* で始まる、Wi-Fi | ⭐⭐⭐⭐ |

### Archive/Document
| モード | 名前 | 特徴 | CTF頻出度 |
|-------|------|------|----------|
| 11600 | 7-Zip | $7z$ で始まる | ⭐⭐⭐ |
| 9800 | MS Office 2007+ | $office$ で始まる | ⭐⭐⭐ |
| 10600 | PDF 1.7 | $pdf$ で始まる | ⭐⭐⭐ |

### Modern Formats
| モード | 名前 | 特徴 | CTF頻出度 |
|-------|------|------|----------|
| 16500 | JWT | eyで始まる3部構成 | ⭐⭐⭐⭐⭐ |

## 🎓 CTF攻略ガイド

### 1. ハッシュ判定の基本フロー

```bash
# ステップ1: ハッシュタイプを特定
./hashcat_pro.py -d <hash>

# ステップ2: 適切な攻撃方法を選択
# - 高速ハッシュ（MD5, SHA-1等）→ 辞書攻撃から
# - 低速ハッシュ（bcrypt, scrypt等）→ マスク攻撃で短いパスワードから

# ステップ3: hashcatで実行
hashcat -m <mode> -a 0 hash.txt rockyou.txt
```

### 2. よくあるCTFシナリオ

#### シナリオ1: 単純なMD5ハッシュ
```bash
# まずonline MD5データベースで検索
# 例: https://crackstation.net/

# それでダメなら辞書攻撃
hashcat -m 0 -a 0 hash.txt rockyou.txt

# ルールを適用して変換パターンを試す
hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule
```

#### シナリオ2: Linux /etc/shadow
```bash
# sha512cryptの場合
hashcat -m 1800 -a 0 hash.txt rockyou.txt

# 時間がかかる場合、短いパスワードから試す
hashcat -m 1800 -a 3 hash.txt ?a?a?a?a?a?a
```

#### シナリオ3: JWT秘密鍵クラック
```bash
# JWTのハッシュモードは16500
hashcat -m 16500 -a 0 jwt.txt rockyou.txt

# 秘密鍵が単語の場合も多い
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/common.txt
```

### 3. 効率的な攻撃順序

1. **Online データベース検索** （MD5, SHA-1の場合）
   - crackstation.net
   - hashes.com
   - cmd5.org

2. **辞書攻撃**（高速ハッシュ）
   ```bash
   # 基本の辞書攻撃
   hashcat -m 0 -a 0 hash.txt rockyou.txt
   
   # ルール適用
   hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule
   ```

3. **マスク攻撃**（パスワード形式が推測できる場合）
   ```bash
   # 4桁の数字（PINコードなど）
   hashcat -m 0 -a 3 hash.txt ?d?d?d?d
   
   # 6文字の英小文字
   hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l
   
   # flagフォーマット: flag{...}
   hashcat -m 0 -a 3 hash.txt flag{?a?a?a?a?a}
   ```

4. **コンビネーション攻撃**
   ```bash
   # 2つの単語の組み合わせ
   hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt
   ```

### 4. ハッシュタイプ判定のコツ

| 長さ/パターン | 可能性 | 優先順位 |
|-------------|--------|---------|
| 32文字16進数 | MD5, NTLM, MD4 | MD5を最初に試す |
| 40文字16進数 | SHA-1, RIPEMD-160 | SHA-1を最初に試す |
| 64文字16進数 | SHA-256, SHA3-256 | SHA-256を最初に試す |
| $1$... | md5crypt | そのまま |
| $6$... | sha512crypt | そのまま |
| $2a$... | bcrypt | そのまま |
| eyJ... | JWT | そのまま |

## 💡 トラブルシューティング

### Q: 複数のモードが検出される
A: 優先度（⭐マーク）を参考に、または文脈（OS、アプリケーション）から判断してください。
   CTFでは通常、最もシンプルなものが答えです。

### Q: hashcatが遅すぎる
A: 
- GPUを使用していることを確認（`-D 2`）
- ワードリストを絞り込む（rockyou.txtの上位10万行など）
- 低速ハッシュ（bcrypt等）の場合、短いマスク攻撃から試す

### Q: どのワードリストを使えばいい？
A:
- 一般的: rockyou.txt（約14GB、最頻出）
- 小規模テスト: /usr/share/wordlists/common.txt
- CTF特化: CTF専用のワードリスト（flag形式含む）
- 特定分野: SecLists（様々なカテゴリ別）

### Q: ハッシュが検出されない
A:
1. ハッシュ値に余分な空白や改行がないか確認
2. Base64エンコードされている可能性を確認
3. カスタムハッシュや独自実装の可能性
4. 実はハッシュではなく暗号化テキストの可能性

## 🔧 オプション一覧

```
usage: hashcat_pro.py [-h] [-f FILE] [-d] [--all] [hash]

positional arguments:
  hash                  判定するハッシュ値

optional arguments:
  -h, --help            ヘルプを表示
  -f FILE, --file FILE  ハッシュ値が記載されたファイルを指定
  -d, --detail          詳細情報とCTFヒントを表示
  --all                 全ての候補を表示（デフォルトは上位3件）
```

## 📖 実用例

### 例1: CTF問題でハッシュを発見
```bash
$ cat password.txt
5f4dcc3b5aa765d61d8327deb882cf99

$ ./hashcat_pro.py -d $(cat password.txt)
⭐ [1] モード 0: MD5
💡 CTFヒント: CTFで最頻出。辞書攻撃やレインボーテーブルが有効

$ hashcat -m 0 -a 0 password.txt rockyou.txt
# password が見つかる
```

### 例2: 複数のハッシュを一括処理
```bash
$ ./hashcat_pro.py -f dump.txt -d
# 各ハッシュについて詳細情報とCTFヒントが表示される
```

### 例3: 不明なハッシュの調査
```bash
$ ./hashcat_pro.py --all "unknown_hash_here"
# 全ての可能性を表示して、手がかりを探る
```

## 🎯 CTFでの使用パターン

### パターン1: Web問題
```
1. SQLインジェクションでハッシュを取得
2. hashcat_pro.py で判定 → たいていMD5かSHA-1
3. online MD5データベースで即座にクラック
4. または rockyou.txt で辞書攻撃
```

### パターン2: Forensics問題
```
1. /etc/shadow や SAM ファイルを発見
2. hashcat_pro.py で判定 → sha512crypt or NTLM
3. 適切なモードでhashcat実行
4. ユーザー名がヒントになっている場合も
```

### パターン3: Crypto問題
```
1. カスタムハッシュアルゴリズムの場合も
2. hashcat_pro.py で標準的なものか確認
3. 該当なければスクリプトで実装が必要
```

## 🚀 高度な使い方

### カスタムワードリストの作成
```bash
# CTFのテーマに沿ったワードリスト作成
cewl https://target-site.com -m 5 -w custom.txt

# 既存リストと組み合わせ
cat rockyou.txt custom.txt > combined.txt

# hashcatで使用
hashcat -m 0 -a 0 hash.txt combined.txt
```

### ルールの活用
```bash
# 基本的な変換ルール
hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule

# 複数のルールを適用
hashcat -m 0 -a 0 hash.txt rockyou.txt -r rules/best64.rule -r rules/toggles1.rule
```

## 📝 ライセンス

このツールは教育目的で作成されています。
自己の管理するシステムまたは許可された範囲でのみ使用してください。

## 🔗 参考リンク

- [Hashcat公式サイト](https://hashcat.net/hashcat/)
- [Hashcatモード一覧](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Hashcat公式Wiki](https://hashcat.net/wiki/)
- [CrackStation](https://crackstation.net/) - Online Hash Database
- [SecLists](https://github.com/danielmiessler/SecLists) - ワードリスト集

## 📊 更新履歴

- v2.0: CTF Edition - 用途説明、CTFヒント追加
- v1.0: 初版リリース
