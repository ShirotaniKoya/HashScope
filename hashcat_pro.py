#!/usr/bin/env python3
"""
Hashcat Mode Detector Pro - CTF Edition
ハッシュ値からhashcatのハッシュモードを自動判定し、詳細情報を提供するツール

Features:
- 数百種類のハッシュタイプに対応
- 用途・背景情報の表示
- CTF向けのヒント
- ファイル/ペースト両対応
"""

import re
import sys
import argparse
from typing import List, Tuple, Dict, Optional
from pathlib import Path

class HashInfo:
    """ハッシュ情報クラス"""
    def __init__(self, mode: int, name: str, pattern: str, 
                 description: str, usage: str = "", 
                 ctf_tips: str = "", speed: str = "中速"):
        self.mode = mode
        self.name = name
        self.pattern = pattern
        self.description = description
        self.usage = usage  # 用途
        self.ctf_tips = ctf_tips  # CTFでのヒント
        self.speed = speed

class HashcatModeDetectorPro:
    """ハッシュ値からhashcatモードを検出（プロ版）"""
    
    def __init__(self):
        self.hash_database = self._build_hash_database()
        self.priority_modes = {
            0: 10,      # MD5 - 最高優先度
            100: 10,    # SHA-1 - 最高優先度
            1400: 10,   # SHA-256 - 最高優先度
            1000: 9,    # NTLM - 高優先度
            1800: 9,    # sha512crypt - 高優先度
            3200: 9,    # bcrypt - 高優先度
            5600: 8,    # NetNTLMv2
            22000: 8,   # WPA new format
            500: 8,     # md5crypt
            1700: 8,    # SHA-512
            16: 7,      # md5(md5($pass)) - MD5より低い
            900: 3,     # MD4 - 低優先度（レガシー）
            3000: 2,    # LM - 最低優先度（レガシー）
        }
    
    def _build_hash_database(self) -> List[HashInfo]:
        """ハッシュデータベースを構築"""
        return [
            # === Raw Hash ===
            HashInfo(
                0, "MD5", r"^[a-fA-F0-9]{32}$",
                "32文字の16進数",
                "最も一般的なハッシュ。Webアプリ、パスワード保存、ファイル整合性チェックなど幅広く使用",
                "CTFで最頻出。辞書攻撃やレインボーテーブルが有効。online MD5データベースで即座に解読できる場合も多い",
                "高速"
            ),
            HashInfo(
                100, "SHA1", r"^[a-fA-F0-9]{40}$",
                "40文字の16進数",
                "Git、証明書、レガシーシステムで使用。MD5より強力だが現在は非推奨",
                "CTFで頻出。MD5同様、辞書攻撃が有効。Git関連の問題で見かけることも",
                "高速"
            ),
            HashInfo(
                1400, "SHA2-256", r"^[a-fA-F0-9]{64}$",
                "64文字の16進数",
                "現代的な標準ハッシュ。Bitcoin、TLS証明書、多くのアプリケーションで使用",
                "CTFで頻出。強度が高いため辞書攻撃でも時間がかかる場合あり。ただしパスワードが単純なら突破可能",
                "高速"
            ),
            HashInfo(
                1700, "SHA2-512", r"^[a-fA-F0-9]{128}$",
                "128文字の16進数",
                "SHA-256より強力。サーバー、暗号通貨、セキュアストレージで使用",
                "CTFでも出現。計算コストは高いが単純なパスワードなら突破可能",
                "高速"
            ),
            HashInfo(
                900, "MD4", r"^[a-fA-F0-9]{32}$",
                "32文字の16進数（MD5と同じ長さ）",
                "古いWindows認証（NTLM v1）で使用。現在は非推奨。⚠️注意: MD5/NTLMと形式が同一",
                "レガシーシステムの問題で出現。MD5より脆弱。現代では稀",
                "高速"
            ),
            HashInfo(
                1000, "NTLM", r"^[a-fA-F0-9]{32}$",
                "32文字の16進数（MD5と同じ長さ）",
                "Windows認証で使用。Active Directory、SMB、RDPなどで見られる",
                "CTFのWindows系問題で頻出。Pass-the-Hash攻撃の対象にもなる",
                "高速"
            ),
            HashInfo(
                3000, "LM", r"^[a-fA-F0-9]{32}$",
                "32文字の16進数",
                "古いWindows認証（Windows XP以前）。非常に脆弱。⚠️注意: MD5/NTLM/MD4と形式が同一",
                "レガシーシステム問題で出現。14文字まで、大文字小文字の区別なし。実際のLMハッシュかどうかは文脈で判断が必要（特徴: AAD3B435B51404EEが空パスワード）",
                "高速"
            ),
            
            # === Salted Hash ===
            HashInfo(
                10, "md5($pass.$salt)", r"^[a-fA-F0-9]{32}:[^:]+$",
                "MD5 with salt (パスワード:ソルト順)",
                "ソルト付きMD5。一部のWebアプリケーションで使用",
                "ソルトにより辞書攻撃の効果が下がるが、ソルトが判明していれば攻撃可能",
                "高速"
            ),
            HashInfo(
                20, "md5($salt.$pass)", r"^[a-fA-F0-9]{32}:[^:]+$",
                "MD5 with salt (ソルト:パスワード順)",
                "ソルト付きMD5（順序逆）。WordPress、Joomlaなどで使用",
                "mode 10と同様だが順序が逆。両方試すことを推奨",
                "高速"
            ),
            HashInfo(
                110, "sha1($pass.$salt)", r"^[a-fA-F0-9]{40}:[^:]+$",
                "SHA1 with salt",
                "ソルト付きSHA-1",
                "ソルトありでもSHA-1の脆弱性は変わらない",
                "高速"
            ),
            HashInfo(
                120, "sha1($salt.$pass)", r"^[a-fA-F0-9]{40}:[^:]+$",
                "SHA1 with salt (reversed)",
                "ソルト付きSHA-1（順序逆）",
                "mode 110と順序が逆",
                "高速"
            ),
            HashInfo(
                1410, "sha256($pass.$salt)", r"^[a-fA-F0-9]{64}:[^:]+$",
                "SHA256 with salt",
                "ソルト付きSHA-256",
                "より強固だがソルトが既知なら攻撃可能",
                "高速"
            ),
            HashInfo(
                1420, "sha256($salt.$pass)", r"^[a-fA-F0-9]{64}:[^:]+$",
                "SHA256 with salt (reversed)",
                "ソルト付きSHA-256（順序逆）",
                "mode 1410と順序が逆",
                "高速"
            ),
            
            # === Unix Crypt ===
            HashInfo(
                500, "md5crypt", r"^\$1\$[^$]+\$[A-Za-z0-9./]{22}$",
                "$1$ で始まるMD5 crypt",
                "古いUnix/Linuxシステムのパスワード。/etc/shadowで使用",
                "CTFのLinux系問題で出現。1000回のMD5反復で強化されている",
                "中速"
            ),
            HashInfo(
                1800, "sha512crypt", r"^\$6\$",
                "$6$ で始まるSHA512 crypt",
                "現代的なUnix/Linuxのパスワード。/etc/shadowで標準的に使用",
                "CTFで頻出。5000回以上の反復で非常に強固。辞書攻撃には時間がかかる",
                "低速"
            ),
            HashInfo(
                7400, "sha256crypt", r"^\$5\$",
                "$5$ で始まるSHA256 crypt",
                "Unix/Linuxのパスワード（SHA-256版）",
                "sha512cryptより少し弱いが依然として強固",
                "低速"
            ),
            HashInfo(
                3200, "bcrypt", r"^\$2[axyb]?\$\d{2}\$[A-Za-z0-9./]{53}$",
                "$2a$, $2b$, $2x$, $2y$ で始まるbcrypt",
                "WordPress、多くのモダンWebアプリで使用。意図的に遅い設計",
                "CTFで出現。計算コストが非常に高く、辞書攻撃でも時間がかかる。costパラメータに注意",
                "非常に低速"
            ),
            HashInfo(
                1500, "descrypt", r"^[A-Za-z0-9./]{13}$",
                "13文字のUnix DES crypt",
                "非常に古いUnixパスワード。1970年代から使用",
                "レガシーシステム問題で出現。非常に脆弱、8文字まで",
                "高速"
            ),
            
            # === Database Hash ===
            HashInfo(
                12, "PostgreSQL", r"^[a-fA-F0-9]{32}:[^:]+$",
                "PostgreSQL MD5",
                "PostgreSQLデータベースのパスワード",
                "データベース関連のCTF問題で出現",
                "高速"
            ),
            HashInfo(
                131, "MSSQL(2000)", r"^0x0100[a-fA-F0-9]{8}[a-fA-F0-9]{40}$",
                "0x0100 で始まる",
                "Microsoft SQL Server 2000のパスワード",
                "古いMSSQLサーバーの問題で出現",
                "高速"
            ),
            HashInfo(
                132, "MSSQL(2005)", r"^0x0100[a-fA-F0-9]{8}[a-fA-F0-9]{40}$",
                "0x0100 で始まる",
                "Microsoft SQL Server 2005のパスワード",
                "MSSQL関連問題で出現",
                "高速"
            ),
            HashInfo(
                1731, "MSSQL(2012/2014)", r"^0x02[a-fA-F0-9]+$",
                "0x02 で始まる",
                "Microsoft SQL Server 2012/2014のパスワード",
                "新しいMSSQLサーバーの問題で出現",
                "低速"
            ),
            HashInfo(
                3100, "Oracle H", r"^[a-fA-F0-9]{16}:[a-fA-F0-9]{16}$",
                "16:16 形式 (Oracle 10g)",
                "Oracle Database 10gのパスワード",
                "データベース関連のCTF問題で出現",
                "高速"
            ),
            HashInfo(
                200, "MySQL323", r"^[a-fA-F0-9]{16}$",
                "16文字の16進数",
                "MySQL 3.2.3のパスワード（非常に古い）",
                "レガシーMySQL問題で出現。非常に脆弱",
                "高速"
            ),
            HashInfo(
                300, "MySQL4.1/MySQL5", r"^\*[a-fA-F0-9]{40}$",
                "*で始まる41文字",
                "MySQL 4.1以降のパスワード",
                "MySQL関連のCTF問題で頻出",
                "高速"
            ),
            
            # === Application Hash ===
            HashInfo(
                400, "phpass", r"^\$P\$[A-Za-z0-9./]{31}$",
                "$P$ で始まる (WordPress等)",
                "WordPress、phpBB等で使用される強化MD5",
                "CTFのWeb問題で頻出。反復回数により強度が変わる",
                "中速"
            ),
            HashInfo(
                11, "Joomla < 2.5.18", r"^[a-fA-F0-9]{32}:[A-Za-z0-9]{16,32}$",
                "MD5:salt形式",
                "古いJoomla CMSのパスワード",
                "CMS関連のCTF問題で出現",
                "高速"
            ),
            HashInfo(
                2611, "vBulletin < v3.8.5", r"^[a-fA-F0-9]{32}:[A-Za-z0-9]{3}$",
                "MD5:3文字salt",
                "古いvBulletin掲示板のパスワード",
                "フォーラムソフト関連問題で出現",
                "高速"
            ),
            HashInfo(
                7900, "Drupal7", r"^\$S\$[A-Za-z0-9./]{52}$",
                "$S$ で始まるDrupal",
                "Drupal 7 CMSのパスワード",
                "CMS関連のCTF問題で出現",
                "低速"
            ),
            HashInfo(
                124, "Django (SHA-1)", r"^sha1\$[^$]+\$[a-fA-F0-9]{40}$",
                "sha1$ で始まるDjango",
                "Django Webフレームワークのパスワード（古いバージョン）",
                "Pythonベースのweb問題で出現",
                "高速"
            ),
            HashInfo(
                10000, "Django (PBKDF2-SHA256)", r"^pbkdf2_sha256\$",
                "pbkdf2_sha256$ で始まる",
                "Django Webフレームワークのパスワード（現行）",
                "モダンなPythonベースのweb問題で出現。PBKDF2で強化",
                "低速"
            ),
            
            # === Network Protocol ===
            HashInfo(
                5500, "NetNTLMv1", 
                r"^[^:]+::[^:]+:[a-fA-F0-9]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$",
                "NetNTLMv1形式",
                "Windows認証プロトコル（古いバージョン）",
                "ネットワーク認証のCTF問題で出現。Pass-the-Hash攻撃の対象",
                "高速"
            ),
            HashInfo(
                5600, "NetNTLMv2",
                r"^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$",
                "NetNTLMv2形式",
                "Windows認証プロトコル（現行）",
                "ネットワーク認証のCTF問題で頻出。Responderなどで取得可能",
                "高速"
            ),
            HashInfo(
                13100, "Kerberos 5 TGS-REP",
                r"^\$krb5tgs\$23\$",
                "$krb5tgs$23$ で始まる",
                "Kerberos認証のチケット。Kerberoasting攻撃の対象",
                "Active Directory関連のCTF問題で出現",
                "中速"
            ),
            HashInfo(
                18200, "Kerberos 5 AS-REP",
                r"^\$krb5asrep\$23\$",
                "$krb5asrep$23$ で始まる",
                "Kerberos認証（AS-REP Roasting攻撃の対象）",
                "Active Directory問題で出現",
                "中速"
            ),
            
            # === Wireless ===
            HashInfo(
                22000, "WPA-PBKDF2-PMKID+EAPOL",
                r"^WPA\*",
                "WPA*で始まる新形式",
                "Wi-Fi WPA/WPA2パスワード（最新形式）",
                "無線LAN関連のCTF問題で出現。hcxdumptoolで取得",
                "低速"
            ),
            HashInfo(
                16800, "WPA-PMKID",
                r"^[a-fA-F0-9]{32}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{12}\*",
                "PMKID形式",
                "Wi-Fi WPA/WPA2パスワード（PMKID攻撃）",
                "クライアントなしでハッシュ取得可能。無線LAN問題で出現",
                "低速"
            ),
            
            # === Modern KDF & Password Hashing ===
            HashInfo(
                10900, "PBKDF2-HMAC-SHA256",
                r"^sha256:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$",
                "sha256: で始まる",
                "PBKDF2-HMAC-SHA256。Django等で使用",
                "Pythonフレームワーク関連で出現",
                "低速"
            ),
            HashInfo(
                12000, "PBKDF2-HMAC-SHA1",
                r"^sha1:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$",
                "sha1: で始まる",
                "PBKDF2-HMAC-SHA1。古いDjango等で使用",
                "Pythonフレームワーク関連で出現",
                "低速"
            ),
            HashInfo(
                12100, "PBKDF2-HMAC-SHA512",
                r"^sha512:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$",
                "sha512: で始まる",
                "PBKDF2-HMAC-SHA512",
                "セキュアなパスワード保存で使用",
                "低速"
            ),
            HashInfo(
                8900, "scrypt",
                r"^SCRYPT:\d+:\d+:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$",
                "SCRYPT: で始まる",
                "scrypt KDF。Litecoin、Tarsnap等で使用",
                "暗号通貨やモダンなシステムで出現。非常に遅い",
                "非常に低速"
            ),
            HashInfo(
                34000, "Argon2",
                r"^\$argon2[id][d]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
                "$argon2 で始まる",
                "Argon2 (id/d)。最新のパスワードハッシング標準。PHC優勝アルゴリズム",
                "CTFで増加中。最も強力なパスワードハッシング。メモリハードで非常に遅い",
                "非常に低速"
            ),
            HashInfo(
                30000, "Python Werkzeug MD5",
                r"^\*md5\$\d+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$",
                "*md5$ で始まる",
                "Python Werkzeug HMAC-MD5",
                "Flaskフレームワーク関連で出現",
                "高速"
            ),
            HashInfo(
                30120, "Python Werkzeug SHA256",
                r"^\*sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
                "*sha256$ で始まる",
                "Python Werkzeug HMAC-SHA256",
                "Flaskフレームワーク関連で出現",
                "高速"
            ),
            HashInfo(
                9200, "Cisco-IOS $8$ (PBKDF2-SHA256)",
                r"^\$8\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$",
                "$8$ で始まる",
                "Cisco Type 8パスワード",
                "ネットワーク機器関連で出現",
                "低速"
            ),
            HashInfo(
                9300, "Cisco-IOS $9$ (scrypt)",
                r"^\$9\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$",
                "$9$ で始まる",
                "Cisco Type 9パスワード",
                "ネットワーク機器関連で出現。最も強力",
                "非常に低速"
            ),
            HashInfo(
                5700, "Cisco-IOS type 4 (SHA256)",
                r"^[a-zA-Z0-9./]{43}$",
                "43文字のCisco Type 4",
                "Cisco Type 4パスワード",
                "ネットワーク機器関連で出現",
                "高速"
            ),
            HashInfo(
                2400, "Cisco-PIX MD5",
                r"^[a-zA-Z0-9./]{16}$",
                "16文字のCisco PIX",
                "古いCisco PIX/ASAファイアウォール",
                "ネットワーク機器関連で出現",
                "高速"
            ),
            HashInfo(
                8800, "Android FDE <= 4.3",
                r"^[a-fA-F0-9]{192}$",
                "192文字の16進数",
                "Android Full Disk Encryption（4.3以前）",
                "モバイルデバイス関連で出現",
                "低速"
            ),
            HashInfo(
                12900, "Android FDE (Samsung DEK)",
                r"^[a-fA-F0-9]{256}$",
                "256文字の16進数",
                "Samsung Androidデバイス暗号化",
                "モバイルデバイス関連で出現",
                "低速"
            ),
            HashInfo(
                13711, "VeraCrypt RIPEMD160 + XTS 512 bit",
                r"^\$veracrypt\$[a-fA-F0-9]+$",
                "$veracrypt$ で始まる",
                "VeraCrypt暗号化コンテナ",
                "ディスク暗号化関連で出現。非常に遅い",
                "非常に低速"
            ),
            HashInfo(
                29411, "VeraCrypt RIPEMD160 + XTS 512 bit",
                r"^\$veracrypt\$[a-fA-F0-9]+\$[a-fA-F0-9]+$",
                "$veracrypt$ で始まる（新形式）",
                "VeraCrypt暗号化コンテナ（新形式）",
                "ディスク暗号化関連で出現。非常に遅い",
                "非常に低速"
            ),
            
            # === Archive/Document ===
            HashInfo(
                11600, "7-Zip",
                r"^\$7z\$",
                "$7z$ で始まる",
                "7-Zipアーカイブのパスワード",
                "暗号化ファイル関連のCTF問題で出現。非常に遅い",
                "非常に低速"
            ),
            HashInfo(
                11600, "7-Zip",
                r"^\$7z\$",
                "$7z$ で始まる",
                "7-Zipアーカイブのパスワード",
                "暗号化ファイル関連のCTF問題で出現。非常に遅い",
                "非常に低速"
            ),
            HashInfo(
                13600, "WinZip",
                r"^\$zip2\$",
                "$zip2$ で始まる",
                "WinZipアーカイブのパスワード",
                "ZIPファイル関連問題で出現",
                "低速"
            ),
            HashInfo(
                9700, "MS Office <= 2003",
                r"^\$oldoffice\$",
                "$oldoffice$ で始まる",
                "古いMicrosoft Officeファイルのパスワード",
                "Office文書関連のCTF問題で出現",
                "中速"
            ),
            HashInfo(
                9800, "MS Office >= 2007",
                r"^\$office\$",
                "$office$ で始まる",
                "現代のMicrosoft Officeファイルのパスワード",
                "Office文書関連のCTF問題で頻出。AES暗号化で強固",
                "非常に低速"
            ),
            HashInfo(
                10400, "PDF 1.1-1.3",
                r"^\$pdf\$1\$",
                "$pdf$1$ で始まる",
                "古いPDFファイルのパスワード",
                "PDF関連問題で出現",
                "中速"
            ),
            HashInfo(
                10500, "PDF 1.4-1.6",
                r"^\$pdf\$2\$",
                "$pdf$2$ で始まる",
                "PDFファイルのパスワード（中期）",
                "PDF関連問題で出現",
                "中速"
            ),
            HashInfo(
                10600, "PDF 1.7",
                r"^\$pdf\$[35]\$",
                "$pdf$3$ または $pdf$5$ で始まる",
                "現代のPDFファイルのパスワード",
                "PDF関連問題で出現。AES暗号化",
                "低速"
            ),
            
            # === Other Modern Formats ===
            HashInfo(
                16500, "JWT (JSON Web Token)",
                r"^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
                "JWT形式",
                "Web認証で広く使用されるトークン",
                "Web API、OAuth関連のCTF問題で頻出。秘密鍵の取得が目的",
                "高速"
            ),
            HashInfo(
                16, "md5(md5($pass))",
                r"^[a-fA-F0-9]{32}$",
                "32文字16進数 (ネストMD5可能性)",
                "二重MD5ハッシュ。一部のフォーラムソフトで使用",
                "通常のMD5と見分けがつかない。両方試すこと",
                "高速"
            ),
            HashInfo(
                23, "Skype",
                r"^[a-fA-F0-9]{32}:[^:]+$",
                "Skype形式",
                "Skypeアカウントのパスワード",
                "Skype関連問題で出現",
                "高速"
            ),
            
            # === Cryptocurrency ===
            HashInfo(
                11300, "Bitcoin/Litecoin wallet.dat",
                r"^\$bitcoin\$",
                "$bitcoin$ で始まる",
                "Bitcoinウォレットファイルのパスワード",
                "暗号通貨関連のCTF問題で出現。非常に遅い",
                "非常に低速"
            ),
            HashInfo(
                15700, "Ethereum Wallet, PBKDF2-HMAC-SHA256",
                r"^\$ethereum\$",
                "$ethereum$ で始まる",
                "Ethereumウォレットのパスワード（PBKDF2版）",
                "暗号通貨関連問題で出現",
                "低速"
            ),
            HashInfo(
                16600, "Ethereum Wallet, SCRYPT",
                r"^\$ethereum\$s\$",
                "$ethereum$s$ で始まる",
                "Ethereumウォレットのパスワード（scrypt版）",
                "暗号通貨関連問題で出現。非常に遅い",
                "非常に低速"
            ),
            
            # Plaintextは別処理するため、ここには含めない
        ]
    
    def detect(self, hash_value: str) -> List[HashInfo]:
        """ハッシュ値から可能性のあるモードを検出"""
        hash_value = hash_value.strip()
        matches = []
        
        for hash_info in self.hash_database:
            if re.match(hash_info.pattern, hash_value):
                priority = self.priority_modes.get(hash_info.mode, 0)
                matches.append((hash_info, priority))
        
        # 優先度でソート
        matches.sort(key=lambda x: (-x[1], x[0].mode))
        
        return [m[0] for m in matches]
    
    def get_hashcat_command(self, hash_info: HashInfo, wordlist: str = "rockyou.txt") -> str:
        """hashcatコマンド例を生成"""
        return f"hashcat -m {hash_info.mode} -a 0 hash.txt {wordlist}"
    
    def print_results(self, hash_value: str, detailed: bool = False, show_all: bool = False):
        """検出結果を表示"""
        matches = self.detect(hash_value)
        
        print(f"\n{'='*80}")
        print(f"ハッシュ値: {hash_value[:70]}{'...' if len(hash_value) > 70 else ''}")
        print(f"{'='*80}\n")
        
        if not matches:
            print("⚠️  一致するハッシュタイプが見つかりませんでした")
            print("   未知の形式か、カスタムハッシュの可能性があります\n")
            return
        
        # Plaintext以外のマッチ
        real_matches = [m for m in matches if m.mode != 99999]
        
        if not real_matches:
            print("このテキストはハッシュ化されていない可能性があります（平文）\n")
            return
        
        print(f"🔍 検出された可能性のあるハッシュタイプ: {len(real_matches)}件\n")
        
        # 表示する件数を決定
        display_count = len(real_matches) if show_all else min(3, len(real_matches))
        
        for i, hash_info in enumerate(real_matches[:display_count], 1):
            priority_mark = "⭐ " if self.priority_modes.get(hash_info.mode, 0) >= 9 else "   "
            
            print(f"{priority_mark}[{i}] モード {hash_info.mode}: {hash_info.name}")
            print(f"    説明: {hash_info.description}")
            print(f"    クラック速度: {hash_info.speed}")
            
            if hash_info.usage:
                print(f"    📌 用途: {hash_info.usage}")
            
            if detailed and hash_info.ctf_tips:
                print(f"    💡 CTFヒント: {hash_info.ctf_tips}")
            
            print(f"    コマンド例:")
            print(f"      {self.get_hashcat_command(hash_info)}")
            print()
        
        if len(real_matches) > display_count:
            print(f"... 他 {len(real_matches) - display_count} 件の候補があります")
            print("    --all オプションで全候補を表示できます\n")
        
        # 一般的なヒント
        if len(real_matches) > 1:
            print("💡 複数の候補:")
            print("   ⭐マークは優先的に試すべきタイプです")
            print("   文脈（OS、アプリケーション、取得元）から判断してください")
            print("   -d/--detail オプションでCTFヒントを表示できます\n")
            
            # 32文字16進数の特別警告
            if re.match(r"^[a-fA-F0-9]{32}$", hash_value):
                print("⚠️  32文字の16進数の注意点:")
                print("   MD5、NTLM、MD4、LMは全て同じ形式です")
                print("   判別のヒント:")
                print("   - Windows環境 → NTLM（最優先）またはLM（古いシステム）")
                print("   - Unix/Web/一般 → MD5（最優先）")
                print("   - LMの特徴: AAD3B435B51404EEは空パスワード")
                print("   - MD4: 現代ではほぼ使われない（NTLM v1のベース）\n")
        
        
        # CTF向けクイックアドバイス
        if not detailed:
            print("💬 CTFクイックガイド:")
            top_match = real_matches[0]
            if top_match.mode in [0, 100, 1400]:
                print("   → このハッシュは高速なので、まず辞書攻撃を試してください")
                print("   → rockyou.txt や common passwords リストが有効")
            elif top_match.mode in [3200, 1800, 7400]:
                print("   → このハッシュは低速なので、短い・単純なパスワードを優先")
                print("   → マスク攻撃で4-6文字から試すのも有効")
            print()


def process_file(filepath: str, detailed: bool = False, show_all: bool = False):
    """ファイルからハッシュを読み込んで処理"""
    detector = HashcatModeDetectorPro()
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not lines:
            print("エラー: ファイルに有効なハッシュが見つかりませんでした")
            return
        
        print(f"\n📁 ファイル: {filepath}")
        print(f"   {len(lines)}行のハッシュを検出しました\n")
        
        for i, hash_value in enumerate(lines, 1):
            if len(lines) > 1:
                print(f"\n{'='*80}")
                print(f"ハッシュ {i}/{len(lines)}")
                print(f"{'='*80}")
            
            detector.print_results(hash_value, detailed, show_all)
            
            if i < len(lines):
                input("\n[Enter] で次のハッシュへ...")
    
    except FileNotFoundError:
        print(f"エラー: ファイル '{filepath}' が見つかりません")
    except Exception as e:
        print(f"エラー: {e}")


def main():
    """メイン処理"""
    parser = argparse.ArgumentParser(
        description='Hashcat Mode Detector Pro - CTF Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # 単一ハッシュを判定
  %(prog)s 5f4dcc3b5aa765d61d8327deb882cf99
  
  # 詳細モード（CTFヒント表示）
  %(prog)s -d e10adc3949ba59abbe56e057f20f883e
  
  # ファイルから読み込み
  %(prog)s -f hashes.txt
  
  # 全候補を表示
  %(prog)s --all 5f4dcc3b5aa765d61d8327deb882cf99
  
  # インタラクティブモード
  %(prog)s
        """
    )
    
    parser.add_argument('hash', nargs='?', help='判定するハッシュ値')
    parser.add_argument('-f', '--file', help='ハッシュ値が記載されたファイル')
    parser.add_argument('-d', '--detail', action='store_true', 
                       help='詳細情報とCTFヒントを表示')
    parser.add_argument('--all', action='store_true', 
                       help='全ての候補を表示（デフォルトは上位3件）')
    
    args = parser.parse_args()
    
    detector = HashcatModeDetectorPro()
    
    # ファイルから読み込み
    if args.file:
        process_file(args.file, args.detail, args.all)
    
    # コマンドライン引数
    elif args.hash:
        detector.print_results(args.hash, args.detail, args.all)
    
    # インタラクティブモード
    else:
        print("="*80)
        print(" Hashcat Mode Detector Pro - CTF Edition")
        print("="*80)
        print("\nハッシュ値を入力してください (Ctrl+C で終了)")
        print("ヒント:")
        print("  - 'detail' と入力すると次のハッシュで詳細表示")
        print("  - 'all' と入力すると次のハッシュで全候補表示")
        print("  - 'file <パス>' でファイルから読み込み\n")
        
        detail_mode = False
        show_all_mode = False
        
        while True:
            try:
                user_input = input("Hash> ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['exit', 'quit', 'q']:
                    print("\n終了します。")
                    break
                
                if user_input.lower() == 'detail':
                    detail_mode = not detail_mode
                    status = "ON" if detail_mode else "OFF"
                    print(f"詳細モード: {status}")
                    continue
                
                if user_input.lower() == 'all':
                    show_all_mode = not show_all_mode
                    status = "ON" if show_all_mode else "OFF"
                    print(f"全候補表示: {status}")
                    continue
                
                if user_input.lower().startswith('file '):
                    filepath = user_input[5:].strip()
                    process_file(filepath, detail_mode, show_all_mode)
                    continue
                
                detector.print_results(user_input, detail_mode, show_all_mode)
                
            except KeyboardInterrupt:
                print("\n\n終了します。")
                break
            except Exception as e:
                print(f"エラー: {e}")


if __name__ == "__main__":
    main()