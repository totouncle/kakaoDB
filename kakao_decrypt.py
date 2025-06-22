import argparse
import binascii
import hashlib
import os
import sys
from typing import Optional

try:
    from pysqlcipher3 import dbapi2 as sqlcipher
except ImportError as e:
    print("pysqlcipher3 라이브러리가 설치되지 않았습니다. 'pip install pysqlcipher3' 명령으로 설치 후 다시 시도하세요.")
    sys.exit(1)

import sqlite3


def derive_key(user_id: str, uuid: str) -> bytes:
    """사용자 ID와 UUID로 복호화 키를 파생한다."""
    password = (user_id + uuid)[::-1].encode("utf-8")
    salt = hashlib.sha256(uuid.encode("utf-8")).digest()
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100_000, dklen=32)


def open_encrypted_db(path: str, key: bytes) -> sqlcipher.Connection:
    """암호화된 DB 파일을 열어 커넥션을 반환한다."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"입력 DB 파일을 찾을 수 없습니다: {path}")

    conn = sqlcipher.connect(path)
    conn.execute("PRAGMA cipher_default_compatibility = 3")
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA key = ?", [b"x'" + binascii.hexlify(key) + b"'"])
    # 키 적용 확인
    conn.execute("SELECT count(*) FROM sqlite_master")
    return conn


def create_output_db(path: str) -> sqlite3.Connection:
    """결과 DB를 생성하고 테이블을 만든다."""
    dest_conn = sqlite3.connect(path)
    cur = dest_conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rooms (
            room_id TEXT PRIMARY KEY,
            room_name TEXT,
            created_at TEXT,
            member_count INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            msg_id TEXT PRIMARY KEY,
            room_id TEXT,
            sender_id TEXT,
            sender_name TEXT,
            message_text TEXT,
            timestamp INTEGER,
            is_incoming INTEGER,
            attachment_info TEXT,
            FOREIGN KEY(room_id) REFERENCES rooms(room_id)
        )
        """
    )
    dest_conn.commit()
    return dest_conn


def export_rooms(src_conn: sqlcipher.Connection, dest_conn: sqlite3.Connection, verbose: bool = False) -> None:
    """채팅방 정보를 추출한다."""
    cur = src_conn.cursor()
    dcur = dest_conn.cursor()
    try:
        cur.execute("SELECT id, name, create_time, member_count FROM chat_rooms")
    except Exception as e:
        if verbose:
            print(f"[Warn] 채팅방 정보 추출 실패: {e}")
        return
    rows = cur.fetchall()
    for row in rows:
        dcur.execute(
            "INSERT OR IGNORE INTO rooms(room_id, room_name, created_at, member_count) VALUES (?, ?, ?, ?)",
            row,
        )
    dest_conn.commit()
    if verbose:
        print(f"채팅방 {len(rows)}개 추출 완료")


def export_messages(src_conn: sqlcipher.Connection, dest_conn: sqlite3.Connection, verbose: bool = False) -> None:
    """메시지 데이터를 추출한다."""
    cur = src_conn.cursor()
    dcur = dest_conn.cursor()
    try:
        cur.execute(
            "SELECT id, room_id, sender_id, sender_name, message, timestamp, is_incoming, attachment FROM chat_logs"
        )
    except Exception as e:
        if verbose:
            print(f"[Warn] 메시지 추출 실패: {e}")
        return
    count = 0
    for row in cur.fetchall():
        dcur.execute(
            "INSERT OR IGNORE INTO messages(msg_id, room_id, sender_id, sender_name, message_text, timestamp, is_incoming, attachment_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            row,
        )
        count += 1
    dest_conn.commit()
    if verbose:
        print(f"메시지 {count}건 추출 완료")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="KakaoTalk DB 복호화 스크립트")
    parser.add_argument("--input", "-i", required=True, help="암호화된 KakaoTalk DB 파일 경로")
    parser.add_argument(
        "--output", "-o", default="kakao_decrypted.db", help="출력 SQLite DB 경로"
    )
    parser.add_argument("--userid", help="사용자 ID")
    parser.add_argument("--uuid", help="디바이스 UUID")
    parser.add_argument("--key", help="직접 제공하는 SQLCipher 키 (hex)")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 로그 출력")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            print("--key 옵션은 hex 문자열이어야 합니다.")
            sys.exit(1)
    else:
        if not (args.userid and args.uuid):
            print("--userid와 --uuid를 함께 제공하거나 --key를 사용해야 합니다.")
            sys.exit(1)
        key = derive_key(args.userid, args.uuid)

    if args.verbose:
        print("키 파생 완료")

    try:
        src_conn = open_encrypted_db(args.input, key)
    except Exception as e:
        print(f"DB 열기 실패: {e}")
        sys.exit(1)

    dest_conn = create_output_db(args.output)

    export_rooms(src_conn, dest_conn, args.verbose)
    export_messages(src_conn, dest_conn, args.verbose)

    src_conn.close()
    dest_conn.close()
    print(f"완료: 결과 DB {args.output}")


if __name__ == "__main__":
    main()
