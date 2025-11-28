import duckdb
import pandas as pandas
import os
from pathlib import Path
from datetime import datetime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class DBHandler:
    """
    DuckDB와의 모든 상호작용을 담당하는 핸들러 클래스.
    데이터 적재, 사용자 인증, 채팅 기록 저장, 메타데이터 관리를 수행함.
    """

    def __init__(self, db_path="storage/database/data.duckdb"):
        """
        클래스 초기화 메서드. DB 연결 설정 및 필수 테이블 생성
 
        Args:
            db_path (str): DuckDB 데이터베이스 파일이 저장될 경로
        """
        # 데이터베이스 파일이 저장될 상위 디렉토리가 없으면 생성
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # DuckDB 연결 객체 생성
        self.conn = duckdb.connect(db_path, read_only=False)

        # 시스템 구동에 필수적인 기본 테이블 생성 및 초기화
        self._init_tables()

        # Argon2 해시 객체 생성
        self.ph = PasswordHasher()

    def _init_tables(self):
        """
        시스템 구동에 필수적인 테이블(채팅내역, 사용자, 메타데이터)이 없을 시 생성.
        DuckDB의 'CREATE TABLE IF NOT EXISTS' 문법 사용
        """

        # 채팅 내역 테이블
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_history (
                session_id VARCHAR PRIMARY KEY,                            -- 세션 ID(사용자 별로 채팅을 여러 개 열 수도 있으니까)
                user_id VARCHAR NOT NULL,                                  -- 사용자 ID
                role VARCHAR NOT NULL,                                     -- 전송 주체(user,AI)
                message VARCHAR NOT NULL,                                  -- 메시지(질문, 답변)
                artifact_path VARCHAR,                                     -- 생성, 삽입한 이미지나 파일의 경로
                created_at TIMESTAMP NOT NULL,                             -- 메시지 생성 시간
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        # 사용자 테이블
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id VARCHAR PRIMARY KEY,                                    -- 사용자 ID
                password_hash VARCHAR NOT NULL,                            -- 비밀번호(암호화)
                name VARCHAR NOT NULL,                                     -- 사용자 이름(혹은 닉네임)
                email VARCHAR NOT NULL,                                    -- 사용자 이메일
                auth VARCHAR NOT NULL,                                     -- 권한 (admin, user, deleted)
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL    -- 가입 일시
            )
            """
        )

        # 메타데이터 테이블
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS table_metadata(
                table_name VARCHAR NOT NULL,                               -- 테이블 이름  
                table_description VARCHAR NOT NULL,                        -- 테이블 요약 설명
                column_name VARCHAR NOT NULL,                              -- 컬럼 이름
                column_description VARCHAR,                                -- 컬럼 설명
                column_type VARCHAR NOT NULL,                              -- 컬럼 데이터 타입
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,   -- 테이블 생성 일시
                PRIMARY KEY (table_name, column_name)                      -- 테이블 이름과 컬럼 이름의 조합으로 복합 키 설정
            )
            """
        )

    # ======================================================================
    # [섹션 1] 사용자 인증 (Authentication)
    # ======================================================================

    def add_user(self, id, password, name, email):
        """
        신규 사용자 등록. 비밀번호는 해싱하여 저장 
        """
        # 사용자는 기본적으로 'user' 권한으로 등록
        auth = "user"

        # 비밀번호를 Argon2id로 해싱하여 저장
        # Argon2id는 bcrypt와 달리 문자열로 디코딩하지 않아도 됨
        password_hash = self.ph.hash(password)

        try:
            # 사용자 정보 INSERT. 파라미터 바인딩 ? 사용해 SQL 인젝션 방지
            self.conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                [id, password_hash, name, email, auth, datetime.now()]
            )
            return True, "신규 사용자 등록 성공"
        except Exception as e:
            # 중복 ID 등록 시 발생하는 에러 발생 시 반환
            return False, f"신규 사용자 등록 실패: {str(e)}"

    def verify_login(self, id, password):
        """
        로그인 시도 시 아이디 및 비밀번호 검증
        """
        # 해당 아이디 사용자 정보 조회
        result = self.conn.execute(
            "SELECT * FROM users WHERE id = ?",
            [id]
        ).fetchone()

        if not result:
            return False, "오류: 존재하지 않는 사용자"

        stored_hash = result[1]
        name = result[2]
        auth = result[4]

        # Argon2id 검증
        try:
            self.ph.verify(stored_hash, password)
            
            # Argon2 파라미터 업데이트 된 경우 대비 해싱된 비밀번호 갱신 필요 여부 확인
            if self.ph.check_needs_rehash(stored_hash):
                new_hash = self.ph.hash(password)
                self.conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    [new_hash, id]
                )
            return True, "로그인 성공"
        except VerifyMismatchError:
            return False, "오류: 비밀번호 불일치"

    # ======================================================================
    # [섹션 2] 데이터 추출·변환·적재 (ETL)
    # ======================================================================

    def register_table_metadata(self, dataframe, table_name, table_description):
        """
        테이블이 생성될 때, LLM이 df.head()를 통해 초벌 분석한 해당 테이블과 그 컬럼 정보를 table_metadata에 등록.
        """
        # 기존에 해당 테이블의 메타데이터가 존재하면 삭제
        self.conn.execute(
            "DELETE FROM table_metadata WHERE table_name = ?",
            [table_name]
        )

        # Dataframe의 컬럼 정보를 순회하며 등록
        for column in dataframe.columns:
            # 컬럼의 데이터 타입 추출
            dtype = str(dataframe[column].dtype)

            # 메타데이터 INSERT
            self.conn.execute(
                "INSERT INTO table_metadata VALUES (?, ?, ?, ?, ?, ?)",
                [
                    table_name,
                    table_description,
                    column,
                    "", # column_description (추후 AI로 채울 영역)
                    dtype,
                    datetime.now()
                ]
            )
        
        print(f"{table_name} 테이블의 메타데이터 등록 완료")

    def load_file_to_db(self, data_folder="storage/raw_data"):
        """
        지정된 폴더 내 파일들을 각각 개별적인 테이블로 DB에 저장
        """
        all_files = list(Path(data_folder).rglob("*.*"))

        print(f"{data_folder} 폴더에서 {len(all_files)}개의 개별 파일 로딩 시작")

        for file_path in all_files:
            try:
                filename_ext = os.path.basename(file_path)
                filename_only = os.path.splitext(filename_ext)[0]

                # 파일 읽기
                if file_path.endswith(".csv"):
                    df = pd.read_csv(file_path)
                elif file_path.endswith(".xlsx") or file_path.endswith(".xls"):
                    df = pd.read_excel(file_path)
                else:
                    continue

                # SQL 호환성을 위해 테이블 이름 정제
                safe_name = "data_" + filename_only.strip().replace(" ", "_").replace("-", "_").lower()

                # 컬럼명 정제
                df.columns = [str(c).strip().replace(" ", "_").replace("-", "_").lower() for c in df.columns]
                
                # 유지보수 목적 식별자 추가
                df["source_file"] = filename_ext
                df["uploaded_at"] = datetime.now()

                # 개별 테이블 생성
                self.conn.execute(
                    f"CREATE OR REPLACE TABLE {safe_name} AS SELECT * FROM df"
                )

                # (미구현)
                # table_description = show_me_desc(df.head())

                # 메타데이터 등록
                self.register_table_metadata(df, safe_name, "Description placeholder")

                print(f"테이블 생성 완료: {safe_name} ({len(df)} 행)")

            except Exception as e:
                print(f"오류: {filename_ext} 파일 처리 중 오류 발생 - {e}")
