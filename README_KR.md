# 🛡️ EzCipher

**EzCipher**는 파이썬을 위한 최신식, 경량화된 제로-보일러플레이트 AES-256-GCM 암호화 유틸리티입니다.  
복잡한 암호화 원리를 깊이 몰라도, 개발자가 즉시 안전한 암호화 기능을 구현할 수 있도록 설계되었습니다.

[English Version](./README.md)

## ✨ 주요 특징

- **인증된 암호화 (AEAD)**: AES-GCM을 사용하여 데이터의 기밀성과 무결성을 동시에 보장합니다.
- **제로 보일러플레이트**: 초기화 벡터(IV), 솔트(Salt), 인증 태그를 수동으로 관리할 필요가 없습니다.
- **강력한 키 유도**: PBKDF2-HMAC-SHA256 알고리즘과 100,000회 반복 횟수를 적용하여 암호 보안을 강화했습니다.
- **SecureConfig**: 암호화된 설정 파일 및 금고(Vault) 관리를 위한 전용 레이어를 내장하고 있습니다.
- **명령줄 인터페이스 (CLI)**: 터미널에서 즉시 비밀 데이터를 암호화하고 관리할 수 있습니다.

## 🚀 설치 방법

```bash
pip install EzCipher
```

## 🛠️ 라이브러리 사용법

### 단순 문자열 암호화
```python
from EzCipher import EzCipher

# 비밀번호로 초기화
cipher = EzCipher.from_password("나만의-비밀번호")

# 암호화
encrypted_blob = cipher.encrypt("안녕하세요, 세상님!")
print(encrypted_blob) # 버전 정보가 포함된 Base64 문자열 반환

# 복호화
original_text = cipher.decrypt(encrypted_blob)
assert original_text == "안녕하세요, 세상님!"
```

### 암호화된 설정 관리 (Vault)
```python
from EzCipher import SecureConfig

# 암호화된 금고 파일 생성 또는 로드
vault = SecureConfig("secrets.vault", "금고-비밀번호")

# 그룹별로 암호화된 데이터 저장
vault.save("database", {"user": "admin", "password": "db-password-123"})

# 읽기 및 복호화
db_secrets = vault.read("database")
print(db_secrets['password']) # "db-password-123"
```

## 💻 CLI 사용법

설치 후 `ezcipher` 명령어를 바로 사용할 수 있습니다:

### 문자열 암호화/복호화
```bash
# 암호화
ezcipher encrypt "비밀 메시지" -p "내-암호"

# 복호화
ezcipher decrypt "AQ==..." -p "내-암호"
```

### 금고 파일 관리
```bash
# 비밀값 설정
ezcipher config -f keys.vault -p "pass" --set production api_key "sk-12345"

# 비밀값 가져오기
ezcipher config -f keys.vault -p "pass" --get production api_key

# 모든 리스트 보기
ezcipher config -f keys.vault -p "pass"
```

## 📖 아키텍처 및 포맷

EzCipher는 다음과 같은 통합 바이너리 포맷을 사용합니다:
`[버전(1바이트)] | [솔트(16바이트)] | [논스(12바이트)] | [태그(16바이트)] | [암호문]`

이를 통해 모든 암호화된 데이터는 올바른 비밀번호만 있다면 복호화에 필요한 모든 정보를 스스로 운반합니다.

## ⚖️ 라이선스
[MIT License](LICENSE)에 따라 라이선스가 부여됩니다.  
Copyright (c) 2026 **minicom365**
