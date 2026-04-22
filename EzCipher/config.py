# -*- coding: utf-8 -*-

import re
import os
import hashlib
from .cipher import EzCipher

# [Architecture 3.0] 설정 파일 보호 레이어 (EzCipher.SecureConfig)
class SecureConfig:
    """
    그룹별로 관리되는 암호화된 설정 파일을 제어합니다.
    """
    def __init__(self, filepath, password):
        self.filepath = filepath
        self.password = password
        self.cipher = EzCipher.from_password(password)
        self._ensure_file()

    def _get_hash(self, text):
        # 기존 blake2b 기반 해시 검증 유지
        return hashlib.blake2b(text.encode('utf-8'), digest_size=64).hexdigest()

    def _ensure_file(self):
        if not os.path.exists(self.filepath):
            with open(self.filepath, 'w', encoding='utf-8') as f:
                f.write(self._get_hash(self.password) + "\n")
        else:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                header = f.readline().strip()
                if header != self._get_hash(self.password):
                    raise ValueError("Config password verification failed.")

    def read(self, group_id=None):
        """특정 그룹 혹은 전체 데이터를 복호화하여 사전 형태로 반환합니다."""
        data = {}
        current_group = None
        
        with open(self.filepath, 'r', encoding='utf-8') as f:
            f.readline() # skip hash
            for line in f:
                line = line.strip()
                if not line: continue
                
                # 그룹 매칭 [group]
                group_match = re.match(r'\[(.*)\]', line)
                if group_match:
                    current_group = group_match.group(1)
                    if group_id and current_group == group_id:
                        data = {}
                    elif not group_id:
                        data[current_group] = {}
                    continue
                
                if current_group:
                    if group_id and current_group != group_id:
                        continue
                        
                    if ":" in line:
                        key, val = [x.strip() for x in line.split(":", 1)]
                        try:
                            decrypted = self.cipher.decrypt(val)
                            target = data if group_id else data[current_group]
                            target[key] = decrypted
                        except Exception:
                            # 복호화 실패 시 원본값 혹은 오류 처리
                            pass
        return data

    def save(self, group_id, keys_dict):
        """특정 그룹에 새로운 키-값 쌍을 암호화하여 저장합니다."""
        # 전체 구조를 읽어온 뒤 업데이트하고 다시 쓰는 방식 (소규모 설정 파일에 적합)
        all_groups = self._parse_all_raw()
        
        if group_id not in all_groups:
            all_groups[group_id] = {}
            
        for k, v in keys_dict.items():
            all_groups[group_id][k] = self.cipher.encrypt(str(v))
            
        self._write_all_raw(all_groups)

    def _parse_all_raw(self):
        groups = {}
        current_group = None
        with open(self.filepath, 'r', encoding='utf-8') as f:
            f.readline() # skip hash
            for line in f:
                line = line.strip()
                if not line: continue
                group_match = re.match(r'\[(.*)\]', line)
                if group_match:
                    current_group = group_match.group(1)
                    groups[current_group] = {}
                elif current_group and ":" in line:
                    k, v = [x.strip() for x in line.split(":", 1)]
                    groups[current_group][k] = v
        return groups

    def _write_all_raw(self, groups):
        with open(self.filepath, 'w', encoding='utf-8') as f:
            f.write(self._get_hash(self.password) + "\n")
            for group, keys in groups.items():
                f.write(f"[{group}]\n")
                for k, v in keys.items():
                    f.write(f"    {k}: {v}\n")
