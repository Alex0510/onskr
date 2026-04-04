#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合并节点获取脚本（输出 Base64 编码到 proxies.txt）
1. 从 cnc07api.cnc07.com 获取加密 SS 节点
2. 从 ioa.onskrgames.uk 获取加密节点
输出：
  - proxies.txt : 节点列表的 Base64 编码
"""

import requests
import json
import base64
import binascii
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ======================== 1. CNC07 源配置 ========================
CNC07_URL = "http://cnc07api.cnc07.com/api/cnc07iuapis"
CNC07_KEY = "1kv10h7t*C3f8c@$"
CNC07_IV = "a$61&bxb5n35c2w9"


def aes_cbc_decrypt_base64(encrypted_b64: str, key: str, iv: str) -> str:
    try:
        key_bytes = key.encode('utf-8')
        iv_bytes = iv.encode('utf-8')
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        encrypted_data = base64.b64decode(encrypted_b64)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[CNC07] AES 解密失败: {e}")
        return None


def extract_cnc07_nodes(decrypted_text: str):
    pattern = r'SS\s*=\s*ss\s*,\s*[^,\n]+,\s*[^,\n]+,\s*encrypt-method=[^,\n]+,\s*password=[^,\n\s\\]+'
    matches = re.findall(pattern, decrypted_text)
    city_pattern = r'"city_cn":"([^"]+)"'
    cities = re.findall(city_pattern, decrypted_text)

    if not matches:
        return []

    nodes = []
    for idx, line in enumerate(matches):
        line = line.strip()
        city = cities[idx] if idx < len(cities) else f"CNC07_{idx+1}"
        modified = re.sub(r'^SS\s*=\s*', f'{city} = ', line)
        modified = re.sub(r'\s*=\s*', '=', modified)
        modified = re.sub(r',\s+', ',', modified)
        nodes.append(modified)

    name_count = {}
    final_nodes = []
    for node in nodes:
        match = re.match(r'^([^=]+)=', node)
        if match:
            name = match.group(1).strip()
            if name not in name_count:
                name_count[name] = 1
            else:
                name_count[name] += 1
                new_name = f"{name}{name_count[name]}"
                node = re.sub(r'^[^=]+=', f'{new_name}=', node)
        final_nodes.append(node)
    return final_nodes


def fetch_cnc07_nodes():
    try:
        resp = requests.get(CNC07_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[CNC07] 请求失败: {e}")
        return []

    servers_enc = data.get('servers')
    if not servers_enc or not isinstance(servers_enc, str):
        print("[CNC07] 缺少 servers 字段")
        return []

    decrypted = aes_cbc_decrypt_base64(servers_enc, CNC07_KEY, CNC07_IV)
    if not decrypted:
        return []

    if decrypted.startswith('z'):
        decrypted = decrypted[1:]

    nodes = extract_cnc07_nodes(decrypted)
    print(f"[CNC07] 提取到 {len(nodes)} 个节点")
    return nodes


# ======================== 2. OnSkr 源配置 ========================
ONSKR_URL = "https://ioa.onskrgames.uk/getLines"
ONSKR_HEADERS = {
    "authority": "ioa.onskrgames.uk",
    "content-type": "application/x-www-form-urlencoded",
    "versionnum": "1.1",
    "bundleid": "com.vpn.onskrvpn",
    "dtype": "2",
    "user-agent": "OnSkrApp/1.1 (iPhone; iOS 16.1.1; Scale/3.00)",
    "cookie": "PHPSESSID=d67onj4srth0o18ocv58iclsi5"
}
ONSKR_BODY = "formInfo=4265a9c353cd8624fd2bc7b5d75d2f180a40d7443bd9fd7d755b804f9362c53f538e090ac89cf7b63208e2053985e88284f7192ae496021bb2e97854bc5db44746bd2312d8dc9cc2f44a5c194b8ec2d7f3a25ebd08c584e825f20045c703dfea"
ONSKR_KEY = b'65151f8d966bf596'
ONSKR_IV = b'88ca0f0ea1ecf975'


def aes_cbc_decrypt_hex(encrypted_hex: str, key: bytes, iv: bytes) -> dict:
    try:
        encrypted_data = binascii.unhexlify(encrypted_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        print(f"[OnSkr] 解密失败: {e}")
        return None


def fetch_onskr_nodes():
    try:
        resp = requests.post(ONSKR_URL, headers=ONSKR_HEADERS, data=ONSKR_BODY, timeout=10)
        resp.raise_for_status()
        encrypted_hex = resp.text.strip()
    except Exception as e:
        print(f"[OnSkr] 请求失败: {e}")
        return []

    decrypted_json = aes_cbc_decrypt_hex(encrypted_hex, ONSKR_KEY, ONSKR_IV)
    if not decrypted_json or 'data' not in decrypted_json:
        print("[OnSkr] 解密结果无效或无 data 字段")
        return []

    nodes = []
    for item in decrypted_json['data']:
        method = 'aes-256-cfb' if item.get('encrypt') == 'AES256CFB' else item.get('encrypt', 'chacha20').lower()
        clean_title = item.get('title', 'OnSkr').replace(',', '').replace(' ', '')
        node_line = f"{clean_title}=ss, {item['ip']}, {item['port']}, encrypt-method={method}, password={item['password']}"
        nodes.append(node_line)

    print(f"[OnSkr] 提取到 {len(nodes)} 个节点")
    return nodes


# ======================== 3. 合并并输出 Base64 编码 ========================
def main():
    all_nodes = []

    cnc_nodes = fetch_cnc07_nodes()
    all_nodes.extend(cnc_nodes)

    onskr_nodes = fetch_onskr_nodes()
    all_nodes.extend(onskr_nodes)

    if not all_nodes:
        print("❌ 未获取到任何节点")
        return

    # 节点明文（每行一个节点）
    plain_text = '\n'.join(all_nodes)

    # Base64 编码
    base64_bytes = base64.b64encode(plain_text.encode('utf-8'))
    base64_str = base64_bytes.decode('ascii')

    # 写入 proxies.txt（内容为 Base64 编码）
    with open('proxies.txt', 'w', encoding='ascii') as f:
        f.write(base64_str)

    print(f"✅ 合并完成，共 {len(all_nodes)} 个节点")
    print(f"   Base64 编码已写入 proxies.txt")


if __name__ == "__main__":
    main()