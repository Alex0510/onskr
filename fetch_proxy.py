import requests
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_data(encrypted_hex):
    key = b'65151f8d966bf596'
    iv = b'88ca0f0ea1ecf975'
    encrypted_data = binascii.unhexlify(encrypted_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return json.loads(decrypted.decode('utf-8'))

def fetch_and_format_nodes():
    url = "https://ioa.onskrgames.uk/getLines"
    headers = {
        "authority": "ioa.onskrgames.uk",
        "content-type": "application/x-www-form-urlencoded",
        "versionnum": "1.1",
        "bundleid": "com.vpn.onskrvpn",
        "dtype": "2",
        "user-agent": "OnSkrApp/1.1 (iPhone; iOS 16.1.1; Scale/3.00)",
        "cookie": "PHPSESSID=d67onj4srth0o18ocv58iclsi5"
    }
    body = "formInfo=4265a9c353cd8624fd2bc7b5d75d2f180a40d7443bd9fd7d755b804f9362c53f538e090ac89cf7b63208e2053985e88284f7192ae496021bb2e97854bc5db44746bd2312d8dc9cc2f44a5c194b8ec2d7f3a25ebd08c584e825f20045c703dfea"

    response = requests.post(url, headers=headers, data=body)
    encrypted_data = response.text.strip()

    try:
        decrypted_json = decrypt_data(encrypted_data)
        nodes = []
        for item in decrypted_json['data']:
            method = 'aes-256-cfb' if item['encrypt'] == 'AES256CFB' else item['encrypt'].lower()
            # 删除节点名称中的逗号和空格
            clean_title = item['title'].replace(',', '').replace(' ', '')
            nodes.append(f"{clean_title}=ss, {item['ip']}, {item['port']}, encrypt-method={method}, password={item['password']}")
        return '\n'.join(nodes)
    except Exception as e:
        print(f"Error: {e}")
        return ""

if __name__ == "__main__":
    nodes = fetch_and_format_nodes()
    if nodes:
        with open('proxies.txt', 'w', encoding='utf-8') as f:
            f.write(nodes)