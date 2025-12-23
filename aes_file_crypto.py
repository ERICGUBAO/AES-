from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

BLOCK_SIZE = 16  # AES 分组长度 16 字节


def pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    PKCS#7 填充
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def unpad(data: bytes) -> bytes:
    """
    去掉 PKCS#7 填充
    """
    if not data:
        raise ValueError("Invalid padding: empty data")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")

    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes")

    return data[:-padding_len]


def normalize_key(key_str: str) -> bytes:
    """
    将用户输入的字符串转为 16 字节密钥（AES-128）
    """
    key_bytes = key_str.encode("utf-8")
    if len(key_bytes) < BLOCK_SIZE:
        key_bytes = key_bytes.ljust(BLOCK_SIZE, b"\0")
    else:
        key_bytes = key_bytes[:BLOCK_SIZE]
    return key_bytes


def encrypt_file(plain_path: str, cipher_path: str, key_str: str) -> None:
    """
    使用 AES-128-CBC 加密文本文件。
    输出文件格式: [16字节IV][密文...]
    """
    if not os.path.exists(plain_path):
        raise FileNotFoundError(f"Plain file not found: {plain_path}")

    # 读取明文（UTF-8 支持汉字/符号）
    with open(plain_path, "r", encoding="utf-8") as f:
        plaintext_str = f.read()

    plaintext_bytes = plaintext_str.encode("utf-8")
    padded = pad(plaintext_bytes)

    key = normalize_key(key_str)
    iv = get_random_bytes(BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    # 将 IV 和密文一起写入
    with open(cipher_path, "wb") as f:
        f.write(iv + ciphertext)

    print("=== Encrypt ===")
    print(f"Input file : {plain_path}")
    print(f"Output file: {cipher_path}")
    print(f"Plain length  : {len(plaintext_bytes)} bytes")
    print(f"Padded length : {len(padded)} bytes")
    print(f"Cipher length : {len(ciphertext)} bytes")
    print()


def decrypt_file(cipher_path: str, plain_out_path: str, key_str: str) -> None:
    """
    使用 AES-128-CBC 解密文件。
    输入文件格式: [16字节IV][密文...]
    """
    if not os.path.exists(cipher_path):
        raise FileNotFoundError(f"Cipher file not found: {cipher_path}")

    with open(cipher_path, "rb") as f:
        data = f.read()

    if len(data) < BLOCK_SIZE:
        raise ValueError("Cipher data too short")

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    key = normalize_key(key_str)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plain = cipher.decrypt(ciphertext)

    plaintext_bytes = unpad(padded_plain)
    plaintext_str = plaintext_bytes.decode("utf-8")

    with open(plain_out_path, "w", encoding="utf-8") as f:
        f.write(plaintext_str)

    print("=== Decrypt ===")
    print(f"Input file : {cipher_path}")
    print(f"Output file: {plain_out_path}")
    print(f"Recovered plain length: {len(plaintext_bytes)} bytes")
    print()