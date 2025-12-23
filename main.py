from aes_file_crypto import encrypt_file, decrypt_file


def main():
    """
    简单测试入口：
    1. 读取当前目录下的 plain.txt
    2. 加密为 cipher.bin
    3. 再解密为 decrypted.txt
    """
    key = "mysecretkey123"  # 口令，可自行修改

    plain_path = "plain.txt"
    cipher_path = "cipher.bin"
    decrypted_path = "decrypted.txt"

    print("开始 AES-128-CBC 文件加解密测试...\n")

    # 加密
    encrypt_file(plain_path, cipher_path, key)

    # 解密
    decrypt_file(cipher_path, decrypted_path, key)

    print("测试完成，请检查 plain.txt 和 decrypted.txt 是否完全一致。")


if __name__ == "__main__":
    main()