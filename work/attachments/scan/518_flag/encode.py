import base64


def samsara_encrypt(text, key_word):
    cycle_step = len(key_word) % 6 + 1

    phase1 = bytes([(c >> cycle_step) | ((c << (8 - cycle_step)) & 0xFF) for c in text])

    phase2 = base64.b85encode(phase1)

    phase3 = bytes([(c >> cycle_step) | ((c << (8 - cycle_step)) & 0xFF) for c in phase2])

    return bytes([phase3[i] ^ key_word[i % len(key_word)] for i in range(len(phase3))])


if __name__ == "__main__":
    flag = b"palu{********}"  # 可替换flag
    key = b""
    cipher = samsara_encrypt(flag, key)

    # 修复点：使用latin-1编码处理二进制数据
    print("轮回密文:", cipher.decode('latin-1'))  # 输出示例：¨×èÄÅÉØÛÚ
