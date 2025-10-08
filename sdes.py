import time
from itertools import product


class S_DES:
    def __init__(self):
        # 初始化置换盒和S盒
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.LeftShift1 = [2, 3, 4, 5, 1]  # 左移1位
        self.LeftShift2 = [3, 4, 5, 1, 2]  # 左移2位

        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]

        self.SBox1 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 0, 2]
        ]

        self.SBox2 = [
            [0, 1, 2, 3],
            [2, 3, 1, 0],
            [3, 0, 1, 2],
            [2, 1, 0, 3]
        ]

        self.SPBox = [2, 4, 3, 1]

    def permute(self, bits, permutation):
        """根据置换表对二进制位进行置换"""
        return [bits[i - 1] for i in permutation]

    def left_shift(self, bits, shift_table):
        """根据移位表进行左移"""
        return [bits[i - 1] for i in shift_table]

    def xor(self, bits1, bits2):
        """对两个等长的二进制位列表进行异或操作"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def generate_subkeys(self, key):
        """生成子密钥k1和k2"""
        # 将密钥转换为整数列表
        key_bits = [int(bit) for bit in key]

        # 应用P10置换
        p10_key = self.permute(key_bits, self.P10)

        # 分为左右两部分
        left = p10_key[:5]
        right = p10_key[5:]

        # 生成k1
        left1 = self.left_shift(left, self.LeftShift1)
        right1 = self.left_shift(right, self.LeftShift1)
        k1 = self.permute(left1 + right1, self.P8)

        # 生成k2
        left2 = self.left_shift(left1, self.LeftShift2)
        right2 = self.left_shift(right1, self.LeftShift2)
        k2 = self.permute(left2 + right2, self.P8)

        return k1, k2

    def f_function(self, right, subkey):
        """轮函数f"""
        # 扩展置换
        expanded = self.permute(right, self.EP)

        # 与子密钥异或
        xored = self.xor(expanded, subkey)

        # 分为两部分，进入S盒
        left_s = xored[:4]
        right_s = xored[4:]

        # S盒1处理
        row1 = left_s[0] * 2 + left_s[3]
        col1 = left_s[1] * 2 + left_s[2]
        s1_out = self.SBox1[row1][col1]
        s1_bits = [(s1_out >> 1) & 1, s1_out & 1]

        # S盒2处理
        row2 = right_s[0] * 2 + right_s[3]
        col2 = right_s[1] * 2 + right_s[2]
        s2_out = self.SBox2[row2][col2]
        s2_bits = [(s2_out >> 1) & 1, s2_out & 1]

        # 合并并应用SP置换
        s_out = s1_bits + s2_bits
        sp_out = self.permute(s_out, self.SPBox)

        return sp_out

    def encrypt(self, plaintext, key):
        """加密函数"""
        # 生成子密钥
        k1, k2 = self.generate_subkeys(key)

        # 将明文转换为整数列表
        plain_bits = [int(bit) for bit in plaintext]

        # 初始置换
        ip_out = self.permute(plain_bits, self.IP)

        # 分为左右两部分
        left = ip_out[:4]
        right = ip_out[4:]

        # 第一轮
        f_out = self.f_function(right, k1)
        new_left = self.xor(left, f_out)
        new_right = right

        # 交换
        left, right = new_right, new_left

        # 第二轮
        f_out = self.f_function(right, k2)
        new_left = self.xor(left, f_out)
        new_right = right

        # 合并
        pre_output = new_left + new_right

        # 最终置换
        ciphertext_bits = self.permute(pre_output, self.IP_inv)

        # 转换为字符串
        return ''.join(str(bit) for bit in ciphertext_bits)

    def decrypt(self, ciphertext, key):
        """解密函数"""
        # 生成子密钥
        k1, k2 = self.generate_subkeys(key)

        # 将密文转换为整数列表
        cipher_bits = [int(bit) for bit in ciphertext]

        # 初始置换
        ip_out = self.permute(cipher_bits, self.IP)

        # 分为左右两部分
        left = ip_out[:4]
        right = ip_out[4:]

        # 第一轮（使用k2）
        f_out = self.f_function(right, k2)
        new_left = self.xor(left, f_out)
        new_right = right

        # 交换
        left, right = new_right, new_left

        # 第二轮（使用k1）
        f_out = self.f_function(right, k1)
        new_left = self.xor(left, f_out)
        new_right = right

        # 合并
        pre_output = new_left + new_right

        # 最终置换
        plaintext_bits = self.permute(pre_output, self.IP_inv)

        # 转换为字符串
        return ''.join(str(bit) for bit in plaintext_bits)

    def encrypt_ascii(self, plaintext, key):
        """加密ASCII字符串"""
        ciphertext = []
        for char in plaintext:
            # 将字符转换为8位二进制
            binary = format(ord(char), '08b')
            # 加密
            encrypted = self.encrypt(binary, key)
            # 将加密后的二进制转换回字符
            ciphertext.append(chr(int(encrypted, 2)))
        return ''.join(ciphertext)

    def decrypt_ascii(self, ciphertext, key):
        """解密ASCII字符串"""
        plaintext = []
        for char in ciphertext:
            # 将字符转换为8位二进制
            binary = format(ord(char), '08b')
            # 解密
            decrypted = self.decrypt(binary, key)
            # 将解密后的二进制转换回字符
            plaintext.append(chr(int(decrypted, 2)))
        return ''.join(plaintext)

    def brute_force(self, plaintext, ciphertext, progress_callback=None):
        """暴力破解密钥"""
        start_time = time.time()
        found_keys = []

        # 生成所有可能的10位密钥
        total_keys = 2 ** 10  # 1024个可能的密钥
        for i, bits in enumerate(product('01', repeat=10)):
            key = ''.join(bits)

            # 检查进度并回调
            if progress_callback and i % 10 == 0:
                progress = (i / total_keys) * 100
                progress_callback(progress)

            # 尝试加密
            encrypted = self.encrypt(plaintext, key)
            if encrypted == ciphertext:
                found_keys.append(key)
                # 继续寻找所有可能的密钥，而不仅仅是第一个

        end_time = time.time()
        elapsed_time = end_time - start_time

        return found_keys, elapsed_time
