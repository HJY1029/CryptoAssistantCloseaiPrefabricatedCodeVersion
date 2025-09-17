import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class SM4Helper:
    def __init__(self, api_key, mode="CBC"):
        self.api_key = api_key
        self.algorithm = f"SM4-{mode.upper()}"
        self.mode = mode.upper()   # "ECB" 或 "CBC"
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), "sm4_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        self.mode = "CBC"
        self.key_length = 16
        self.iv_length = 16
        self.work_dir = os.path.join(os.getcwd(), "sm4_workdir")
        os.makedirs(self.work_dir, exist_ok=True)

        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 3
        self.test_vectors = [
            {
                "name": "SM4 Test Vector 1",
                "key": "0123456789abcdeffedcba9876543210",
                "iv": "000102030405060708090a0b0c0d0e0f",
                "plaintext": "0123456789abcdeffedcba9876543210",
                "expected_ecb": "681edf34d206965e86b3e94f536e4246",
                "expected_cbc": "7649abac8119b246cee98e9b12e9197d"
            }
        ]




    @staticmethod
    def hex_to_bytes(hex_str):
        return bytes.fromhex(hex_str)

    @staticmethod
    def bytes_to_hex(byte_data):
        return byte_data.hex()

    def encrypt(self, plaintext_hex, key_hex, iv_hex=None):
        plaintext = self.hex_to_bytes(plaintext_hex)
        key = self.hex_to_bytes(key_hex)
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key, SM4_ENCRYPT)

        if self.mode.upper() == "ECB":
            return self.bytes_to_hex(crypt_sm4.crypt_ecb(plaintext))
        elif self.mode.upper() == "CBC":
            if iv_hex is None:
                raise ValueError("CBC 模式需要 IV")
            iv = self.hex_to_bytes(iv_hex)
            return self.bytes_to_hex(crypt_sm4.crypt_cbc(iv, plaintext))

    def decrypt(self, ciphertext_hex, key_hex, iv_hex=None):
        ciphertext = self.hex_to_bytes(ciphertext_hex)
        key = self.hex_to_bytes(key_hex)
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key, SM4_DECRYPT)

        if self.mode.upper() == "ECB":
            return self.bytes_to_hex(crypt_sm4.crypt_ecb(ciphertext))
        elif self.mode.upper() == "CBC":
            if iv_hex is None:
                raise ValueError("CBC 模式需要 IV")
            iv = self.hex_to_bytes(iv_hex)
            return self.bytes_to_hex(crypt_sm4.crypt_cbc(iv, ciphertext))

    def run_test_vectors(self):
        print("=== SM4 测试向量验证 ===")
        all_passed = True
        for vec in self.test_vectors:
            expected = vec["expected_ecb"] if self.mode.upper() == "ECB" else vec["expected_cbc"]
            ciphertext = self.encrypt(vec["plaintext"], vec["key"], vec["iv"] if self.mode.upper()=="CBC" else None)
            if ciphertext.lower() == expected.lower():
                print(f"[{vec['name']}] ✅ 测试通过")
            else:
                print(f"[{vec['name']}] ❌ 测试失败")
                print(f"实际: {ciphertext}\n预期: {expected}")
                all_passed = False
        return all_passed

   

    def interactive_mode(self):
        print(f"===== SM4 {self.mode} 交互式加密 =====")
        key = input(f"请输入 {self.key_length*2} 字符十六进制密钥: ").strip()
        iv = input(f"请输入 {self.iv_length*2} 字符十六进制 IV: ").strip() if self.mode.upper() == "CBC" else None
        plaintext = input("请输入十六进制明文: ").strip()
        ciphertext = self.encrypt(plaintext, key, iv)
        print(f"密文: {ciphertext}")

    def process(self):
        print("请选择加密模式:\n1. ECB\n2. CBC")
        mode_choice = input("输入选项(1/2): ").strip()
        self.mode = "ECB" if mode_choice == "1" else "CBC"
        self.algorithm = f"SM4-{self.mode}"
        print("请选择运行模式:\n1. 固定模板\n2. AI生成C模板")
        choice = input("输入选项(1/2): ").strip()
        
        if choice == "1":
            if not self.run_test_vectors():  # Python端验证
                print("❌ 固定模板测试向量失败")
                return
            self.interactive_mode()
        
        elif choice == "2":
            code, msg = self._generate_c_code()
            if not code:
                print("❌ AI生成代码失败")
                return
            
            if self._verify_c_code_vectors():  # 自动测试向量验证
                print("✅ AI生成代码通过测试向量验证")
                self.interactive_mode()
            else:
                print("❌ AI生成代码测试向量失败，回退到固定模板")
                if not self.run_test_vectors():
                    print("❌ 固定模板也失败")
                    return
                self.interactive_mode()


    def _generate_c_code(self, plaintext_hex: str, key_hex: str, iv_hex: str = None) -> str:
        """
        调用 AI 生成 C 代码模板，并确保函数名不会与 GMSSL 冲突
        """
        import re
        import requests

        # 根据模式决定函数名
        mode_upper = self.mode.upper()
        if mode_upper == "CBC":
            safe_func_name = "my_sm4_cbc_encrypt"
        elif mode_upper == "ECB":
            safe_func_name = "my_sm4_ecb_encrypt"
        else:
            safe_func_name = "my_sm4_encrypt"

        system_prompt = f"""
    你是一个C语言密码学助手，任务是生成基于 GMSSL 的 SM4-{mode_upper} 模式加密示例程序。
    要求：
    1. 使用 GMSSL 提供的 <openssl/sm4.h>。
    2. 使用 hex 输入 key/iv/plaintext，自动转换为字节。
    3. 输出 ciphertext（hex 格式）。
    4. 主要逻辑写在一个函数里，函数名必须是 {safe_func_name}，不要使用 GMSSL 内置函数名。
    """

        user_prompt = f"""
    请生成一个完整的 C 程序（包含 main），支持以下功能：
    - 从输入参数读取 Key（16 字节，hex）、IV（CBC 需要，16 字节，hex）、Plaintext（16 字节，hex）
    - 调用 {safe_func_name} 完成加密
    - 打印 Ciphertext（hex）

    输入样例：
    Key: {key_hex}
    IV: {iv_hex if iv_hex else 'N/A'}
    Plaintext: {plaintext_hex}
    """

        # === 调用 AI 接口 ===
        resp = requests.post(
            "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": "ep-xxxxxxxxxxxxxxxx",  # 你的模型 endpoint
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]

        # === 提取代码块 ===
        code_blocks = re.findall(r"```c(.*?)```", content, re.S)
        clean_code = code_blocks[0] if code_blocks else content

        # === 安全替换，避免函数名冲突 ===
        clean_code = re.sub(r"\bsm4_cbc_encrypt\b", "my_sm4_cbc_encrypt", clean_code)
        clean_code = re.sub(r"\bsm4_ecb_encrypt\b", "my_sm4_ecb_encrypt", clean_code)

        return clean_code.strip()

    def _compile_and_run(self, code=None, auto_input=None):
        """
        编译并运行生成的C代码
        auto_input: 如果传入字符串，则自动作为 stdin 输入
        """
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 修复填充长度计算
        c_code = re.sub(
            r'size_t padded_len = plaintext_len \+ \(16 - \(plaintext_len % 16\)\);',
            r'size_t pad_len = (plaintext_len % 16 == 0) ? 16 : (16 - (plaintext_len % 16));\n    size_t padded_len = plaintext_len + pad_len;',
            c_code
        )

        if 'unsigned char iv[16];' not in c_code:
            c_code = re.sub(
                r'unsigned char raw_key\[16\];',
                r'unsigned char raw_key[16];\n    unsigned char iv[16];',
                c_code
            )

        code_path = os.path.join(self.work_dir, "sm4_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "sm4_encrypt")
        compile_cmd = f"gcc {code_path} -o {exec_path} -I/usr/local/include -L/usr/local/lib -lgmssl -Wl,-rpath=/usr/local/lib"
        compile_result = subprocess.run(compile_cmd, shell=True, capture_output=True, text=True)

        if compile_result.returncode != 0:
            error_lines = [line for line in compile_result.stderr.split('\n') if "error:" in line]
            self.last_error = "\n".join(error_lines)
            return f"编译失败:\n{self.last_error}"

        os.chmod(exec_path, 0o755)

        try:
            if auto_input is None:
                subprocess.run(
                    [exec_path],
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr
                )
            else:
                result = subprocess.run(
                    [exec_path],
                    input=auto_input,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.stdout.strip()
            return "运行成功"
        except Exception as e:
            return f"运行失败: {str(e)}"



    def _verify_c_code_vectors(self):
        """
        自动验证 AI 生成的 C 代码是否通过测试向量
        返回 True/False
        """
        if not self.generated_code:
            print("❌ 没有生成的 C 代码可验证")
            return False

        all_passed = True
        for vec in self.test_vectors:
            # 构造输入字符串，模拟终端输入：key\niv\nplaintext\n
            key_input = vec["key"] + "\n"
            iv_input = vec["iv"] + "\n"
            plaintext_input = vec["plaintext"] + "\n"
            test_input = key_input + iv_input + plaintext_input

            try:
                output = self._compile_and_run(auto_input=test_input)

                # 只保留十六进制字符
                ciphertext = "".join(re.findall(r'[0-9a-fA-F]{2}', output))

                expected = vec["expected_cbc"] if self.mode.upper() == "CBC" else vec["expected_ecb"]
                if ciphertext.lower() != expected.lower():
                    print(f"[{vec['name']}] ❌ 测试失败")
                    print(f"实际: {ciphertext}")
                    print(f"预期: {expected}")
                    all_passed = False
                else:
                    print(f"[{vec['name']}] ✅ 测试通过")

            except subprocess.TimeoutExpired:
                print(f"[{vec['name']}] ❌ 测试超时")
                all_passed = False
            except Exception as e:
                print(f"[{vec['name']}] ❌ 测试异常: {str(e)}")
                all_passed = False

        return all_passed



    def process(self):
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 ({self.algorithm}) =====")

            code, msg = self._generate_c_code()
            if not code:
                print(f"❌ 代码生成失败: {msg}")
                if input("重试？(y/n): ").lower() != 'y':
                    return
                continue

            print("\n📝 生成的加密代码：")
            print("-" * 70)
            print(code)
            print("-" * 70)

            result = self._compile_and_run(code)
            if result == "运行成功":
                print("✅ 加密成功")
                return

            print(f"❌ 操作失败: {result}")
            if input("重试？(y/n): ").lower() != 'y':
                return

        print(f"⚠️ 已达最大重试次数({self.max_retry})")
