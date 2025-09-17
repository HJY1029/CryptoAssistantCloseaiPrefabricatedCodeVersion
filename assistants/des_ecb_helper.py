import requests
import json
import subprocess
import os
import re
import sys
import getpass
from retrying import retry

# 修复类名拼写错误：DESECBheler → DESECBHelper
class DESECBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "ECB"
        self.supported_mode = "ECB"
        
        self.mode_config = {
            "encrypt_func": "DES_ecb_encrypt",
            "needs_iv": False,
            "key_length": 8,
            "block_size": 8
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"des_ecb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

        self.test_vectors = [
            {
                "name": "NIST ECB Example 1",
                "key": "133457799BBCDFF1",
                "iv": "",  # ECB 不需要 IV
                "plaintext": "0123456789ABCDEF",
                "expected_ciphertext": "85E813540F0AB405"
            },
        ]

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成支持用户输入的 DES-ECB 加密代码"""
        base_prompt = """仅输出纯C代码，实现 DES-ECB 加密，必须严格遵循以下标准：
1. 头文件必须包含：<stdio.h>、<stdlib.h>、<string.h>、<stddef.h>、<openssl/des.h>
2. 实现十六进制字符串转字节数组的函数：
   int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len)
   功能：将十六进制字符串转换为字节数组，失败返回0，成功返回1
3. 用户输入流程（ECB 不需要 IV）：
   - 提示用户输入16字符的十六进制密钥（8字节）
   - 提示用户输入明文（字符串）
4. 加密流程：
   - 验证输入的密钥长度是否正确（16个十六进制字符）
   - 对明文进行 PKCS#7 填充（块大小8字节）
   - 使用 DES_ecb_encrypt 进行加密（ECB 模式专用函数）
5. 输出：
   - 输入的密钥（十六进制）
   - 原始明文
   - 填充后的明文（十六进制）
   - 加密后的密文（十六进制）

只输出C代码，无任何多余文本！"""

        error_feedback = "必须修复：1) 移除所有 IV 相关逻辑（ECB 不需要 IV）；2) 使用 DES_ecb_encrypt 函数；3) 加密函数参数不需要 IV；4) 确保填充后长度为8字节的整数倍。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成支持用户输入密钥和明文的 DES-ECB 加密代码，移除所有 IV 相关逻辑"
        messages.append({"role": "user", "content": f"{user_content}。错误修复：{error_feedback}"})

        payload = {
            "model": "gpt-3.5-turbo",
            "messages": messages,
            "temperature": 0.0
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            raw_code = response.json()["choices"][0]["message"]["content"]
            
            # 代码净化与修复
            clean_code = re.sub(
                r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]',
                '', 
                raw_code, 
                flags=re.DOTALL
            )
            clean_code = clean_code.strip()
            
            # 确保必要头文件
            required_headers = [
                "#include <stdio.h>",
                "#include <stdlib.h>",
                "#include <string.h>",
                "#include <stddef.h>",
                "#include <openssl/des.h>"
            ]
            for header in required_headers:
                if header not in clean_code:
                    clean_code = header + "\n" + clean_code

            # 确保 hex_to_bytes 函数存在
            if 'hex_to_bytes' not in clean_code:
                hex_func = """int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    if (strlen(hex) != 2 * len) return 0;
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) return 0;
    }
    return 1;
}
"""
                clean_code = hex_func + "\n" + clean_code

            # 确保 PKCS#7 填充函数存在
            if 'pkcs7_pad' not in clean_code:
                pad_func = """void pkcs7_pad(unsigned char* data, size_t len, size_t block_size) {
    unsigned char pad_len = block_size - (len % block_size);
    for (size_t i = len; i < len + pad_len; i++) {
        data[i] = pad_len;
    }
}
"""
                clean_code = clean_code + "\n" + pad_func

            # 移除所有 IV 相关代码
            clean_code = re.sub(r'char iv_hex.*?\n', '', clean_code)
            clean_code = re.sub(r'unsigned char iv.*?\n', '', clean_code)
            clean_code = re.sub(r'printf\("Enter .*?IV.*?"\);.*?\n', '', clean_code)
            clean_code = re.sub(r'scanf\("%16s", iv_hex\);.*?\n', '', clean_code)
            clean_code = re.sub(r'if \(.*?iv.*?\)\n', '', clean_code)

            # 确保使用 ECB 加密函数
            clean_code = clean_code.replace("DES_ecb_encrypt", "DES_ecb_encrypt")

            self.generated_code = clean_code
            return self.generated_code, "代码生成成功（DES-ECB 模式，支持用户输入）"
        except Exception as e:
            return "", f"API错误: {str(e)}"
    def _compile_code(self, code=None):
        """单独编译代码，返回可执行文件路径"""
        c_code = code or self.generated_code
        # print("=== 编译用的 C 代码 ===")
        # print(c_code)
        # print("=====================")
        if not c_code:
            return None, "无代码可编译"

        # 如果是 fallback 代码（EVP API），直接跳过 AI 检查
        if "EVP_des_ecb" not in c_code and "DES_ecb_encrypt" not in c_code:
            # AI 代码检查
            if "padded_len = ((plaintext_len / 8) + 1) * 8" in c_code:
                return None, "AI 代码包含错误的填充计算，自动拒绝"

            # 检查 key 转换
            if not re.search(r'hex_to_bytes\s*\(\s*key_hex\s*,\s*key\s*,\s*(8|8)\s*\)', c_code):
                print("⚠️ AI 代码缺少密钥转换，自动回退到固定模板")
                c_code = self._fallback_c_code(no_padding=self.testing_vectors)
                self.generated_code = c_code

            # 检查 IV 转换
            if not re.search(r'hex_to_bytes\s*\(\s*iv_hex\s*,\s*iv\s*,\s*(8|8)\s*\)', c_code):
                print("⚠️ AI 代码缺少IV转换，自动回退到固定模板")
                c_code = self._fallback_c_code(no_padding=self.testing_vectors)
                self.generated_code = c_code

            # 检查密钥初始化
            if not ('DES_set_encrypt_key' in c_code or 'EVP_EncryptInit_ex' in c_code):
                print("⚠️ AI 代码缺少密钥初始化，自动回退到固定模板")
                c_code = self._fallback_c_code(no_padding=self.testing_vectors)
                self.generated_code = c_code

        # ===== 正式编译阶段 =====
        code_path = os.path.join(self.work_dir, "DES_ecb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "DES_ecb_encrypt")
        compile_cmd = f"gcc -std=c99 -DOPENSSL_API_COMPAT=0x00908000L {code_path} -o {exec_path} -lcrypto -Wall"
        compile_result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        if compile_result.returncode != 0:
            self.last_error = compile_result.stderr
            return None, f"编译失败: {self.last_error}"

        os.chmod(exec_path, 0o755)
        return exec_path, "编译成功"
    
    def fallback_c_code(self):
        """固定模板：FIPS/NIST 测试向量专用"""
        return r'''#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    if (strlen(hex) != 2 * len) return 0;
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) return 0;
    }
    return 1;
}

int main() {
    char key_hex[17], pt_hex[17];
    unsigned char key[8], plaintext[8], ciphertext[8];

    // 用户输入
    printf("Enter 16-character hex key: ");
    scanf("%16s", key_hex);
    printf("Enter 16-character hex plaintext: ");
    scanf("%16s", pt_hex);

    if (!hex_to_bytes(key_hex, key, 8) || !hex_to_bytes(pt_hex, plaintext, 8)) {
        printf("hex_to_bytes failed\n");
        return 1;
    }

    DES_key_schedule schedule;
    DES_set_key((DES_cblock*)key, &schedule);

    DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)ciphertext, &schedule, DES_ENCRYPT);

    printf("Key: %s\n", key_hex);
    printf("Plaintext: %s\n", pt_hex);
    printf("Ciphertext: ");
    for (int i = 0; i < 8; i++) printf("%02X", ciphertext[i]);
    printf("\n");

    return 0;
}
'''
    def run_test_vector(self, exec_path, test_vector):
        """运行单个测试向量并验证结果"""
        import re
        try:
            clean_plaintext = re.sub(r'[^0-9A-Fa-f]', '', test_vector["plaintext"]).strip()
            input_data = f"{test_vector['key']}\n{clean_plaintext}\n"

            result = subprocess.run(
                [exec_path],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return False, f"程序退出码 {result.returncode}\nstderr: {result.stderr}"

            output = result.stdout.strip()
            matches = re.findall(r"Ciphertext:\s*([0-9A-Fa-f]+)", output)
            if not matches:
                return False, f"输出解析失败: {output}"

            ciphertext = matches[0].upper()
            expected = test_vector.get("expected_ciphertext", "").upper()

            if expected:
                if ciphertext != expected:
                    return False, f"结果不匹配\n预期: {expected}\n实际: {ciphertext}"
                else:
                    return True, f"✅ 结果匹配 {ciphertext}"
            else:
                return True, f"✅ 运行成功，得到密文 {ciphertext}"

        except Exception as e:
            return False, f"运行测试异常: {e}"



    def _run_interactive(self, exec_path):
        """交互式运行加密程序"""
        print("\n===== 开始交互式加密 =====")
        try:
            sys.stdin.flush()
            subprocess.run([exec_path], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"
    def _compile_and_run(self, code):
        exec_path, msg = self._compile_code(code)
        if not exec_path:
            return msg
        return self._run_interactive(exec_path)
    

    def detect_mode_from_key(self, key_hex):
        if len(key_hex) == 48:  # 24字节 => 3DES
            self.mode_config["key_length"] = 24
            self.mode_config["encrypt_func"] = "EVP_des_ede3_ecb"
        elif len(key_hex) == 16:  # 8字节 => 单DES
            self.mode_config["key_length"] = 8
            self.mode_config["encrypt_func"] = "EVP_des_ecb"
        else:
            raise ValueError(f"不支持的 key 长度: {len(key_hex)//2} 字节")
    

    def run_tests(self):
        self.testing_vectors = True
        exec_path, compile_msg = self._compile_code(self.fallback_c_code())

        self.testing_vectors = False
        if not exec_path:
            print(f"❌ 编译失败: {compile_msg}")
            return False

        all_passed = True
        for vector in self.test_vectors:
            self.detect_mode_from_key(vector["key"])
            passed, msg = self.run_test_vector(exec_path, vector)
            if passed:
                print(f"✅ {vector['name']}: {msg}")
            else:
                print(f"❌ {vector['name']}: {msg}")
                all_passed = False

        return all_passed


    def process(self):
        # 用户选择使用固定模板还是 AI 生成代码
        print("请选择加密模式：")
        print("1) 使用固定模板代码（测试向量专用）")
        print("2) 使用 AI 生成代码（支持用户输入密钥和明文）")
        choice = input("输入 1 或 2: ").strip()

        if choice == "1":
            print("🔹 使用固定模板代码进行测试")
            code = self.fallback_c_code()
            exec_path, compile_msg = self._compile_code(code)
            
            if not exec_path:
                print(f"❌ 编译失败: {compile_msg}")
                return
            # 仅运行测试向量，不进入交互式加密
            all_passed = True
            for vector in self.test_vectors:
                self.detect_mode_from_key(vector["key"])
                passed, msg = self.run_test_vector(exec_path, vector)
                if passed:
                    print(f"✅ {vector['name']}: {msg}")
                else:
                    print(f"❌ {vector['name']}: {msg}")
                    all_passed = False
            if not all_passed:
                print("❌ 测试向量未通过，请检查代码")
            self._run_interactive(exec_path)

        elif choice == "2":
            print("🔹 使用 AI 生成代码进行交互式加密")
            code, msg = self._generate_c_code()
            if not code:
                print(f"生成失败: {msg}")
                print("❌ 回退到固定模板（非交互式）")
                return
            exec_path, compile_msg = self._compile_code(code)
            if not exec_path:
                print(f"❌ 编译失败: {compile_msg}")
                return
            # AI 生成的代码支持用户输入，进入交互式加密
            self._run_interactive(exec_path)
        else:
            print("❌ 无效选择")
            return



if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = DESECBHelper(api_key)
    helper.process()
    
