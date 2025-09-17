import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class DESOFBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "OFB"
        self.supported_mode = "OFB"
        
        self.mode_config = {
            "encrypt_func": "DES_OFB_encrypt",
            "needs_iv": True,
            "key_length": 8  # 64位密钥
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"des_OFB_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

        # NIST / FIPS DES-OFB 测试向量
        # 来源: NIST SP 800-17 / FIPS PUB 81
        self.test_vectors = [
            {
                "name": "FIPS81 DES-OFB 64-bit (first block Now is t)",
                "key": "0123456789abcdef",
                "iv":  "1234567890abcdef",
                "plaintext": "4e6f772069732074",  # "Now is t" 的 hex
                "expected_ciphertext": "f3096249c7f46e51"
            }
        ]

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成符合FIPS DES-OFB标准的C代码"""
        base_prompt = f"""仅输出纯C代码，实现DES-{self.mode}加密，严格满足以下要求：

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {{
    for (size_t i = 0; i < len; i++) {{
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }}
}}

int main() {{
    unsigned char key_bytes[8];
    unsigned char iv[8];
    char key_hex[17];
    char iv_hex[17];
    char plaintext_hex[1024];

    printf("请输入8字节十六进制密钥（16字符）: ");
    scanf("%16s", key_hex);
    while(getchar() != '\\n');
    hex_to_bytes(key_hex, key_bytes, 8);

    printf("请输入8字节十六进制IV（16字符）: ");
    scanf("%16s", iv_hex);
    while(getchar() != '\\n');
    hex_to_bytes(iv_hex, iv, 8);

    printf("请输入要加密的明文（十六进制，任意长度）: ");
    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
    if (plaintext_hex[strlen(plaintext_hex)-1] == '\\n')
        plaintext_hex[strlen(plaintext_hex)-1] = '\\0';

    size_t plaintext_len = strlen(plaintext_hex) / 2;
    unsigned char plaintext[plaintext_len];
    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);

    DES_cblock key;
    memcpy(key, key_bytes, 8);
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    unsigned char ciphertext[plaintext_len];
    unsigned char iv_copy[8];
    memcpy(iv_copy, iv, 8);
    int num = 0;
    DES_ofb64_encrypt(plaintext, ciphertext, plaintext_len, &schedule, &iv_copy, &num);
    printf("密文: ");
    for (size_t i = 0; i < plaintext_len; i++) {{
        printf("%02x", ciphertext[i]);
    }}
    printf("\\n");

    return 0;
}}
"""
        messages = [
            {"role": "system", "content": "仅输出符合要求的C代码，不添加任何其他说明。"},
            {"role": "user", "content": base_prompt}
        ]
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 2000
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            raw_code = response.json()["choices"][0]["message"]["content"]
            clean_code = re.sub(r'//.*?\n|/\*.*?\*/|```c|```', '', raw_code, flags=re.DOTALL).strip()
            self.generated_code = clean_code
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"生成失败: {str(e)}"

    def _compile_code(self, code):
        if not code:
            return None, "无代码可编译"
        code_path = os.path.join(self.work_dir, "des_OFB_encrypt.c")
        with open(code_path, "w") as f:
            f.write(code)
        exec_path = os.path.join(self.work_dir, "des_OFB_encrypt")
        compile_cmd = f"gcc {code_path} -o {exec_path} -lcrypto -Wall -Wno-deprecated-declarations"
        compile_result = subprocess.run(compile_cmd, shell=True, capture_output=True, text=True)
        if compile_result.returncode != 0:
            self.last_error = compile_result.stderr
            return None, f"编译失败: {self.last_error}"
        os.chmod(exec_path, 0o755)
        return exec_path, "编译成功"

    def _fallback_c_code(self):
        """备用 DES-OFB C 代码（FIPS81 64-bit 兼容）"""
        return r'''
#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }
}

int main() {
    char key_hex[64];
    char iv_hex[64];
    char plaintext_hex[64];

    // 输入三行：key, iv, plaintext
    if (!fgets(key_hex, sizeof(key_hex), stdin)) return 1;
    if (!fgets(iv_hex, sizeof(iv_hex), stdin)) return 1;
    if (!fgets(plaintext_hex, sizeof(plaintext_hex), stdin)) return 1;

    // 去掉末尾换行
    if (key_hex[strlen(key_hex)-1] == '\n') key_hex[strlen(key_hex)-1] = '\0';
    if (iv_hex[strlen(iv_hex)-1] == '\n') iv_hex[strlen(iv_hex)-1] = '\0';
    if (plaintext_hex[strlen(plaintext_hex)-1] == '\n') plaintext_hex[strlen(plaintext_hex)-1] = '\0';

    unsigned char key_bytes[8];
    unsigned char iv[8];
    unsigned char plaintext[8];
    unsigned char ciphertext[8];

    hex_to_bytes(key_hex, key_bytes, 8);
    hex_to_bytes(iv_hex, iv, 8);
    hex_to_bytes(plaintext_hex, plaintext, 8);

    DES_cblock key;
    memcpy(key, key_bytes, 8);
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    int num = 0;
    DES_cblock iv_copy;
    memcpy(iv_copy, iv, 8);

    // 只加密 8 字节（一个分组）
    DES_ofb64_encrypt(plaintext, ciphertext, 8, &schedule, &iv_copy, &num);

    for (int i = 0; i < 8; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    return 0;
}


'''
    def _run_test_vector(self, exec_path, test_vector):
        try:
            input_data = f"{test_vector['key']}\n{test_vector['iv']}\n{test_vector['plaintext']}\n"
            result = subprocess.run(
                [exec_path],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                return False, f"运行错误: {result.stderr[:100]}"
            clean_out = result.stdout.replace("\r", "").replace("\n", "").strip()
            match = re.search(r"密文:\s*([0-9a-fA-F]{16,})", clean_out)
            if not match:
                match = re.search(r"([0-9a-fA-F]{16,})", clean_out)
            if not match:
                return False, f"未找到密文输出 (实际输出: {clean_out})"
            actual = match.group(1).lower()
            expected = test_vector["expected_ciphertext"].lower()
            if actual == expected:
                return True, f"测试通过: {actual}"
            else:
                return False, f"结果不符\n实际: {actual}\n预期: {expected}"
        except Exception as e:
            return False, f"测试失败: {str(e)}"

    def _run_interactive(self, exec_path):
        print("\n===== 开始交互式加密 =====")
        try:
            sys.stdin.flush()
            subprocess.run([exec_path], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"

    def process(self):
        print("请选择运行模式:\n1. 使用预制FIPS模板\n2. 使用AI生成C代码")
        choice = input("输入选项(1/2): ").strip()

        if choice == "1":
            print("\n使用经过验证的DES-OFB模板代码...")
            fallback_code = self._fallback_c_code()
            exec_path, compile_msg = self._compile_code(fallback_code)
            if not exec_path:
                print(f"编译失败: {compile_msg}")
                return
            print("\n正在验证测试向量...")
            all_passed = True
            for vector in self.test_vectors:
                passed, msg = self._run_test_vector(exec_path, vector)
                print(f"[{vector['name']}] {msg}")
                if not passed:
                    all_passed = False
                    break
            if not all_passed:
                print("❌ 固定模板测试向量验证失败")
                return
            print("\n✅ 所有测试向量验证通过")
            self._run_interactive(exec_path)
            return

        elif choice == "2":
            while self.retry_count < self.max_retry:
                self.retry_count += 1
                print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 =====")
                code, msg = self._generate_c_code()
                if not code:
                    print(f"生成失败: {msg}")
                    if input("重试？(y/n): ").lower() != 'y':
                        return
                    continue
                print("\n生成的代码：")
                print("-" * 70)
                print(code)
                print("-" * 70)

                exec_path, compile_msg = self._compile_code(code)
                if not exec_path:
                    print(f"编译失败: {compile_msg}")
                    if input("重试？(y/n): ").lower() != 'y':
                        return
                    continue

                print("\n正在验证测试向量...")
                all_passed = True
                for vector in self.test_vectors:
                    passed, msg = self._run_test_vector(exec_path, vector)
                    print(f"[{vector['name']}] {msg}")
                    if not passed:
                        all_passed = False
                        break
                if not all_passed:
                    print("❌ 测试向量验证失败")
                    if input("重试？(y/n): ").lower() != 'y':
                        print("\n使用模板...")
                        fallback_code = self._fallback_c_code()
                        exec_path, _ = self._compile_code(fallback_code)
                        print("\n正在验证模板测试向量...")
                        all_passed = True
                        for vector in self.test_vectors:
                            passed, msg = self._run_test_vector(exec_path, vector)
                            print(f"[{vector['name']}] {msg}")
                            if not passed:
                                all_passed = False
                                break
                        if not all_passed:
                            print("❌ 模板验证失败")
                            return
                        print("\n✅ 模板测试向量验证通过")
                        self._run_interactive(exec_path)
                        return
                    continue

                print("\n✅ 所有测试向量验证通过")
                self._run_interactive(exec_path)
                return

            print("\n⚠️ 已达最大重试次数，使用模板...")
            fallback_code = self._fallback_c_code()
            exec_path, _ = self._compile_code(fallback_code)
            print("\n正在验证模板测试向量...")
            all_passed = True
            for vector in self.test_vectors:
                passed, msg = self._run_test_vector(exec_path, vector)
                print(f"[{vector['name']}] {msg}")
                if not passed:
                    all_passed = False
                    break
            if not all_passed:
                print("❌ 模板验证失败")
                return
            print("\n✅ 模板测试向量验证通过")
            self._run_interactive(exec_path)
            return
        else:
            print("无效选项，请重新运行程序。")


if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = DESOFBHelper(api_key)
    helper.process()
