import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class DESCFBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "CFB"
        self.supported_mode = "CFB"
        
        self.mode_config = {
            "encrypt_func": "DES_cfb64_encrypt",
            "needs_iv": True,
            "key_length": 8,  # 64位密钥
            "feedback_size": 64
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"des_cfb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""


        # 测试向量（DES-CFB 8字节块）
        self.test_vectors = [
            {
                "name": "DES-CFB Test Vector 1",
                "key": "0123456789ABCDEF",          # 8字节DES密钥
                "iv":  "1234567890ABCDEF",          # 8字节IV
                "plaintext": "0123456789ABCDEF",    # 8字节明文
                "expected_ciphertext": "8CA64DE9C1B123A7"  # DES-CFB加密结果
            }
        ]

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成符合NIST DES-CFB标准的C代码"""
        base_prompt = f"""仅输出纯C代码，实现DES-{self.mode}加密，必须严格满足以下约束：

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
    unsigned char key[16];
    unsigned char iv[16];
    char key_hex[33], iv_hex[33];
    char plaintext_hex[1024];
    int num = 0;  // ✅ 修复: CFB反馈位置必须初始化为0

    printf("请输入16字节十六进制密钥（32字符）: ");
    scanf("%32s", key_hex);
    while(getchar() != '\\n');
    hex_to_bytes(key_hex, key, 16);

    printf("请输入16字节十六进制IV（32字符）: ");
    scanf("%32s", iv_hex);
    while(getchar() != '\\n');
    hex_to_bytes(iv_hex, iv, 16);

    printf("请输入要加密的明文（十六进制）: ");
    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
    if (plaintext_hex[strlen(plaintext_hex)-1] == '\\n')
        plaintext_hex[strlen(plaintext_hex)-1] = '\\0';

    size_t plaintext_len = strlen(plaintext_hex) / 2;
    unsigned char plaintext[plaintext_len];
    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);

    DES_KEY des_key;
    DES_set_encrypt_key(key, 64, &des_key);

    unsigned char ciphertext[plaintext_len];
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);
    DES_cfb64_encrypt(plaintext, ciphertext, plaintext_len,
                      &des_key, iv_copy, &num, DES_ENCRYPT);

    printf("密文: ");
    for (size_t i = 0; i < plaintext_len; i++) {{
        printf("%02x", ciphertext[i]);
    }}
    printf("\\n");

    return 0;
}}
"""
        # 调用 AI 生成代码
        messages = [
            {"role": "system", "content": "仅输出符合约束的C代码，不添加任何解释。"},
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
        code_path = os.path.join(self.work_dir, "des_cfb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(code)
        exec_path = os.path.join(self.work_dir, "des_cfb_encrypt")
        compile_cmd = f"gcc {code_path} -o {exec_path} -lcrypto -Wall -Wno-deprecated-declarations"
        compile_result = subprocess.run(compile_cmd, shell=True, capture_output=True, text=True)
        if compile_result.returncode != 0:
            self.last_error = compile_result.stderr
            return None, f"编译失败: {self.last_error}"
        os.chmod(exec_path, 0o755)
        return exec_path, "编译成功"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 最终强制修复关键部分
        c_code = c_code.replace(
            'DES_cfb64_encrypt', 
            'DES_cfb64_encrypt'  # 确保函数名正确
        )
        c_code = c_code.replace(
            'iv, &num, DES_ENCRYPT', 
            'iv_copy, &num, DES_ENCRYPT'  # 确保使用IV副本
        )

        # 修复3：调用补充的 _compile_code 方法
        exec_path, compile_msg = self._compile_code(c_code)
        if not exec_path:
            return f"编译失败: {compile_msg}"

        print("\n请输入加密信息：")
        try:
            sys.stdin.flush()
            subprocess.run([exec_path], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"

    def _fallback_c_code(self):
        """备用C代码，支持stdin输入，确保DES-CFB测试向量验证通过"""
        return r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) return 0;
    }
    return 1;
}

int main() {
    char key_hex[17], iv_hex[17], pt_hex[17];
    unsigned char key[8], iv[8], plaintext[8], ciphertext[8];
    DES_key_schedule schedule;
    int num = 0;

    printf("Enter 16-char hex key: ");
    if(!scanf("%16s", key_hex)) return 1;
    hex_to_bytes(key_hex, key, 8);

    printf("Enter 16-char hex IV: ");
    if(!scanf("%16s", iv_hex)) return 1;
    hex_to_bytes(iv_hex, iv, 8);

    printf("Enter 16-char hex plaintext: ");
    if(!scanf("%16s", pt_hex)) return 1;
    hex_to_bytes(pt_hex, plaintext, 8);

    if (DES_set_key_checked((DES_cblock*)key, &schedule) != 0) {
        printf("Key parity error\n");
        return 1;
    }

    unsigned char iv_copy[8];
    memcpy(iv_copy, iv, 8);

    DES_cfb64_encrypt(plaintext, ciphertext, 8, &schedule, (DES_cblock*)iv_copy, &num, DES_ENCRYPT);

    printf("密文: ");
    for(int i = 0; i < 8; i++) printf("%02X", ciphertext[i]);
    printf("\n");

    return 0;
}
'''



    def _run_test_vector(self, exec_path, test_vector):
        """运行NIST测试向量并验证结果"""
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
            
            # 提取并验证密文
            match = re.search(r"密文:\s*([0-9a-fA-F]+)", result.stdout)
            if not match:
                return False, "未找到密文输出"
            
            actual = match.group(1).lower()
            expected = test_vector["expected_ciphertext"].lower()
            
            if actual == expected:
                return True, f"测试通过: {actual}"
            else:
                return False, f"结果不符\n实际: {actual}\n预期: {expected}"
        except Exception as e:
            return False, f"测试失败: {str(e)}"

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
    def run_tests(self, code):
        exec_path, compile_msg = self._compile_code(code)
        if not exec_path:
            return False, f"编译失败: {compile_msg}"
        
        for vector in self.test_vectors:
            passed, msg = self._run_test_vector(exec_path, vector)
            if not passed:
                return False, msg
        return True, "✅ 所有测试向量通过"
    def process(self):
        print("请选择运行模式:\n1. 使用预制NIST模板\n2. 使用AI生成C代码")
        choice = input("输入选项(1/2): ").strip()

        if choice == "1":
            # 使用固定模板
            print("\n使用经过验证的NIST模板代码...")
            fallback_code = self._fallback_c_code()
            exec_path, compile_msg = self._compile_code(fallback_code)
            if not exec_path:
                print(f"编译失败: {compile_msg}")
                return

            # 自动运行测试向量验证
            print("\n正在验证NIST测试向量...")
            all_passed = True
            for vector in self.test_vectors:
                passed, msg = self._run_test_vector(exec_path, vector)
                print(f"[{vector['name']}] {msg}")
                if not passed:
                    all_passed = False
                    break

            if not all_passed:
                print("❌ 固定模板测试向量验证失败，请检查代码！")
                return
            print("\n✅ 所有测试向量验证通过")
            self._run_interactive(exec_path)
            return

        elif choice == "2":
            # 使用AI生成
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

                # 自动运行NIST测试向量验证
                print("\n正在验证NIST测试向量...")
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
                        # 回退到固定模板
                        print("\n使用经过验证的NIST模板...")
                        fallback_code = self._fallback_c_code()
                        exec_path, _ = self._compile_code(fallback_code)

                        # 自动验证固定模板
                        print("\n正在验证NIST测试向量（模板）...")
                        all_passed = True
                        for vector in self.test_vectors:
                            passed, msg = self._run_test_vector(exec_path, vector)
                            print(f"[{vector['name']}] {msg}")
                            if not passed:
                                all_passed = False
                                break

                        if not all_passed:
                            print("❌ 模板验证失败，请检查代码！")
                            return

                        print("\n✅ 模板测试向量验证通过")
                        self._run_interactive(exec_path)
                        return
                    continue

                print("\n✅ 所有测试向量验证通过")
                self._run_interactive(exec_path)
                return

            # 最大重试次数后使用固定模板
            print("\n⚠️ 已达最大重试次数，使用NIST模板...")
            fallback_code = self._fallback_c_code()
            exec_path, _ = self._compile_code(fallback_code)

            # 自动验证固定模板
            print("\n正在验证NIST测试向量（模板）...")
            all_passed = True
            for vector in self.test_vectors:
                passed, msg = self._run_test_vector(exec_path, vector)
                print(f"[{vector['name']}] {msg}")
                if not passed:
                    all_passed = False
                    break

            if not all_passed:
                print("❌ 模板验证失败，请检查代码！")
                return
            print("\n✅ 模板测试向量验证通过")
            self._run_interactive(exec_path)
            return

        else:
            print("无效选项，请重新运行程序。")


if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = DESCFBHelper(api_key)
    helper.process()

