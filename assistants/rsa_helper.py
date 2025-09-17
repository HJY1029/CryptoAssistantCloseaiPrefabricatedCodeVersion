import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry
from OpenSSL import crypto

class RSAHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "RSA"
        self.supported_mode = "RSA"
        
        self.mode_config = {
            "key_length": 2048,       # RSA 密钥长度
            "padding": "PKCS1_OAEP"   # 默认填充，可选 PKCS1/PKCS1_OAEP
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"RSA_cbc_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        
        self.test_vectors = [
            {
                "name": "RSA Test Vector 1",
                "public_key_pem": """-----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn...
        -----END PUBLIC KEY-----""",
                "private_key_pem": """-----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAo...
        -----END PRIVATE KEY-----""",
                "plaintext": "Hello RSA",
                "expected_ciphertext_hex": None  # 可以留空，由运行时计算
            }
        ]


      

    def _force_fix_c_code(self, code: str) -> str:
        # 对 RSA 只需保证 RSA_public_encrypt 调用正确
        code = re.sub(r"RSA_cbc_encrypt.*?;", "", code)  # 删除错误的 CBC 调用
        return code


    def extract_c_code(self,raw_output: str) -> str:
        """
        从 LLM 输出中提取 C 代码，避免误替换提示文本。
        """
        code_blocks = re.findall(r"```(?:c|C)?\s*(.*?)```", raw_output, re.DOTALL)
        if code_blocks:
            # 优先取最长的代码块，通常是正确的
            code = max(code_blocks, key=len).strip()
        else:
            # 如果没有 ``` 包裹，就直接返回全文，但去掉多余解释
            # 常见情况：AI 没加 markdown code fence
            lines = raw_output.splitlines()
            code_lines = []
            for line in lines:
                # 过滤掉明显不是代码的提示文本
                if line.strip().startswith(("请", "注意", "提示", "# ")):
                    continue
                code_lines.append(line)
            code = "\n".join(code_lines).strip()
        return code
    
    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成精确符合标准的RSA加密代码"""
        base_prompt = """仅输出纯C代码，实现RSA-CBC加密，必须严格遵循以下标准：

1. 头文件：
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

2. 主流程：
- 读取 PEM 格式公钥
- 输入明文字符串
- 调用 RSA_public_encrypt(plaintext, ciphertext, rsa_pub, RSA_PKCS1_OAEP_PADDING)
- 输出密文为 hex
- 无 IV、无 CBC、无块分组处理

    只输出完整C代码，无其他内容！"""

        error_feedback = "必须严格修复：1) 密钥和IV必须通过hex_to_bytes转换；2) 提示文本必须完全匹配；3) 密文输出前缀必须是'密文: '；4) 确保所有长度计算正确。"

        messages = [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"生成符合标准的RSA-CBC加密代码，确保与提供的测试向量匹配。错误修复：{error_feedback}"}
        ]

        payload = {
            "model": "gpt-4o-mini",
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
            print(response.status_code, response.text)
            raw_code = response.json()["choices"][0]["message"]["content"]
            raw_code = self.extract_c_code(raw_code)
            clean_code = re.sub(r'//.*?\n|/\*.*?\*/|```c|```', '', raw_code, flags=re.DOTALL)

            # 强制修复（复用你原来的 _force_fix_c_code）
            self.generated_code = self._force_fix_c_code(clean_code.strip())
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_code(self, code=None):
        """
        编译 C 代码，返回可执行文件路径和状态信息。
        - code: 可选，指定要编译的 C 代码。如果未提供，使用 self.generated_code。
        """
        c_code = code or self.generated_code
        if not c_code:
            return None, "无代码可编译"

        os.makedirs(self.work_dir, exist_ok=True)
        code_path = os.path.join(self.work_dir, "RSA_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "RSA_encrypt_exec")

        # 使用 OpenSSL libcrypto，屏蔽 deprecated 警告
        compile_cmd = f"gcc -std=c99 {code_path} -o {exec_path} -lcrypto -Wall -Wno-deprecated-declarations"

        compile_result = subprocess.run(
            compile_cmd, shell=True, capture_output=True, text=True
        )

        if compile_result.returncode != 0:
            self.last_error = compile_result.stderr
            print(f"⚠ 编译失败: {self.last_error}")
            print("ℹ️ 尝试使用固定模板 fallback 编译")
            fallback_code = self._fallback_c_code(no_padding=True)
            code_path = os.path.join(self.work_dir, "RSA_encrypt_fallback.c")
            with open(code_path, "w") as f:
                f.write(fallback_code)
            compile_result = subprocess.run(
                f"gcc -std=c99 {code_path} -o {exec_path} -lcrypto -Wall -Wno-deprecated-declarations",
                shell=True, capture_output=True, text=True
            )
            if compile_result.returncode != 0:
                self.last_error = compile_result.stderr
                return None, f"固定模板 fallback 编译失败: {self.last_error}"
            print("✅ 固定模板编译成功")

        os.chmod(exec_path, 0o755)
        return exec_path, "编译成功"

    def _fallback_c_code(self,no_padding=False):
        return r'''
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int main() {
    const char *pub_key_pem = "-----BEGIN PUBLIC KEY-----\n...-----END PUBLIC KEY-----";
    const char *plaintext = "Hello RSA";

    BIO *bio = BIO_new_mem_buf(pub_key_pem, -1);
    RSA *rsa_pub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsa_pub) { printf("读取公钥失败\n"); return 1; }

    unsigned char ciphertext[256]; // 对于2048-bit RSA
    int len = RSA_public_encrypt(strlen(plaintext), (unsigned char*)plaintext,
                                 ciphertext, rsa_pub, RSA_PKCS1_OAEP_PADDING);

    if (len < 0) {
        printf("加密失败\n");
        ERR_print_errors_fp(stdout);
        return 1;
    }

    printf("密文: ");
    for (int i = 0; i < len; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    RSA_free(rsa_pub);
    return 0;
}


'''


    def _run_test_vector(self, exec_path, test_vector):
        """
        修正测试向量字段，确保使用 public_key_pem
        """
        self.detect_mode_from_key(test_vector["public_key_pem"])

        try:
            result = subprocess.run([exec_path], capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired:
            return False, "程序运行超时"

        if result.returncode != 0:
            return False, result.stderr

        output = result.stdout
        match = re.search(r"密文:\s*([0-9a-fA-F]+)", output)
        if match:
            return True, f"生成密文: {match.group(1)}"
        return False, "未找到密文输出"
    
    def _run_interactive(self, exec_path):
        """交互式运行加密程序"""
        print("\n===== 开始交互式加密 =====")
        try:
            sys.stdin.flush()
            subprocess.run([exec_path], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, timeout=30)

            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"
    def _compile_and_run(self, code):
        exec_path, msg = self._compile_code(code)
        if not exec_path:
            return msg
        return self._run_interactive(exec_path)
    

    def detect_mode_from_key(self, key_pem):
        # RSA 使用公钥 PEM，无需校验长度
        self.mode_config["key_pem"] = key_pem


    def run_tests(self):
        self.testing_vectors = True
        exec_path, compile_msg = self._compile_code(self._fallback_c_code(no_padding=True))
        self.testing_vectors = False
        if not exec_path:
            print(f"❌ 编译失败: {compile_msg}")
            return False

        all_passed = True
        for vector in self.test_vectors:
            self.detect_mode_from_key(vector["key"])
            passed, msg = self._run_test_vector(exec_path, vector)
            if passed:
                print(f"✅ {vector['name']}: {msg}")
            else:
                print(f"❌ {vector['name']}: {msg}")
                all_passed = False

        return all_passed

    def process(self):
        print("===== 先用固定模板验证测试向量 =====")
        exec_path, msg = self._compile_code(self._fallback_c_code(no_padding=True))
        if not exec_path:
            print(f"❌ 编译失败: {msg}")
            return

        all_passed = True
        for vector in self.test_vectors:
            passed, msg = self._run_test_vector(exec_path, vector)
            if not passed:
                all_passed = False
                print(f"❌ {vector['name']} 测试未通过: {msg}")
            else:
                print(f"✅ {vector['name']} 测试通过: {msg}")

        if not all_passed:
            print("❌ 测试向量未全部通过，使用固定模板运行。")
            self._compile_and_run(self._fallback_c_code(no_padding=True))
            return

        print("✅ 所有测试向量通过，尝试 AI 生成代码")
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试生成 AI 代码 (RSA-CBC) =====")
            
            code, msg = self._generate_c_code()
            if not code:
                print(f"生成失败: {msg}")
                continue

            self.generated_code = code
            self._compile_and_run(self.generated_code)
            return


if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = RSAHelper(api_key)
    helper.process()
    
