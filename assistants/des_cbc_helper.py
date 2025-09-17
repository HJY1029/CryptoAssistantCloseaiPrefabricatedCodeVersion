import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class DESCBCHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "CBC"
        self.supported_mode = "CBC"
        
        self.mode_config = {
            "encrypt_func": None,  # 初始化后动态设置
            "needs_iv": True,
            "key_length": None,    # 动态根据检测设置
            "block_size": 8
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"aes_cbc_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        
        self.test_vectors = [
            {
                "name": "NIST DES CBC Test Vector 1",
                "key": "0123456789abcdef",
                "iv": "1234567890abcdef",
                "plaintext": "4e6f77206973207468652074696d6520666f7220616c6c20",
                "expected_ciphertext": "e5c7cdde872bf27c43e934008c389c0f6837884997d94cfdcda5f90b12a3815a"
            },
            {
                "name": "NIST 3DES CBC Example 1",
                "key": "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123",  # 24字节
                "iv": "0000000000000000",
                "plaintext": "5468697320697320736f6d652074657874202e2e2e202020",
                "expected_ciphertext": "5cdda60cd4d2beba674e3b8246b08dd7a9b9fca18e8c8d0a"
            },
        ]
        # 在 __init__ 里 test_vectors 定义完之后加：
        first_key_len = len(self.test_vectors[0]["key"])
        if first_key_len == 16:
            self.mode_config["key_length"] = 8
            self.mode_config["encrypt_func"] = "EVP_des_cbc"
        elif first_key_len == 48:
            self.mode_config["key_length"] = 24
            self.mode_config["encrypt_func"] = "EVP_des_ede3_cbc"
        else:
            raise ValueError(f"不支持的 key 字节长度: {first_key_len//2}")

        expected_hex_len_iv = self.mode_config["block_size"] * 2

        for tv in self.test_vectors:
            key_hex_len = len(tv["key"])
            if key_hex_len == 16:      # 8 字节单 DES
                pass
            elif key_hex_len == 48:    # 24 字节 3DES
                pass
            else:
                raise AssertionError(f"Key 长度错误: {tv['key']} (len={key_hex_len})")

            assert re.fullmatch(rf"[0-9a-fA-F]{{{expected_hex_len_iv}}}", tv["iv"]), \
                f"IV 长度错误: {tv['iv']}"

    def _force_fix_c_code(self, code: str) -> str:
        """自动修复生成的 C 代码，适配 AES/DES"""
        key_len_bytes = self.mode_config["key_length"]
        block_size_bytes = self.mode_config["block_size"]

        key_len_hex = key_len_bytes
        block_len_hex = block_size_bytes

        # 修复 key 数组大小
        code = re.sub(
            r"unsigned char key\[\d+\], iv\[\d+\], iv_copy\[\d+\];",
            f"unsigned char key[{key_len_hex}], iv[{block_len_hex}], iv_copy[{block_len_hex}];",
            code
        )

        # 修复 hex_to_bytes 调用中的长度
        code = re.sub(
            r"hex_to_bytes\(key_hex, key, \d+\);",
            f"hex_to_bytes(key_hex, key, {key_len_hex});",
            code
        )
        code = re.sub(
            r"hex_to_bytes\(iv_hex, iv, \d+\);",
            f"hex_to_bytes(iv_hex, iv, {block_len_hex});",
            code
        )

        # 修复 block_size
        code = re.sub(
            r"pkcs7_pad\(plaintext, plaintext_len, \d+\);",
            f"pkcs7_pad(plaintext, plaintext_len, {block_size_bytes});",
            code
        )

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
        """生成精确符合标准的DES-CBC加密代码"""
        base_prompt = """仅输出纯C代码，实现DES-CBC加密，必须严格遵循以下标准：

    1. 头文件：
    #include <stddef.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <openssl/des.h>
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    2. 函数定义：
    - hex_to_bytes：将十六进制字符串转换为字节数组
    原型：void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len);

    - pkcs7_pad：强制PKCS#7填充（无论长度是否对齐）
    原型：void pkcs7_pad(unsigned char* data, size_t len, size_t block_size);

    3. 主流程（严格按顺序，禁止任何多余步骤）：
    a. 变量定义：
        - unsigned char key[8], iv[8], iv_copy[8];
        - char key_hex[17], iv_hex[17], plaintext_hex[1024];

    b. 输入密钥 → 转换密钥：
        printf("请输入8字节十六进制密钥（16字符）: ");
        scanf("%16s", key_hex);
        while(getchar() != '\\n');
        hex_to_bytes(key_hex, key, 8);

    c. 输入IV → 转换IV（仅一次，禁止重复）：
        printf("请输入8字节十六进制IV（16字符）: ");
        scanf("%16s", iv_hex);
        while(getchar() != '\\n');
        hex_to_bytes(iv_hex, iv, 8);

    d. 输入明文 → 处理换行符：
        printf("请输入要加密的明文（十六进制）: ");
        fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
        if (plaintext_hex[strlen(plaintext_hex)-1] == '\\n')
            plaintext_hex[strlen(plaintext_hex)-1] = '\\0';

    e. 长度计算：
        size_t plaintext_len = strlen(plaintext_hex) / 2;
        size_t encrypted_len = ((plaintext_len + 7) / 8) * 8;

    f. 明文处理：
        unsigned char plaintext[encrypted_len], ciphertext[encrypted_len];
        memset(plaintext, 0, encrypted_len);
        hex_to_bytes(plaintext_hex, plaintext, plaintext_len);
        pkcs7_pad(plaintext, plaintext_len, 8);

    g. 加密（必须使用iv_copy）：
        DES_cblock key_block;
        DES_key_schedule schedule;
        memcpy(key_block, key, 8);
        DES_set_key_unchecked(&key_block, &schedule);
        memcpy(iv_copy, iv, 8);
        DES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &schedule, &iv_copy, DES_ENCRYPT);

    h. 输出密文：
        printf("密文: ");
        for (size_t i = 0; i < encrypted_len; i++)
            printf("%02x", ciphertext[i]);
        printf("\\n");

    4. 绝对禁止：
    - 重复输入密钥/IV/明文
    - 冗余的变量定义或函数调用
    - 任意注释或中文说明
    - 错误的长度计算公式

    只输出完整C代码，无其他内容！"""

        error_feedback = "必须严格修复：1) 密钥和IV必须通过hex_to_bytes转换；2) 提示文本必须完全匹配；3) 密文输出前缀必须是'密文: '；4) 确保所有长度计算正确。"

        messages = [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"生成符合标准的DES-CBC加密代码，确保与提供的测试向量匹配。错误修复：{error_feedback}"}
        ]

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
        """单独编译代码，返回可执行文件路径"""
        c_code = code or self.generated_code
        # print("=== 编译用的 C 代码 ===")
        # print(c_code)
        # print("=====================")
        if not c_code:
            return None, "无代码可编译"

        # 如果是 fallback 代码（EVP API），直接跳过 AI 检查
        if "EVP_des_cbc" not in c_code and "DES_cbc_encrypt" not in c_code:
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
        code_path = os.path.join(self.work_dir, "DES_cbc_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "DES_cbc_encrypt")
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
    

    def _fallback_c_code(self, no_padding=False):
        """返回一个保证正确的 DES-CBC C 代码（兼容 OpenSSL 3.x）"""
        if no_padding:
            return r'''
#include <openssl/des.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void hex_to_bytes(const char *hex, unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &buf[i]);
    }
}

void trim_str(char *str) {
    size_t len = strlen(str);
    while (len > 0 &&
           (str[len - 1] == '\n' || str[len - 1] == '\r' ||
            str[len - 1] == ' '  || str[len - 1] == '\t')) {
        str[--len] = '\0';
    }
}

int main() {
    char key_hex[49] = {0}; // 最长24字节key => 48 hex
    char iv_hex[17]  = {0};
    char pt_hex[8192] = {0};

    // 输入 KEY
    if (scanf("%48s", key_hex) != 1) return 1;
    while (getchar() != '\n' && !feof(stdin));

    size_t key_len_bytes = strlen(key_hex) / 2;
    unsigned char key[key_len_bytes];
    hex_to_bytes(key_hex, key, key_len_bytes);

    // 输入 IV
    if (scanf("%16s", iv_hex) != 1) return 1;
    while (getchar() != '\n' && !feof(stdin));
    unsigned char iv[8];
    hex_to_bytes(iv_hex, iv, 8);

    // 输入明文
    if (!fgets(pt_hex, sizeof pt_hex, stdin)) return 1;
    trim_str(pt_hex);
    size_t pt_len = strlen(pt_hex) / 2;
    if (pt_len % 8 != 0) {
        fprintf(stderr, "明文字节数必须是8的倍数（无填充模式）\n");
        return 1;
    }
    unsigned char plaintext[pt_len], ciphertext[pt_len];
    hex_to_bytes(pt_hex, plaintext, pt_len);

    if (key_len_bytes == 8) {
        // === 单 DES ===
        DES_cblock k1;
        DES_key_schedule ks1;
        memcpy(k1, key, 8);
        DES_set_key_unchecked(&k1, &ks1);

        DES_cblock iv_block;
        memcpy(iv_block, iv, 8);

        DES_cbc_encrypt(plaintext, ciphertext, pt_len, &ks1, &iv_block, DES_ENCRYPT);

    } else if (key_len_bytes == 16) {
        // === 2-Key 3DES: K1 || K2 || K1 ===
        DES_cblock k1, k2, k3;
        DES_key_schedule ks1, ks2, ks3;

        memcpy(k1, key, 8);
        memcpy(k2, key + 8, 8);
        memcpy(k3, key, 8); // K3 = K1

        DES_set_key_unchecked(&k1, &ks1);
        DES_set_key_unchecked(&k2, &ks2);
        DES_set_key_unchecked(&k3, &ks3);

        DES_cblock iv_block;
        memcpy(iv_block, iv, 8);

        DES_ede3_cbc_encrypt(plaintext, ciphertext, pt_len,
                             &ks1, &ks2, &ks3, &iv_block, DES_ENCRYPT);

    } else if (key_len_bytes == 24) {
        // === 3-Key 3DES: K1 || K2 || K3 ===
        DES_cblock k1, k2, k3;
        DES_key_schedule ks1, ks2, ks3;

        memcpy(k1, key, 8);
        memcpy(k2, key + 8, 8);
        memcpy(k3, key + 16, 8);

        DES_set_key_unchecked(&k1, &ks1);
        DES_set_key_unchecked(&k2, &ks2);
        DES_set_key_unchecked(&k3, &ks3);

        DES_cblock iv_block;
        memcpy(iv_block, iv, 8);

        DES_ede3_cbc_encrypt(plaintext, ciphertext, pt_len,
                             &ks1, &ks2, &ks3, &iv_block, DES_ENCRYPT);
    } else {
        fprintf(stderr, "不支持的key长度 %zu 字节\n", key_len_bytes);
        return 1;
    }

    printf("密文: ");
    for (size_t i = 0; i < pt_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
    '''
        else:
            return r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }
}

void pkcs7_pad(unsigned char* data, size_t len, size_t block_size) {
    unsigned char pad = block_size - (len % block_size);
    for (size_t i = 0; i < pad; i++) {
        data[len + i] = pad;
    }
}

int main() {

    unsigned char key[8], iv[8];
    char key_hex[17], iv_hex[17], plaintext_hex[8192];

    // 输入密钥
    printf("请输入8字节十六进制密钥（16字符）: ");
    if (scanf("%16s", key_hex) != 1) return 1;
    while (getchar() != '\n');
    hex_to_bytes(key_hex, key, 8);

    // 输入IV
    printf("请输入8字节十六进制IV（16字符）: ");
    if (scanf("%16s", iv_hex) != 1) return 1;
    while (getchar() != '\n');
    hex_to_bytes(iv_hex, iv, 8);

    // 输入明文
    printf("请输入要加密的明文（十六进制）: ");
    if (!fgets(plaintext_hex, sizeof(plaintext_hex), stdin)) return 1;
    size_t len_pt_hex = strlen(plaintext_hex);
    while (len_pt_hex > 0 &&
          (plaintext_hex[len_pt_hex - 1] == '\n' || plaintext_hex[len_pt_hex - 1] == '\r')) {
        plaintext_hex[--len_pt_hex] = '\0';
    }
    // 去掉 \r 和 \n
size_t len_pt_hex = strcspn(pt_hex, "\r\n");
pt_hex[len_pt_hex] = '\0';

// 调试输出（测试阶段用，stderr 打印避免被正则忽略）
fprintf(stderr, "DEBUG: raw pt_hex='%s'\n", pt_hex);
fprintf(stderr, "DEBUG: len_pt_hex=%zu\n", len_pt_hex);
    size_t plaintext_len = strlen(plaintext_hex) / 2;
    size_t encrypted_len = ((plaintext_len + 7) / 8) * 8;

    unsigned char plaintext[encrypted_len];
    unsigned char ciphertext[encrypted_len];
    memset(plaintext, 0, encrypted_len);
    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);
    pkcs7_pad(plaintext, plaintext_len, 8);

    DES_cblock key_block;
    DES_key_schedule schedule;
    memcpy(key_block, key, 8);
    DES_set_key_unchecked(&key_block, &schedule);

    DES_cblock iv_block;
    memcpy(iv_block, iv, 8);

    DES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &schedule, &iv_block, DES_ENCRYPT);

    printf("密文: ");
    for (size_t i = 0; i < encrypted_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    return 0;
}
'''


    def _run_test_vector(self, exec_path, test_vector):
        """运行单个测试向量并验证结果，输出 stderr 调试信息"""
        try:
            import re
            # 纯净化明文，去掉所有非hex字符
            clean_plaintext = re.sub(r'[^0-9A-Fa-f]', '', test_vector["plaintext"]).strip()

            # ✅ 保证严格三行 key/iv/plaintext，结尾有换行符
            input_data = f"{test_vector['key']}\n{test_vector['iv']}\n{clean_plaintext}\n".replace("\r", "")
            print(f"[DEBUG Python] sending to C:\n{repr(input_data)}")

            # 调用可执行文件
            result = subprocess.run(
                [exec_path],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=5
            )

            # 输出调试信息（stderr）
            if result.stderr.strip():
                print(f"--- 调试信息 ({test_vector['name']}) ---")
                print(result.stderr.strip())
                print("-------------------------------")

            if result.returncode != 0:
                return False, f"程序退出码 {result.returncode}\nstderr: {result.stderr}"

            output = result.stdout.strip()

            # 提取密文
            matches = re.findall(r"密文:\s*([0-9A-Fa-f]+)", output)
            if not matches:
                return False, f"输出解析失败: {output}"

            ciphertext = max(matches, key=len).lower()
            expected = test_vector.get("expected_ciphertext", "").lower()

            if expected and re.fullmatch(r"[0-9a-f]+", expected):
                if ciphertext != expected:
                    return False, f"结果不匹配\n预期: {expected}\n实际: {ciphertext}"
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
            self.mode_config["encrypt_func"] = "EVP_des_ede3_cbc"
        elif len(key_hex) == 16:  # 8字节 => 单DES
            self.mode_config["key_length"] = 8
            self.mode_config["encrypt_func"] = "EVP_des_cbc"
        else:
            raise ValueError(f"不支持的 key 长度: {len(key_hex)//2} 字节")
    

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
        print("\n===== 测试阶段：NIST DES-CBC 向量验证（无填充） =====")
        tests_passed = self.run_tests()
        if not tests_passed:
            print("\n❌ 存在测试未通过，切换到固定模板（无填充）")
            self.generated_code = self._fallback_c_code(no_padding=True)
            self._compile_and_run(self.generated_code)
            return

        print("\n✅ 所有测试向量通过，进入 AI 代码生成阶段")
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试生成 AI 代码 (DES-CBC) =====")
            
            code, msg = self._generate_c_code()
            if not code:
                print(f"生成失败: {msg}")
                continue

            self.generated_code = code
            self._compile_and_run(self.generated_code)
            return


if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = DESCBCHelper(api_key)
    helper.process()
    
