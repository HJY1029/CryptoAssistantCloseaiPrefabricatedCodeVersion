import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class AESCBCHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "CBC"
        self.supported_mode = "CBC"
        
        self.mode_config = {
            "encrypt_func": "AES_cbc_encrypt",
            "needs_iv": True,
            "key_length": 16,  # 128位密钥
            "block_size": 16
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"aes_cbc_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        
        # 测试向量 - 来自NIST测试标准
        self.test_vectors = [
            {
                "name": "NIST Test Vector 1",
                "key": "2b7e151628aed2a6abf7158809cf4f3c",
                "iv": "000102030405060708090a0b0c0d0e0f",
                "plaintext": (
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710"
                ),
                "expected_ciphertext": (
                    "7649abac8119b246cee98e9b12e9197d"
                    "5086cb9b507219ee95db113a917678b2"
                    "73bed6b8e3c1743b7116e69e22229516"
                    "3ff1caa1681fac09120eca307586e1a7"
                )
            }
        ]
        for tv in self.test_vectors:
            assert re.fullmatch(r"[0-9a-fA-F]{32}", tv["key"]), f"Key 长度错误: {tv['key']}"
            assert re.fullmatch(r"[0-9a-fA-F]{32}", tv["iv"]), f"IV 长度错误: {tv['iv']}"
        
    def _force_fix_c_code(self, code: str) -> str:
        """对 AI 生成的代码做强制修复，保证行为和固定模板一致"""
        fixed = code

        # 修复1：删除所有重复的IV输入块，仅保留第一个
        iv_input_pattern = r'printf\("请输入16字节十六进制IV（32字符）: "\);.*?hex_to_bytes\(iv_hex, iv, 16\);'
        iv_blocks = re.findall(iv_input_pattern, fixed, flags=re.DOTALL)
        if len(iv_blocks) > 1:
            first_iv_block = iv_blocks[0]
            fixed = re.sub(iv_input_pattern, lambda m: first_iv_block if m.group(0) == first_iv_block else '', fixed, flags=re.DOTALL)

        # 修复2：删除IV输入后、明文输入前的所有冗余代码（包括无提示的scanf和冗余输出）
        fixed = re.sub(
            r'(hex_to_bytes\(iv_hex, iv, 16\);\s*).*?(printf\("请输入要加密的明文（十六进制）: "\);)',
            r'\1\n    \2',  # 只保留IV转换和明文输入提示
            fixed,
            flags=re.DOTALL
        )

        # 修复3：确保明文输入提示和读取逻辑正确
        if 'printf("请输入要加密的明文（十六进制）: ");' not in fixed:
            fixed = re.sub(
                r'fgets\(plaintext_hex, sizeof\(plaintext_hex\), stdin\);',
                'printf("请输入要加密的明文（十六进制）: ");\n    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);',
                fixed
            )

        # 修复4：删除冗余的IV复制（只保留一次）
        fixed = re.sub(r'memcpy\(iv_copy, iv, 16\);\s*memcpy\(iv_copy, iv, 16\);', 'memcpy(iv_copy, iv, 16);', fixed)

        # 修复5：统一换行符（替换非法换行符为标准\n）
        fixed = fixed.replace('        ', '\n').replace('    ', '\n').replace('\n\n', '\n')  # 处理多余空格和空行
       

        # 修复7：确保plaintext缓冲区清零
        if "memset(plaintext, 0" not in fixed:
            fixed = fixed.replace(
                "hex_to_bytes(plaintext_hex, plaintext, plaintext_len);",
                "memset(plaintext, 0, encrypted_len);\n    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);"
            )

        # 修复8：统一提示文本格式
        fixed = re.sub(r'printf\(".*?密钥.*?"\);', 'printf("请输入16字节十六进制密钥（32字符）: ");', fixed)
        fixed = re.sub(r'printf\(".*?IV.*?"\);', 'printf("请输入16字节十六进制IV（32字符）: ");', fixed)
        fixed = re.sub(r'printf\(".*?密文.*?"\);', 'printf("密文: ");', fixed)

        # 修复9：确保IV_copy定义和使用正确
        if "iv_copy" not in fixed:
            fixed = fixed.replace(
                "unsigned char iv[16];",
                "unsigned char iv[16];\n    unsigned char iv_copy[16];"
            )
        # 确保加密函数使用iv_copy（避免原IV被修改）
        fixed = fixed.replace(
            "AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv, AES_ENCRYPT);",
            "memcpy(iv_copy, iv, 16);\n    AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv_copy, AES_ENCRYPT);"
        )

        return fixed

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
        """生成精确符合标准的AES-CBC加密代码"""
        base_prompt = """仅输出纯C代码，实现AES-CBC加密，必须严格遵循以下标准：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 函数定义：
- hex_to_bytes：将十六进制字符串转换为字节数组
  原型：void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len);

- pkcs7_pad：强制PKCS#7填充（无论长度是否对齐）
  原型：void pkcs7_pad(unsigned char* data, size_t len, size_t block_size);

3. 主流程（严格按顺序，禁止任何多余步骤）：
   a. 变量定义：
      - unsigned char key[16], iv[16], iv_copy[16];
      - char key_hex[33], iv_hex[33], plaintext_hex[1024];

   b. 输入密钥 → 转换密钥：
      printf("请输入16字节十六进制密钥（32字符）: ");
      scanf("%32s", key_hex);
      while(getchar() != '\n');
      hex_to_bytes(key_hex, key, 16);

   c. 输入IV → 转换IV（仅一次，禁止重复）：
      printf("请输入16字节十六进制IV（32字符）: ");
      scanf("%32s", iv_hex);
      while(getchar() != '\n');
      hex_to_bytes(iv_hex, iv, 16);

   d. 输入明文 → 处理换行符：
      printf("请输入要加密的明文（十六进制）: ");
      fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
      if (plaintext_hex[strlen(plaintext_hex)-1] == '\n')
          plaintext_hex[strlen(plaintext_hex)-1] = '\0';

   e. 长度计算（必须严格按此公式）：
      size_t plaintext_len = strlen(plaintext_hex) / 2;
      size_t encrypted_len = ((plaintext_len + 15) / 16) * 16;

   f. 明文处理：
      unsigned char plaintext[encrypted_len], ciphertext[encrypted_len];
      memset(plaintext, 0, encrypted_len);  // 必须清零
      hex_to_bytes(plaintext_hex, plaintext, plaintext_len);
      pkcs7_pad(plaintext, plaintext_len, 16);  // 强制填充

   g. 加密（必须使用iv_copy）：
      AES_KEY aes_key;
      AES_set_encrypt_key(key, 128, &aes_key);
      memcpy(iv_copy, iv, 16);  // 仅复制一次
      AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv_copy, AES_ENCRYPT);

   h. 输出密文：
      printf("密文: ");
      for (size_t i = 0; i < encrypted_len; i++)
          printf("%02x", ciphertext[i]);
      printf("\n");

4. 绝对禁止：
   - 重复输入密钥/IV/明文
   - IV输入后、明文输入前有任何代码（包括scanf/fgets/printf）
   - 冗余的变量定义或函数调用
   - 任何注释或中文说明
   - 错误的长度计算公式

只输出完整C代码，无其他内容！"""

        error_feedback = "必须严格修复：1) 密钥和IV必须通过hex_to_bytes转换；2) 提示文本必须完全匹配要求；3) 密文输出前缀必须是'密文: '；4) 确保所有长度计算正确。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成符合标准的AES-CBC加密代码，确保与提供的测试向量匹配"
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
            raw_code = self.extract_c_code(raw_code)
            
            # 代码净化与强制修复
            # clean_code = re.sub(
            #     r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]',
            #     '', 
            #     raw_code, 
            #     flags=re.DOTALL
            # )
            # 改为（保留中文）
            clean_code = re.sub(
                r'//.*?\n|/\*.*?\*/|```c|```',
                '',
                raw_code,
                flags=re.DOTALL
            )
            # 修复IV重复输入
            clean_code = re.sub(
                r'(hex_to_bytes\(iv_hex, iv, 16\);\s*).*?(printf\("请输入16字节十六进制IV.*?hex_to_bytes\(iv_hex, iv, 16\);)',
                r'\1',  # 仅保留第一次IV输入
                clean_code,
                flags=re.DOTALL
            )
            # 修复明文输入提示位置
            clean_code = re.sub(
                r'(hex_to_bytes\(iv_hex, iv, 16\);\s*).*?(printf\("请输入要加密的明文.*?\);)',
                r'\1\n    \2',  # 在IV转换后直接输入明文
                clean_code,
                flags=re.DOTALL
            )          
            # 关键修复：确保完整的密钥输入流程
            if 'scanf("%32s", key_hex);' not in clean_code:
                # 插入完整的密钥输入代码块
                key_input_block = """    printf("请输入16字节十六进制密钥（32字符）: ");
    scanf("%32s", key_hex);
    while(getchar() != '\\n');
    hex_to_bytes(key_hex, key, 16);
"""
                # 在main函数开始处插入
                clean_code = re.sub(r'int main\(\)\s*\{', r'int main() {', clean_code)
                clean_code = re.sub(
                    r'(int main\(\)\s*\{\s*.*?unsigned char .*?;)',
                    r'\1\n' + key_input_block,
                    clean_code,
                    flags=re.DOTALL
                )
            
            # 关键修复：确保完整的IV输入流程
            if 'scanf("%32s", iv_hex);' not in clean_code:
                # 插入完整的IV输入代码块
                iv_input_block = """    printf("请输入16字节十六进制IV（32字符）: ");
    scanf("%32s", iv_hex);
    while(getchar() != '\\n');
    hex_to_bytes(iv_hex, iv, 16);
"""
                clean_code = re.sub(
                    r'(hex_to_bytes\(key_hex, key, 16\);\s*)',
                    r'\1\n' + iv_input_block,
                    clean_code,
                    flags=re.DOTALL
                )

            # 增强的提示文本修复逻辑
            # 1. 修复密钥提示
            clean_code = re.sub(
                r'printf\(".*?"\);.*?scanf\("%32s", key_hex\);',
                'printf("请输入16字节十六进制密钥（32字符）: ");\n    scanf("%32s", key_hex);',
                clean_code,
                flags=re.DOTALL
            )

            # 2. 修复IV提示
            clean_code = re.sub(
                r'printf\(".*?"\);.*?scanf\("%32s", iv_hex\);',
                'printf("请输入16字节十六进制IV（32字符）: ");\n    scanf("%32s", iv_hex);',
                clean_code,
                flags=re.DOTALL
            )

            # 3. 修复明文提示
            if 'printf("请输入要加密的明文（十六进制）: ");' not in clean_code:
                clean_code = re.sub(
                    r'\bfgets\(\s*plaintext_hex\s*,\s*sizeof\(plaintext_hex\)\s*,\s*stdin\s*\)\s*;',
                    'printf("请输入要加密的明文（十六进制）: ");\n    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);',
                    clean_code
                )
            clean_code = re.sub(
                r'(unsigned char iv\[16\];)',
                r'\1\nunsigned char iv_copy[16];',
                clean_code
            )
            clean_code = clean_code.replace(
                'AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv, AES_ENCRYPT);',
                'memcpy(iv_copy, iv, 16);\n    AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv_copy, AES_ENCRYPT);'
            )
            clean_code = re.sub(
                r'size_t\s+\w+\s*=\s*\(\(.*?plaintext_len\s*/\s*16.*?\)\s*\+\s*1\)\s*\*\s*16;',
                'size_t padded_len = ((plaintext_len + 15) / 16) * 16;',
                clean_code
            )
            if 'iv_copy' not in clean_code:
                clean_code = clean_code.replace(
                    'unsigned char iv[16];',
                    'unsigned char iv[16];\n    unsigned char iv_copy[16];'
                )

            clean_code = clean_code.replace(
                'AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv, AES_ENCRYPT);',
                'memcpy(iv_copy, iv, 16);\n    AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv_copy, AES_ENCRYPT);'
            )
            # 修复1：删除IV输入后的冗余"密文: "输出
            clean_code = re.sub(
                r'(hex_to_bytes\(iv_hex, iv, 16\);)\s*printf\("密文: "\);',
                r'\1',  # 仅保留IV转换
                clean_code,
                flags=re.DOTALL
            )

            # 修复2：强制正确的填充逻辑（总是填充）
            clean_code = re.sub(
                r'if \(plaintext_len % 16 != 0\)\s*pkcs7_pad',
                'pkcs7_pad',  # 移除条件判断
                clean_code
            )

            # 修复3：删除冗余的IV复制
            clean_code = re.sub(
                r'unsigned char iv_copy\[16\];\s*memcpy\(iv_copy, iv, 16\);\s*',
                '',
                clean_code
            )
            clean_code = re.sub(
                r'AES_cbc_encrypt\((.*?), (.*?), (.*?), (.*?), iv_copy, (.*?)\);',
                r'AES_cbc_encrypt(\1, \2, \3, \4, iv, \5);',
                clean_code
            )
            # --- 强制清零 plaintext ---
            if 'memset(plaintext, 0' not in clean_code:
                clean_code = clean_code.replace(
                    'hex_to_bytes(plaintext_hex, plaintext, plaintext_len);',
                    'memset(plaintext, 0, encrypted_len);\n    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);'
                )
            # 确保密钥和IV被正确转换
            if 'hex_to_bytes(key_hex, key, 16);' not in clean_code:
                clean_code = re.sub(
                    r'(scanf\("%32s", key_hex\);\n.*?while\(getchar\(\) != \'\n\'\);)',
                    r'\1\n    hex_to_bytes(key_hex, key, 16);',
                    clean_code,
                    flags=re.DOTALL
                )
            if 'hex_to_bytes(iv_hex, iv, 16);' not in clean_code:
                clean_code = re.sub(
                    r'(scanf\("%32s", iv_hex\);\n.*?while\(getchar\(\) != \'\n\'\);)',
                    r'\1\n    hex_to_bytes(iv_hex, iv, 16);',
                    clean_code,
                    flags=re.DOTALL
                )
            
            # 确保密文输出提示正确 - 增加更严格的替换
            clean_code = re.sub(
                r'printf\(".*?: "\);',
                'printf("密文: ");',
                clean_code
            )
            
            # 确保加密长度正确
            clean_code = re.sub(
                r'AES_cbc_encrypt\((.*?), (.*?), \d+, (.*?), (.*?), (.*?)\);',
                r'AES_cbc_encrypt(\1, \2, encrypted_len, \3, \4, \5);',
                clean_code
            )
            # 新增：强制检查并插入缺失的关键代码块

            required_blocks = [
                # 密钥输入流程（极简模式，只匹配关键函数和输入）
                (
                    r'printf\(".*?"\);\s*scanf\("%32s", key_hex\);\s*while\(getchar\(\) != \'\n\'\);\s*hex_to_bytes\(key_hex, key, 16\);',
                    """    printf("请输入16字节十六进制密钥（32字符）: ");
                scanf("%32s", key_hex);
                while(getchar() != '\\n');
                hex_to_bytes(key_hex, key, 16);
            """
                ),
                # IV输入流程（极简模式）
                (
                    r'printf\(".*?"\);\s*scanf\("%32s", iv_hex\);\s*while\(getchar\(\) != \'\n\'\);\s*hex_to_bytes\(iv_hex, iv, 16\);',
                    """    printf("请输入16字节十六进制IV（32字符）: ");
                scanf("%32s", iv_hex);
                while(getchar() != '\\n');
                hex_to_bytes(iv_hex, iv, 16);
            """
                )
            ]

      # 检查并插入缺失的代码块
            for pattern, code_block in required_blocks:
                if not re.search(pattern, clean_code, flags=re.DOTALL):
                    # 在main函数的变量定义后插入关键代码
                    clean_code = re.sub(
                        r'(int main\(\)\s*\{\s*.*?char plaintext_hex\[1024\];\s*)',
                        r'\1\n' + code_block,
                        clean_code,
                        flags=re.DOTALL
                    )
            # 提取密钥和IV输入块
            key_block_match = re.search(
                r'(printf\("请输入16字节十六进制密钥.*?hex_to_bytes\(key_hex, key, 16\);)',
                clean_code,
                flags=re.DOTALL
            )
            iv_block_match = re.search(
                r'(printf\("请输入16字节十六进制IV.*?hex_to_bytes\(iv_hex, iv, 16\);)',
                clean_code,
                flags=re.DOTALL
            )

            if key_block_match and iv_block_match:
                key_block = key_block_match.group(1)
                iv_block = iv_block_match.group(1)
                
                # 删除原有块
                clean_code = re.sub(re.escape(key_block), '', clean_code, flags=re.DOTALL)
                clean_code = re.sub(re.escape(iv_block), '', clean_code, flags=re.DOTALL)
                clean_code = re.sub(
                    r'(\s*)size_t\s+\w+\s*=\s*\(\(.*?plaintext_len\s*/\s*16.*?\)\s*\+\s*1\)\s*\*\s*16;',
                    r'\1size_t padded_len = ((plaintext_len + 15) / 16) * 16;',
                    clean_code
                )
                # 按正确顺序插入（先密钥后IV）
                correct_order = key_block + '\n    ' + iv_block
                clean_code = re.sub(
                    r'(int main\(\)\s*\{\s*.*?char plaintext_hex\[1024\];\s*)',
                    r'\1\n    ' + correct_order,
                    clean_code,
                    flags=re.DOTALL
                )
            # self.generated_code = clean_code.strip()
            self.generated_code = self._force_fix_c_code(clean_code.strip())

            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_code(self, code=None):
        """单独编译代码，返回可执行文件路径"""
        c_code = code or self.generated_code
        if "padded_len = ((plaintext_len / 16) + 1) * 16" in c_code:
            return None, "AI 代码包含错误的填充计算，自动拒绝"

        if not c_code:
            return None, "无代码可编译"
        # 最终检查确保所有关键步骤存在
        if 'hex_to_bytes(key_hex, key, 16);' not in c_code:
            print("⚠️ AI 代码缺少密钥转换，自动回退到固定模板")
            c_code = self._fallback_c_code()
        if 'hex_to_bytes(iv_hex, iv, 16);' not in c_code:
            return None, "代码缺少IV转换步骤"
        if 'AES_set_encrypt_key(key, 128, &aes_key);' not in c_code:
            return None, "代码缺少密钥设置步骤"

        # 最终检查确保所有转换步骤存在
        if 'hex_to_bytes(key_hex, key, 16);' not in c_code:
            c_code = c_code.replace(
                'while(getchar() != \'\\n\');',
                'while(getchar() != \'\\n\');\n    hex_to_bytes(key_hex, key, 16);',
                1
            )
        if 'hex_to_bytes(iv_hex, iv, 16);' not in c_code:
            c_code = c_code.replace(
                'while(getchar() != \'\\n\');',
                'while(getchar() != \'\\n\');\n    hex_to_bytes(iv_hex, iv, 16);',
                1
            )

        # 最后检查并修复提示文本
        if 'printf("请输入要加密的明文（十六进制）: ");' not in c_code:
            c_code = re.sub(
                r'printf\(".*?"\);.*?fgets\(plaintext_hex,.*?\);',
                'printf("请输入要加密的明文（十六进制）: ");\n    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);',
                c_code,
                flags=re.DOTALL
            )
        # 仅保留“for 循环输出密文”前的那一次“密文: ”
        c_code = re.sub(
            r'printf\("密文: "\);\s*(?!\s*for\s*\(\s*size_t)',
            '',  # 非 for 循环前的“密文: ”统统删掉
            c_code
        )    
        if 'printf("密文: ");' not in c_code:
            c_code = re.sub(
                r'printf\(".*?"\);.*?for \(size_t i = 0;.*?\);',
                'printf("密文: ");\n    for (size_t i = 0; i < encrypted_len; i++)\n        printf("%02x", ciphertext[i]);',
                c_code,
                flags=re.DOTALL
            )

        code_path = os.path.join(self.work_dir, "aes_cbc_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "aes_cbc_encrypt")
        compile_cmd = f"gcc {code_path} -o {exec_path} -lcrypto -Wall"
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
    def _fallback_c_code(self):
        """返回一个保证正确的AES-CBC C代码（与NIST向量一致）"""
        return r'''
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <openssl/aes.h>

    void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {
        for (size_t i = 0; i < len; i++) {
            sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
        }
    }

    void pkcs7_pad(unsigned char* data, size_t len, size_t block_size) {
        unsigned char pad = block_size - (len % block_size);
        if (pad == 0) return;  // 恰好对齐时不填充（NIST CBC 向量要求）
        for (size_t i = 0; i < pad; i++) {
            data[len + i] = pad;
        }
    }

    int main() {
        unsigned char key[16], iv[16], iv_copy[16];
        char key_hex[33], iv_hex[33], plaintext_hex[8192];

        if (scanf("%32s", key_hex) != 1) return 1;
        hex_to_bytes(key_hex, key, 16);

        if (scanf("%32s", iv_hex) != 1) return 1;
        hex_to_bytes(iv_hex, iv, 16);

        if (scanf("%8191s", plaintext_hex) != 1) return 1;

        size_t plaintext_len = strlen(plaintext_hex) / 2;
        size_t pad = (16 - (plaintext_len % 16)) % 16;
        size_t encrypted_len = plaintext_len + pad;

        unsigned char plaintext[encrypted_len];
        unsigned char ciphertext[encrypted_len];
        memset(plaintext, 0, encrypted_len);

        hex_to_bytes(plaintext_hex, plaintext, plaintext_len);
        if (pad) pkcs7_pad(plaintext, plaintext_len, 16);

        AES_KEY aes_key;
        AES_set_encrypt_key(key, 128, &aes_key);
        memcpy(iv_copy, iv, 16);
        AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv_copy, AES_ENCRYPT);

        printf("密文: ");
        for (size_t i = 0; i < encrypted_len; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
        return 0;
    }
    '''


    def _run_test_vector(self, exec_path, test_vector):
        """运行单个测试向量并验证结果"""
        try:
            # 构建输入字符串，逐行输入 key/iv/plaintext
            input_parts = []
            if "key" in test_vector:
                input_parts.append(test_vector["key"])
            if "iv" in test_vector and test_vector["iv"] is not None:
                input_parts.append(test_vector["iv"])
            if "plaintext" in test_vector:
                input_parts.append(test_vector["plaintext"])

            # subprocess.run(text=True) → 必须是 str
            input_data = "\n".join(input_parts) + "\n"

            # 调用编译后的 C 程序
            result = subprocess.run(
                [exec_path],
                input=input_data,         # 直接传 str，不要 encode
                capture_output=True,
                text=True,                # 开启文本模式，stdout/stderr 都是 str
                timeout=5
            )

            if result.returncode != 0:
                return False, f"程序退出码 {result.returncode}\nstderr: {result.stderr}"

            output = result.stdout.strip()
            match = re.search(r"密文:\s*([0-9a-fA-F]+)", output)
            if not match:
                return False, f"输出解析失败: {output}"
            # 抓所有“密文: ”后的 hex 串
            matches = re.findall(r"密文:\s*([0-9a-fA-F]+)", output)
            if not matches:
                return False, f"输出解析失败: {output}"

            # 方案1（推荐）：取最长的那段

            ciphertext = max(matches, key=len).lower()


            # 检查是否有 expected_ciphertext
            if test_vector.get("expected_ciphertext"):
                expected = test_vector["expected_ciphertext"].lower()
                if ciphertext != expected:
                    return False, f"结果不匹配\n预期: {expected}\n实际: {ciphertext}"
                return True, f"✅ 结果匹配 {ciphertext}"
            else:
                return True, f"✅ 运行成功，得到密文 {ciphertext}"

        except Exception as e:
            return False, f"Failed to run test vector: {e}"

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
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (AES-CBC) =====")

            code, msg = self._generate_c_code()
            if not code:
                print(f"生成失败: {msg}")
                choice = input("选择操作：1=使用固定模板, 2=继续AI生成 (默认2): ").strip()
                if choice == "1":
                    code = self._fallback_c_code()
                    test_passed, test_msg = self.run_tests(code)
                    if test_passed:
                        print(f"✅ 使用固定模板通过测试: {test_msg}")
                        self._compile_and_run(code)
                        return
                    else:
                        print(f"❌ 固定模板仍然失败: {test_msg}")
                        return
                else:
                    continue  # 继续AI生成下一轮
            else:
                print("\n生成的代码：")
                print("-" * 70)
                print(code)
                print("-" * 70)

                # 运行测试
                test_passed, test_msg = self.run_tests(code)
                if not test_passed:
                    print(f"测试失败: {test_msg}")
                    choice = input("选择操作：1=使用固定模板, 2=继续AI生成 (默认2): ").strip()
                    if choice == "1":
                        code = self._fallback_c_code()
                        test_passed, test_msg = self.run_tests(code)
                        if test_passed:
                            print(f"✅ 使用固定模板通过测试: {test_msg}")
                            self._compile_and_run(code)
                            return
                        else:
                            print(f"❌ 固定模板仍然失败: {test_msg}")
                            return
                    else:
                        continue  # 继续AI生成下一轮

                print(f"\n{test_msg}，继续进行交互式加密")

                # 编译并运行交互式程序
                exec_path, compile_msg = self._compile_code(code)
                if not exec_path:
                    print(f"编译失败: {compile_msg}")
                    choice = input("选择操作：1=使用固定模板, 2=继续AI生成 (默认2): ").strip()
                    if choice == "1":
                        code = self._fallback_c_code()
                        test_passed, test_msg = self.run_tests(code)
                        if test_passed:
                            print(f"✅ 使用固定模板通过测试: {test_msg}")
                            self._compile_and_run(code)
                            return
                        else:
                            print(f"❌ 固定模板仍然失败: {test_msg}")
                            return
                    else:
                        continue  # 继续AI生成下一轮
                if exec_path:
                    self._run_interactive(exec_path)
                

                # 最终交互运行
                result = self._compile_and_run(code)
                if result == "运行成功":
                    print("✅ 加密成功")
                    return
                else:
                    print(f"❌ 失败: {result}")
                    choice = input("选择操作：1=使用固定模板, 2=继续AI生成 (默认2): ").strip()
                    if choice == "1":
                        code = self._fallback_c_code()
                        test_passed, test_msg = self.run_tests(code)
                        if test_passed:
                            print(f"✅ 使用固定模板通过测试: {test_msg}")
                            self._compile_and_run(code)
                            return
                        else:
                            print(f"❌ 固定模板仍然失败: {test_msg}")
                            return
                    else:
                        continue  # 继续AI生成下一轮

        print("⚠️ 已达最大重试次数")


if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = AESCBCHelper(api_key)
    helper.process()
    
