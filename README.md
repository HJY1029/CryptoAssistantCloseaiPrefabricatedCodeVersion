```

```

# 🔐 CryptoAssist

让自然语言驱动你的加密开发：结合 **大模型 (OpenAI)** + **OpenSSL / GmSSL**。

## ✨ 特点

- 💬 **自然语言 → 加密 C/Python 示例代码**
- 🔍 **自动编译 & 运行并返回结果**
- 🔄 **OpenSSL vs GmSSL 行为对比测试**
- 🖥️ 支持 CLI 接口（未来扩展 Web UI）
- 📦 内置多种算法 Helper 模块（AES / DES / SM4 / RSA 等）

---

## 📂 项目结构

CryptoAssist/ 

├── assistants/ 

│   ├── aes_ecb_helper.py

│   ├── aes_cbc_helper.py 

│   ├── aes_cfb_helper.py 

│   ├── aes_ofb_helper.py 

│   ├── des_ecb_helper.py 

│   ├── des_cbc_helper.py 

│   ├── des_cfb_helper.py 

│   ├── des_ofb_helper.py 

│   ├── sm4_cbc_helper.py 

│   ├── rsa_helper.py 

│   ├── gmssl_helper.py 

│   └── openssl_helper.py 

├── cli.py

├── requirements.txt 

└── README.md

| 目录 / 文件        | 作用                                     |
| ------------------ | ---------------------------------------- |
| `assistants/`      | 各类加密/解密 Helper 模块 & LLM 交互逻辑 |
| `examples/`        | 示例代码，供提示工程（Prompt）使用       |
| `tests/`           | 脚本化自动验证 OpenSSL / GmSSL 结果      |
| `cli.py`           | 命令行入口                               |
| `config.yaml`      | 配置文件（OpenSSL / GmSSL 路径等参数）   |
| `requirements.txt` | Python 依赖列表                          |

---

## 🔧 安装

### 1. 克隆项目
```bash
git clone https://github.com/HJY1029/CryptoAssist.git
cd CryptoAssist
```

### 2. 设置 Python 环境

```
bash复制代码sudo apt update && sudo apt install python3-pip python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. 安装 OpenSSL & GmSSL

#### OpenSSL

```
sudo apt install libssl-dev openssl
```

#### GmSSL

```
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

------

## 📦 Python 依赖（来自 `requirements.txt`）

| 模块           | 用途                          |
| :------------- | :---------------------------- |
| `cryptography` | 提供 Python 级加密基元接口    |
| `click`        | 命令行参数解析                |
| `pyopenssl`    | Python 对 OpenSSL 的支持      |
| `gmssl`        | 国密 GmSSL Python 封装        |
| `pyyaml`       | 配置文件解析                  |
| `requests`     | API 调用支持（如 OpenAI API） |

安装：

```
bash复制代码
pip install -r requirements.txt
```

------

## 🔑 配置 OpenAI API Key

```
bash复制代码
export OPENAI_API_KEY=your-api-key
```

------

## 🚀 使用 CLI

#### 1. SM4 加密

```
bash复制代码
python cli.py "请用 SM4 CBC 模式加密一段字符串" --backend gmssl
```

#### 2. AES ECB 加密

```
bash复制代码
python cli.py "使用 AES-256 ECB 模式加密文件 data.txt" --backend openssl
```

#### 3. DES OFB 解密

```
bash复制代码
python cli.py "用 DES OFB 模式解密 ciphertext.bin" --backend openssl
```

#### 4. RSA 签名验证

```
bash复制代码
python cli.py "生成 RSA 签名并验证消息完整性" --backend openssl
```

------

## 🧪 测试一致性

```
bash复制代码
python tests/verify.py
```

------

## 🛡️ 支持的加密算法与模式

| 库      | 类型       | 算法与模式                                         |
| :------ | :--------- | :------------------------------------------------- |
| OpenSSL | 对称加密   | AES (ECB, CBC, CFB, OFB), DES (ECB, CBC, CFB, OFB) |
| OpenSSL | 非对称加密 | RSA, ECC                                           |
| GmSSL   | 对称加密   | SM4 (CBC 模式)                                     |
| GmSSL   | 非对称加密 | SM2                                                |
| GmSSL   | 摘要       | SM3                                                |

------

## 🧠 Example Prompts for GPT

| 目标     | Prompt 示例                                                  |
| :------- | :----------------------------------------------------------- |
| AES-CBC  | "Write Python code to encrypt a file with AES-256-CBC using OpenSSL." |
| DES-OFB  | "Generate OpenSSL command to decrypt data using DES in OFB mode." |
| SM4-CBC  | "用 Python 调用 GmSSL 实现 SM4 CBC 加密字符串，并给出运行结果。" |
| RSA 签名 | "Create OpenSSL RSA signature and verification flow in Python." |

------

## 📜 License

本项目遵循 MIT License，欢迎二次开发与贡献。
