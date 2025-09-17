import argparse
import getpass
import sys
import re
from importlib import import_module  # 使用importlib优化动态导入

# 支持的算法与后端映射关系（结构化调整）
SUPPORTED_ALGORITHMS = {
    "openssl": {
        "RSA": {"internal_name": "rsa", "needs_mode": False},
        # AES算法族
        "AES-ECB": {"internal_name": "aes_ecb", "needs_mode": False},
        "AES-CBC": {"internal_name": "aes_cbc", "needs_mode": False},
        "AES-OFB": {"internal_name": "aes_ofb", "needs_mode": False},
        "AES-CFB": {"internal_name": "aes_cfb", "needs_mode": False},
        # DES算法族
        "DES-ECB": {"internal_name": "des_ecb", "needs_mode": False},
        "DES-CBC": {"internal_name": "des_cbc", "needs_mode": False},
        "DES-OFB": {"internal_name": "des_ofb", "needs_mode": False},
        "DES-CFB": {"internal_name": "des_cfb", "needs_mode": False}
    },
    "gmssl": {
        # 国密算法
        "SM4-ECB": {"internal_name": "sm4_ecb", "needs_mode": False},
        "SM4-CBC": {"internal_name": "sm4_cbc", "needs_mode": False}
    }
}

def import_helper(backend: str, algorithm: str):
    """动态导入对应的加密助手类（优化版）"""
    # 定义模块与类的映射关系，减少条件判断
    module_mapping = {
        "openssl": {
            "rsa": ("rsa_helper", "RSAHelper"),
            "aes_ecb": ("aes_ecb_helper", "AESECBHelper"),
            "aes_cbc": ("aes_cbc_helper", "AESCBCHelper"),
            "aes_ofb": ("aes_ofb_helper", "AESOFBHelper"),
            "aes_cfb": ("aes_cfb_helper", "AESCFBHelper"),
            "des_ecb": ("des_ecb_helper", "DESECBHelper"),
            "des_cbc": ("des_cbc_helper", "DESCBCHelper"),
            "des_ofb": ("des_ofb_helper", "DESOFBHelper"),
            "des_cfb": ("des_cfb_helper", "DESCFBHelper")
        },
        "gmssl": {
            "sm4_ecb": ("sm4_ecb_helper", "SM4ECBHelper"),
            "sm4_cbc": ("sm4_cbc_helper", "SM4CBCHelper")
        }
    }

    try:
        # 检查映射关系是否存在
        if backend not in module_mapping or algorithm not in module_mapping[backend]:
            raise ImportError(f"不支持的{backend}后端算法: {algorithm}")

        # 动态导入模块和类
        module_name, class_name = module_mapping[backend][algorithm]
        module = import_module(f"assistants.{module_name}")
        return getattr(module, class_name)

    except ImportError as e:
        print(f"❌ 导入助手类失败: {str(e)}")
        sys.exit(1)

def validate_api_key(api_key: str) -> bool:
    """验证OpenAI API Key有效性（通常以sk-开头，长度符合规范）"""
    # OpenAI API Key格式通常为sk-开头，后跟随机字符串
    return bool(api_key and re.match(r'^sk-[a-zA-Z0-9]{48,}$', api_key))

def get_valid_api_key():
    """独立的API Key获取函数，适配OpenAI"""
    print("\n⚠ 需要OpenAI API Key生成加密代码")
    print("  API Key格式通常为: sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    for attempt in range(3):
        api_key = getpass.getpass("请输入OpenAI API Key（输入时不显示）: ").strip()
        if not validate_api_key(api_key):
            print(f"❌ API Key无效（应为sk-开头的字符串，长度符合要求），剩余{2-attempt}次机会")
            continue
        
        confirm_key = getpass.getpass("请再次确认API Key: ").strip()
        if api_key == confirm_key:
            return api_key
        print(f"❌ 两次输入不一致，剩余{2-attempt}次机会")
    
    print("❌ 多次输入错误，程序退出")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='国密/通用加密工具（支持指定算法）',
        formatter_class=argparse.RawTextHelpFormatter  # 优化帮助信息格式
    )
    parser.add_argument(
        'algorithm', 
        type=str, 
        help=f'指定加密算法（支持列表）：\n'
             f'OpenSSL后端：{list(SUPPORTED_ALGORITHMS["openssl"].keys())}\n'
             f'GMSSL后端：{list(SUPPORTED_ALGORITHMS["gmssl"].keys())}'
    )
    parser.add_argument(
        '--backend', 
        type=str, 
        required=True, 
        choices=['openssl', 'gmssl'],
        help='加密后端（openssl/gmssl）'
    )
    parser.add_argument(
        '--debug', 
        action='store_true', 
        help='显示详细错误信息'
    )
    args = parser.parse_args()

    try:
        # 标准化算法名称
        algorithm_upper = args.algorithm.upper()
        
        # 验证算法是否支持
        if algorithm_upper not in SUPPORTED_ALGORITHMS[args.backend]:
            supported = list(SUPPORTED_ALGORITHMS[args.backend].keys())
            print(f"❌ 不支持的算法！{args.backend}后端支持：{supported}")
            sys.exit(1)
        
        # 获取算法配置
        algo_config = SUPPORTED_ALGORITHMS[args.backend][algorithm_upper]
        internal_algo = algo_config["internal_name"]
        needs_mode = algo_config["needs_mode"]
        mode = algorithm_upper.split("-")[-1] if needs_mode else None
        
        # 显示当前选择
        print(f"🔍 已选择算法：{algorithm_upper}，后端：{args.backend}")
        if needs_mode and mode:
            print(f"🔑 加密模式：{mode}")
        print("💡 流程：AI生成代码 → 展示代码 → 执行加密")

        # 获取API Key（已改为OpenAI）
        api_key = get_valid_api_key()

        # 导入助手类并初始化
        HelperClass = import_helper(args.backend, internal_algo)
        helper = HelperClass(api_key, mode=mode) if needs_mode else HelperClass(api_key)

        # 执行加密流程
        helper.process()

    except KeyboardInterrupt:
        print("\n⚠️ 用户中断操作")
        sys.exit(0)  # 中断操作是正常退出，返回0
    except Exception as e:
        print(f"❌ 程序出错：{str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
