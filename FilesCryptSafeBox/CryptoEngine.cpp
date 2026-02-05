#include "CryptoEngine.h"
#include <openssl/err.h>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <iostream>
#include <openssl/applink.c>
// AES-GCM 需要一个 12 字节的 IV（初始化向量）
const int GCM_IV_LEN = 12;
const int GCM_TAG_LEN = 16;

std::vector<char> CryptoEngine::AES_Encrypt(const std::vector<char>& plaintext, const std::vector<unsigned char>& key) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	std::vector<char> ciphertext;

	// 1. 生成随机 IV
	unsigned char iv[GCM_IV_LEN];
	RAND_bytes(iv, GCM_IV_LEN); // 调用硬件随机数生成器

	// 2. 初始化加密操作 (AES-256-GCM)
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv);

	ciphertext.resize(GCM_IV_LEN + plaintext.size() + GCM_TAG_LEN);
	// 将 IV 放在密文开头
	memcpy(ciphertext.data(), iv, GCM_IV_LEN);

	int len;
	int ciphertext_len;

	// 3. 加密数据 (此处 OpenSSL 会自动调用 AES-NI)
	EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data() + GCM_IV_LEN, &len,
		(const unsigned char*)plaintext.data(), plaintext.size());
	ciphertext_len = len;

	// 4. 完成加密
	EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + GCM_IV_LEN + len, &len);
	ciphertext_len += len;

	// 5. 获取 GCM Tag (校验码) 并放在最后
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, ciphertext.data() + GCM_IV_LEN + ciphertext_len);

	EVP_CIPHER_CTX_free(ctx);
	ciphertext.resize(GCM_IV_LEN + ciphertext_len + GCM_TAG_LEN);
	return ciphertext;
}

std::vector<char> CryptoEngine::AES_Decrypt(const std::vector<char>& ciphertext, const std::vector<unsigned char>& key) {
	if (ciphertext.size() < GCM_IV_LEN + GCM_TAG_LEN) return {};

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	std::vector<char> plaintext(ciphertext.size() - GCM_IV_LEN - GCM_TAG_LEN);

	// 1. 提取 IV (前12字节)
	unsigned char iv[GCM_IV_LEN];
	memcpy(iv, ciphertext.data(), GCM_IV_LEN);

	// 2. 初始化解密
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv);

	int len;
	int plaintext_len;

	// 3. 解密主体数据
	EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len,
		(const unsigned char*)ciphertext.data() + GCM_IV_LEN,
		ciphertext.size() - GCM_IV_LEN - GCM_TAG_LEN);
	plaintext_len = len;

	// 4. 设置预期的 GCM Tag (后16字节)
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)(ciphertext.data() + ciphertext.size() - GCM_TAG_LEN));

	// 5. 完成解密并校验完整性
	int ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	if (ret > 0) {
		plaintext.resize(plaintext_len + len);
		return plaintext;
	}
	else {
		// 校验失败（数据被篡改或密钥错误）
		return {};
	}
}



EVP_PKEY* CryptoEngine::GetRSAPublicKey(std::string keyPath) {
	static EVP_PKEY* pkey = nullptr;
	if (pkey) return pkey; // 静态单例，只加载一次

	FILE* fp;
	auto err = fopen_s(&fp, keyPath.c_str(), "r");
	if (!fp) {
		// 尝试从当前目录查找
		const char* alt_path = "public_key.pem";
		err = fopen_s(&fp, alt_path, "r");
		if (!fp) {
			std::cerr << "无法打开公钥文件: " << keyPath << " 或 " << alt_path << std::endl;
			return nullptr;
		}
	}

	// PEM_read_PUBKEY 会读取文件并分配 EVP_PKEY 结构
	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!pkey) {
		std::cerr << "读取公钥格式错误" << std::endl;
		// 打印详细的 OpenSSL 错误
		ERR_print_errors_fp(stderr);
	}
	return pkey;
}

EVP_PKEY* CryptoEngine::GetRSAPrivateKey(std::string keyPath) {
	static EVP_PKEY* pkey = nullptr;
	if (pkey) return pkey;

	FILE* fp;
	auto err = fopen_s(&fp, keyPath.c_str(), "r");
	if (!fp) {
		// 尝试从当前目录查找
		const char* alt_path = "private_key.pem";
		err = fopen_s(&fp, alt_path, "r");
		if (!fp) {
			std::cerr << "无法打开私钥文件: " << keyPath << " 或 " << alt_path << std::endl;
			return nullptr;
		}
	}

	// PEM_read_PrivateKey 读取私钥（如果私钥有密码保护，第四个参数需提供回调或密码）
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!pkey) {
		std::cerr << "读取私钥格式错误" << std::endl;
		ERR_print_errors_fp(stderr);
	}
	return pkey;
}
