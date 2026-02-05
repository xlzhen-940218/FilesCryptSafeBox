#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <vector>
#include <string>
// 假设我们有一个简单的 RSA 加速上下文管理
class CryptoEngine {
public:
    // 实际项目中应从文件加载密钥
    static EVP_PKEY* GetRSAPublicKey(std::string keyPath);
    static EVP_PKEY* GetRSAPrivateKey(std::string keyPath);

    // 硬件加速的 AES 加密
    static std::vector<char> AES_Encrypt(const std::vector<char>& data, const std::vector<unsigned char>& key);
    static std::vector<char> AES_Decrypt(const std::vector<char>& data, const std::vector<unsigned char>& key);
};