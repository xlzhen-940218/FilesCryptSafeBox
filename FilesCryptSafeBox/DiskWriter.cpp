#include "DiskWriter.h"
#include "DiskType.h"
#include <iostream>
#include <fstream>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "CryptoEngine.h"
#include <openssl/rand.h>

DiskWriter::DiskWriter(std::string boxPath, std::string publicKeyPath)
{
    this->boxPath = boxPath;
    this->publicKeyPath = publicKeyPath;
}

DiskWriter::~DiskWriter()
{
}

bool DiskWriter::WriteFile(FileEntity entity) {
    if (entity.type != FOLDER && entity.data.size() == 0) return false;

    // ios::app 可能会导致读取时 seekg 定位混乱，建议使用 binary 模式管理
    std::ofstream os(boxPath, std::ios::app | std::ios::binary);
    if (!os.is_open()) return false;

    // 辅助 Lambda：写入基础类型（int, uint64_t, bool 等）
    auto writeVal = [&](auto val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
        };

    // 辅助 Lambda：写入变长字符串/数据
    auto writeBlob = [&](const std::string& str) {
        uint32_t len = static_cast<uint32_t>(str.size());
        writeVal(len); // 先写长度
        os.write(str.data(), len); // 再写内容
        };

    // --- 加密逻辑开始 ---
    std::vector<char> dataToBuffer = entity.data;
    std::vector<unsigned char> encryptedKey;

    if (entity.type != FOLDER) {
        // 1. 生成随机 AES 密钥 (硬件指令生成真随机数)
        unsigned char aesKey[32]; // AES-256
        RAND_bytes(aesKey, sizeof(aesKey));
        
        // 调试：打印AES密钥的前几个字节
        std::cout << "Generated AES key (first 8 bytes): ";
        for (int i = 0; i < 8; ++i) {
            printf("%02x ", aesKey[i]);
        }
        std::cout << std::endl;

        // 2. RSA 硬件加速加密密钥
        EVP_PKEY* pubkey = CryptoEngine::GetRSAPublicKey(publicKeyPath);
        if (!pubkey) {
            std::cerr << "Failed to get RSA public key" << std::endl;
            return false;
        }
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
        if (!ctx) {
            std::cerr << "Failed to create RSA encrypt context" << std::endl;
            return false;
        }
        
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            std::cerr << "Failed to init RSA encrypt" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        // 设置RSA填充模式为PKCS1
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            std::cerr << "Failed to set RSA padding" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, aesKey, 32) <= 0) {
            std::cerr << "Failed to get RSA encrypt output size" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        encryptedKey.resize(outlen);
        if (EVP_PKEY_encrypt(ctx, (unsigned char*)encryptedKey.data(), &outlen, aesKey, 32) <= 0) {
            std::cerr << "Failed to encrypt AES key with RSA" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        encryptedKey.resize(outlen);
        EVP_PKEY_CTX_free(ctx);
        
        std::cout << "RSA encrypted AES key size: " << encryptedKey.size() << std::endl;

        // 3. 使用 AES-NI 硬件加速加密主体数据
        dataToBuffer = CryptoEngine::AES_Encrypt(entity.data, std::vector<unsigned char>(aesKey, aesKey + 32));
    }
    // --- 加密逻辑结束 ---

    // 1. 写入头部标记
    writeVal(DiskType::HEADER);

    // 2. 写入固定长度字段
    writeVal(entity.id);
    writeVal(entity.parent_id);
    writeVal(entity.type);
    writeVal(entity.size);
    writeVal(entity.create_time);
    writeVal(entity.modify_time);
    writeVal(entity.deleted);

    // 3. 写入变长字符串字段
    writeBlob(entity.name);
    writeBlob(entity.ext);
    writeBlob(entity.mimetype);

    // 4. 写入加密的AES密钥（如果是文件）
    if (entity.type != FOLDER) {
        uint32_t keyLen = static_cast<uint32_t>(encryptedKey.size());
        writeVal(keyLen);
        os.write(reinterpret_cast<const char*>(encryptedKey.data()), keyLen);
    } else {
        uint32_t keyLen = 0;
        writeVal(keyLen); // 文件夹没有加密密钥
    }

    // 5. 写入 DATA 部分
    writeVal(DiskType::DATA);
    if (entity.type != FOLDER) {
        // 写入加密后的数据
        uint64_t encryptedSize = dataToBuffer.size();
        writeVal(encryptedSize); // 写入加密后数据的大小
        os.write(dataToBuffer.data(), encryptedSize);
    }
    else {
        // 文件夹：写入子 ID 列表
        uint32_t idCount = static_cast<uint32_t>(entity.ids.size());
        writeVal(idCount);
        for (uint64_t subId : entity.ids) {
            writeVal(subId);
        }
    }

    os.close();
    return true;
}
