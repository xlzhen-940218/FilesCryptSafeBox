#include "DiskReader.h"
#include <fstream>
#include <iostream>
#include "DiskType.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "CryptoEngine.h"
DiskReader::DiskReader()
{
}

DiskReader::~DiskReader()
{
}

std::vector<FileEntity> DiskReader::GetFiles(std::string boxPath, std::string privateKeyPath) {
    std::vector<FileEntity> entityQueue;
    std::ifstream is(boxPath, std::ios::in | std::ios::binary);

    if (!is.is_open()) return entityQueue;

    // 辅助 Lambda：读取基础类型
    auto readVal = [&](auto& val) {
        is.read(reinterpret_cast<char*>(&val), sizeof(val));
        };

    // 辅助 Lambda：读取变长字符串
    auto readBlob = [&](std::string& str) {
        uint32_t len = 0;
        readVal(len);
        str.resize(len);
        is.read(&str[0], len);
        };

    while (is.peek() != EOF) {
        unsigned char marker;
        readVal(marker);

        if (marker == DiskType::HEADER) {
            FileEntity entity;

            // 1. 读取固定长度字段
            readVal(entity.id);
            readVal(entity.parent_id);
            readVal(entity.type);
            readVal(entity.size);
            readVal(entity.create_time);
            readVal(entity.modify_time);
            readVal(entity.deleted);

            // 2. 读取字符串
            readBlob(entity.name);
            readBlob(entity.ext);
            readBlob(entity.mimetype);

            // 3. 读取被 RSA 加密的 AES 密钥
            uint32_t keyLen = 0;
            readVal(keyLen);
            std::vector<unsigned char> encKey(keyLen);
            if (keyLen > 0) is.read(reinterpret_cast<char*>(encKey.data()), keyLen);

            unsigned char dataMarker;
            readVal(dataMarker);
            if (dataMarker == DiskType::DATA) {
                if (entity.type != FOLDER) {
                    // 4. 读取加密数据大小
                    uint64_t encryptedSize = 0;
                    readVal(encryptedSize);
                    
                    // 5. 读取加密数据
                    std::vector<char> encryptedData(encryptedSize);
                    is.read(encryptedData.data(), encryptedSize);

                    // 6. RSA 解密获取 AES Key
                    EVP_PKEY* privkey = CryptoEngine::GetRSAPrivateKey(privateKeyPath);
                    if (!privkey) {
                        std::cerr << "Failed to get RSA private key" << std::endl;
                        continue;
                    }
                    
                    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, NULL);
                    if (!ctx) {
                        std::cerr << "Failed to create RSA decrypt context" << std::endl;
                        continue;
                    }
                    
                    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                        std::cerr << "Failed to init RSA decrypt" << std::endl;
                        EVP_PKEY_CTX_free(ctx);
                        continue;
                    }
                    
                    // 设置RSA填充模式为PKCS1（与加密时一致）
                    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
                        std::cerr << "Failed to set RSA padding" << std::endl;
                        EVP_PKEY_CTX_free(ctx);
                        continue;
                    }
                    
                    // 首先获取解密后数据的大小
                    size_t outlen = 0;
                    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encKey.data(), encKey.size()) <= 0) {
                        std::cerr << "Failed to get RSA decrypt output size" << std::endl;
                        EVP_PKEY_CTX_free(ctx);
                        continue;
                    }
                    
                    std::cout << "RSA decrypt output size: " << outlen << std::endl;
                    
                    // 分配足够大的缓冲区
                    std::vector<unsigned char> decryptedBuffer(outlen);
                    
                    // 实际解密
                    if (EVP_PKEY_decrypt(ctx, decryptedBuffer.data(), &outlen, encKey.data(), encKey.size()) <= 0) {
                        // 解密失败
                        std::cerr << "RSA decrypt AES key failed" << std::endl;
                        EVP_PKEY_CTX_free(ctx);
                        continue;
                    }
                    decryptedBuffer.resize(outlen);
                    EVP_PKEY_CTX_free(ctx);
                    
                    // 对于PKCS1填充，解密后的数据可能包含填充字节
                    // AES-256密钥应该是32字节，我们需要从解密后的数据中提取它
                    // 通常PKCS1填充会在数据前面添加一些字节
                    if (outlen < 32) {
                        std::cerr << "Decrypted data too small for AES key: " << outlen << std::endl;
                        continue;
                    }
                    
                    // 提取最后32字节作为AES密钥（PKCS1填充通常在前面）
                    unsigned char aesKey[32];
                    if (outlen == 32) {
                        // 正好是32字节，直接使用
                        memcpy(aesKey, decryptedBuffer.data(), 32);
                    } else {
                        // 有填充，取最后32字节
                        memcpy(aesKey, decryptedBuffer.data() + (outlen - 32), 32);
                    }
                    
                    // 调试：打印解密后的AES密钥前几个字节
                    std::cout << "Decrypted AES key (first 8 bytes): ";
                    for (int i = 0; i < 8; ++i) {
                        printf("%02x ", aesKey[i]);
                    }
                    std::cout << std::endl;

                    // 7. AES 硬件解密数据
                    entity.data = CryptoEngine::AES_Decrypt(encryptedData, std::vector<unsigned char>(aesKey, aesKey + 32));
                    entity.size = entity.data.size(); // 还原真实长度
                }
                else {
                    // 文件夹：读取子 ID 列表
                    uint32_t idCount = 0;
                    readVal(idCount);
                    for (uint32_t i = 0; i < idCount; ++i) {
                        uint64_t subId;
                        readVal(subId);
                        entity.ids.push_back(subId);
                    }
                }
            }
            entityQueue.push_back(entity);
        }
    }

    is.close();
    return entityQueue;
}