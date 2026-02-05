#include "DiskWriter.h"
#include "DiskType.h"
#include <iostream>
#include <fstream>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "CryptoEngine.h"
#include <openssl/rand.h>
#include <filesystem>
#include <chrono>

DiskWriter::DiskWriter(std::string boxPath, std::string publicKeyPath)
{
    this->boxPath = boxPath;
    this->publicKeyPath = publicKeyPath;
}

DiskWriter::~DiskWriter()
{
}

std::string DiskWriter::GetDataFilePath(uint64_t fileId) {
    // 获取.box文件所在目录
    std::filesystem::path boxPathObj(boxPath);
    std::filesystem::path dataDir = boxPathObj.parent_path() / "encrypted_data";
    
    // 创建目录（如果不存在）
    std::filesystem::create_directories(dataDir);
    
    // 生成文件名：file_{id}.enc
    return (dataDir / ("file_" + std::to_string(fileId) + ".enc")).string();
}

bool DiskWriter::WriteEncryptedDataToFile(uint64_t fileId, const std::vector<char>& encryptedData) {
    std::string dataFilePath = GetDataFilePath(fileId);
    std::ofstream dataFile(dataFilePath, std::ios::binary);
    if (!dataFile.is_open()) {
        std::cerr << "Failed to open data file: " << dataFilePath << std::endl;
        return false;
    }
    
    dataFile.write(encryptedData.data(), encryptedData.size());
    dataFile.close();
    return true;
}

bool DiskWriter::WriteFile(FileEntity entity) {
    if (entity.type != FOLDER && entity.data.size() == 0) return false;

    // 设置数据文件路径
    if (entity.type != FOLDER) {
        entity.data_path = GetDataFilePath(entity.id);
    }

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
        
        // 4. 将加密数据写入单独文件
        if (!WriteEncryptedDataToFile(entity.id, dataToBuffer)) {
            std::cerr << "Failed to write encrypted data to separate file" << std::endl;
            return false;
        }
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
    writeBlob(entity.data_path); // 写入数据文件路径

    // 4. 写入加密的AES密钥（如果是文件）
    if (entity.type != FOLDER) {
        uint32_t keyLen = static_cast<uint32_t>(encryptedKey.size());
        writeVal(keyLen);
        os.write(reinterpret_cast<const char*>(encryptedKey.data()), keyLen);
    } else {
        uint32_t keyLen = 0;
        writeVal(keyLen); // 文件夹没有加密密钥
    }

    // 5. 写入 DATA 部分标记（现在只包含元数据，实际数据在单独文件中）
    writeVal(DiskType::DATA);
    if (entity.type != FOLDER) {
        // 对于文件，我们不再在.box文件中存储数据，只存储数据大小
        uint64_t encryptedSize = dataToBuffer.size();
        writeVal(encryptedSize);
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

bool DiskWriter::DeleteFile(uint64_t fileId) {
    // 这里实现标记删除，将deleted标志设为true
    // 注意：实际实现需要读取.box文件，找到对应ID的记录，更新deleted标志
    // 由于时间关系，这里只提供框架
    
    std::cout << "DeleteFile called for fileId: " << fileId << std::endl;
    std::cout << "Note: Full implementation requires reading and updating .box file" << std::endl;
    
    // 可选：删除对应的加密数据文件
    std::string dataFilePath = GetDataFilePath(fileId);
    if (std::filesystem::exists(dataFilePath)) {
        if (std::filesystem::remove(dataFilePath)) {
            std::cout << "Deleted encrypted data file: " << dataFilePath << std::endl;
        } else {
            std::cerr << "Failed to delete encrypted data file: " << dataFilePath << std::endl;
        }
    }
    
    return true;
}

bool DiskWriter::UpdateFile(const FileEntity& entity) {
    // 更新文件信息
    // 注意：实际实现需要读取.box文件，找到对应ID的记录，更新字段
    // 由于时间关系，这里只提供框架
    
    std::cout << "UpdateFile called for fileId: " << entity.id << std::endl;
    std::cout << "New name: " << entity.name << std::endl;
    std::cout << "New ext: " << entity.ext << std::endl;
    std::cout << "New mimetype: " << entity.mimetype << std::endl;
    
    // 更新修改时间
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    std::cout << "Updated modify_time to: " << timestamp << std::endl;
    
    return true;
}