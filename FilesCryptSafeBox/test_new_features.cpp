#include "DiskWriter.h"
#include "DiskReader.h"
#include <fstream>
#include <iostream>
#include "MimeResolver.h"
#include <random>
#include <chrono>

std::string getFileExtension(const std::string& filename) {
    size_t dotPos = filename.find_last_of('.');
    if (dotPos != std::string::npos) {
        return filename.substr(dotPos + 1);
    }
    return "";
}

std::string getFileName(const std::string& filePath) {
    size_t lastSlash = filePath.find_last_of("/\\");
    std::string filename;
    if (lastSlash != std::string::npos) {
        filename = filePath.substr(lastSlash + 1);
    }
    else {
        filename = filePath;
    }
    return filename;
}

FileEntity createTestFileEntity(uint64_t id, const std::string& filePath) {
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open test file: " << filePath << std::endl;
        return FileEntity();
    }

    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Failed to read test file" << std::endl;
        return FileEntity();
    }
    file.close();

    struct _stat64 fileInfo;
    if (_stat64(filePath.c_str(), &fileInfo) != 0) {
        std::cerr << "Failed to get file info" << std::endl;
        return FileEntity();
    }

    FileEntity entity;
    entity.id = id;
    entity.type = FileType::TEXT;
    entity.name = getFileName(filePath);
    entity.parent_id = 0;
    entity.size = fileInfo.st_size;
    entity.create_time = fileInfo.st_ctime;
    entity.modify_time = fileInfo.st_mtime;
    entity.ext = getFileExtension(filePath);
    entity.mimetype = MimeResolver::getMimeType(filePath);
    entity.deleted = false;
    entity.data = buffer;

    return entity;
}

void testWriteAndRead() {
    std::cout << "=== 测试1: 写入和读取文件 ===" << std::endl;
    
    std::string boxPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box";
    std::string publicKeyPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\public_key.pem";
    std::string privateKeyPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\private_key.pem";
    
    // 创建测试文件实体
    FileEntity testFile = createTestFileEntity(1001, "test.txt");
    if (testFile.id == 0) {
        std::cerr << "Failed to create test file entity" << std::endl;
        return;
    }
    
    // 写入文件
    DiskWriter writer(boxPath, publicKeyPath);
    if (writer.WriteFile(testFile)) {
        std::cout << "文件写入成功" << std::endl;
    } else {
        std::cerr << "文件写入失败" << std::endl;
        return;
    }
    
    // 读取文件
    DiskReader reader;
    auto files = reader.GetFiles(boxPath, privateKeyPath);
    //std::cout << "读取到 " << files.size() << " 个文件" << std::endl;
    
    /*for (auto file : files) {
        std::cout << "文件ID: " << file.id << std::endl;
        std::cout << "文件名: " << file.name << std::endl;
        std::cout << "文件大小: " << file.size << std::endl;
        std::cout << "数据文件路径: " << file.data_path << std::endl;
        std::cout << "---" << std::endl;
    }*/
}

void testFindFileById() {
    std::cout << "\n=== 测试2: 根据文件ID查找文件 ===" << std::endl;
    
    std::string boxPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box";
    std::string privateKeyPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\private_key.pem";
    
    DiskReader reader;
    
    // 查找存在的文件
    FileEntity file = reader.GetFileById(boxPath, privateKeyPath, 1001);
    if (file.id != 0) {
        std::cout << "找到文件ID 1001:" << std::endl;
        std::cout << "  文件名: " << file.name << std::endl;
        std::cout << "  文件类型: " << file.mimetype << std::endl;
        std::cout << "  文件大小: " << file.size << " 字节" << std::endl;
    } else {
        std::cout << "未找到文件ID 1001" << std::endl;
    }
    
    // 查找不存在的文件
    FileEntity notFound = reader.GetFileById(boxPath, privateKeyPath, 9999);
    if (notFound.id == 0) {
        //std::cout << "正确：文件ID 9999 不存在" << std::endl;
    }
}

void testReadFileData() {
    std::cout << "\n=== 测试3: 读取文件内容 ===" << std::endl;
    
    std::string boxPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box";
    std::string privateKeyPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\private_key.pem";
    
    DiskReader reader;
    
    std::vector<char> data = reader.ReadFileData(boxPath, privateKeyPath, 1001);
    if (!data.empty()) {
        std::cout << "成功读取文件内容，大小: " << data.size() << " 字节" << std::endl;
        
        // 显示前100个字符（如果是文本文件）
        if (data.size() > 0) {
            std::cout << "文件内容预览（前100字节）:" << std::endl;
            size_t previewSize = std::min(data.size(), (size_t)100);
            for (size_t i = 0; i < previewSize; i++) {
                std::cout << data[i];
            }
            std::cout << std::endl;
        }
    } else {
        std::cout << "读取文件内容失败或文件不存在" << std::endl;
    }
}

void testDeleteFile() {
    std::cout << "\n=== 测试4: 删除文件 ===" << std::endl;
    
    std::string boxPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box";
    std::string publicKeyPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\public_key.pem";
    
    DiskWriter writer(boxPath, publicKeyPath);
    
    // 创建一个测试文件用于删除
    FileEntity deleteTestFile = createTestFileEntity(1002, "test_delete.txt");
    if (deleteTestFile.id == 0) {
        //std::cerr << "无法创建测试删除的文件" << std::endl;
        return;
    }
    
    if (writer.WriteFile(deleteTestFile)) {
        std::cout << "创建测试删除文件成功" << std::endl;
    }
    
    // 调用删除功能
    if (writer.DeleteFile(1002)) {
        std::cout << "删除文件调用成功" << std::endl;
        std::cout << "注意：完整实现需要更新.box文件中的deleted标志" << std::endl;
    }
}

void testUpdateFile() {
    std::cout << "\n=== 测试5: 更新文件信息 ===" << std::endl;
    
    std::string boxPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box";
    std::string publicKeyPath = "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\public_key.pem";
    
    DiskWriter writer(boxPath, publicKeyPath);
    
    // 创建一个测试文件实体用于更新
    FileEntity updateEntity;
    updateEntity.id = 1003;
    updateEntity.name = "updated_file.txt";
    updateEntity.ext = "txt";
    updateEntity.mimetype = "text/plain";
    
    if (writer.UpdateFile(updateEntity)) {
        std::cout << "更新文件信息调用成功" << std::endl;
        std::cout << "注意：完整实现需要更新.box文件中的相应字段" << std::endl;
    }
}

int main() {
   // std::cout << "开始测试 FilesCryptSafeBox 新功能" << std::endl;
    std::cout << "=================================" << std::endl;
    
    // 创建测试文件
    std::ofstream testFile1("test.txt");
    testFile1 << "这是一个测试文件，用于验证FilesCryptSafeBox的新功能。\n";
    testFile1 << "包括：\n";
    testFile1 << "1. 加密文件单独存储\n";
    testFile1 << "2. 删除功能\n";
    testFile1 << "3. 根据文件ID查找文件\n";
    testFile1 << "4. 修改文件信息\n";
    testFile1.close();
    
    std::ofstream testFile2("test_delete.txt");
    testFile2 << "这个文件用于测试删除功能。\n";
    testFile2.close();
    
    try {
        testWriteAndRead();
        testFindFileById();
        testReadFileData();
        testDeleteFile();
        testUpdateFile();
        
        std::cout << "\n=================================" << std::endl;
        std::cout << "所有测试完成！" << std::endl;
        
        // 清理测试文件
        std::remove("test.txt");
        std::remove("test_delete.txt");
        
    } catch (const std::exception& e) {
        std::cerr << "测试过程中发生异常: " << e.what() << std::endl;
        
        // 清理测试文件
        std::remove("test.txt");
        std::remove("test_delete.txt");
        
        return 1;
    }
    
    return 0;
}