#pragma once
#include <vector>
#include "FileEntity.h"
class DiskReader
{
public:
	DiskReader();
	~DiskReader();
	std::vector<FileEntity> GetFiles(std::string boxPath, std::string privateKeyPath);
	FileEntity GetFileById(std::string boxPath, std::string privateKeyPath, uint64_t fileId); // 根据ID查找文件
	std::vector<char> ReadFileData(std::string boxPath, std::string privateKeyPath, uint64_t fileId); // 读取文件内容
private:
	std::string GetDataFilePath(std::string boxDir, uint64_t fileId); // 获取加密数据文件路径
	std::vector<char> ReadEncryptedDataFromFile(std::string boxDir, uint64_t fileId); // 从单独文件读取加密数据
};

