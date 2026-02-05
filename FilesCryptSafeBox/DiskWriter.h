#pragma once
#include <queue>
#include "FileEntity.h"
#include <vector>
class DiskWriter
{
public:
	DiskWriter(std::string boxPath, std::string publicKeyPath);
	~DiskWriter();
	bool WriteFile(FileEntity entity);
	bool DeleteFile(uint64_t fileId); // 删除功能
	bool UpdateFile(const FileEntity& entity); // 更新文件信息
private:
	std::string boxPath;
	std::string publicKeyPath;
	std::string GetDataFilePath(uint64_t fileId); // 获取加密数据文件路径
	bool WriteEncryptedDataToFile(uint64_t fileId, const std::vector<char>& encryptedData); // 写入加密数据到单独文件
};

