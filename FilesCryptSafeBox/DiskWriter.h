#pragma once
#include <queue>
#include "FileEntity.h"
class DiskWriter
{
public:
	DiskWriter(std::string boxPath, std::string publicKeyPath);
	~DiskWriter();
	bool WriteFile(FileEntity entity);
private:
	std::string boxPath;
	std::string publicKeyPath;
};

