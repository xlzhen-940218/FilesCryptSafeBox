#pragma once
#include <vector>
#include "FileEntity.h"
class DiskReader
{
public:
	DiskReader();
	~DiskReader();
	std::vector<FileEntity> GetFiles(std::string boxPath, std::string privateKeyPath);
};

