#include "DiskWriter.h"
#include <fstream>
#include <iostream>
#include "MimeResolver.h"
#include "DiskReader.h"
#include <random>

std::string getFileExtension(const std::string& filename) {
	size_t dotPos = filename.find_last_of('.');
	if (dotPos != std::string::npos) {
		return filename.substr(dotPos + 1); // 返回包含"."的后缀
	}
	return ""; // 没有后缀
}

std::string getFileName(const std::string& filePath) {
	// 查找最后一个 \ 或 /
	size_t lastSlash = filePath.find_last_of("/\\");

	std::string filename;
	if (lastSlash != std::string::npos) {
		// 截取 \ 后面的部分
		filename = filePath.substr(lastSlash + 1);
	}
	else {
		filename = filePath; // 没有路径分隔符，原字符串即为文件名
	}
	return filename;
}

int main(int argc, const char* argv[]) {
	std::ifstream file(argv[1], std::ios::in | std::ios::binary);

	// 2. 获取文件大小
	file.seekg(0, std::ios::end);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	// 3. 读取数据到缓冲区
	std::vector<char> buffer(size);
	if (file.read(buffer.data(), size)) {
		std::cout << "成功读取 " << size << " 字节。" << std::endl;
	}

	// 4. 关闭文件
	file.close();

	struct _stat64 fileInfo;
	if (_stat64(argv[1], &fileInfo) == 0) {

		FileEntity entity;
		entity.id = 0;
		entity.type = FileType::TEXT;
		entity.name = getFileName(argv[1]);
		entity.parent_id = 0;
		entity.size = fileInfo.st_size;
		entity.create_time = fileInfo.st_ctime;
		entity.modify_time = fileInfo.st_mtime;
		entity.ext = getFileExtension(argv[1]);
		entity.mimetype = MimeResolver::getMimeType(argv[1]);
		entity.deleted = false;
		entity.data = buffer;
		DiskWriter writer("C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box", "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\public_key.pem");

		writer.WriteFile(entity);
	}

	DiskReader reader;
	auto files = reader.GetFiles("C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\FileCryptSafe.box", "C:\\Users\\xiong\\Documents\\FilesCryptSafeBox\\private_key.pem");
	for (auto file : files) {
		std::cout << file.id << std::endl;
		std::cout << file.type << std::endl;
		std::cout << file.name << std::endl;
		std::cout << file.parent_id << std::endl;
		std::cout << file.size << std::endl;
		std::cout << file.create_time << std::endl;
		std::cout << file.modify_time << std::endl;
		std::cout << file.ext << std::endl;
		std::cout << file.mimetype << std::endl;
		std::cout << file.deleted << std::endl;
		std::cout << file.data.data() << std::endl;
	}
}