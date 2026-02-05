
#include <string>
#include <vector>
#pragma once
enum FileType:uint8_t {
	TEXT, BLOB, VIDEO, AUDIO, DOCUMENT, IMAGE, COMPRESSED, FOLDER
};
struct FileEntity {
	uint64_t id;//文件id
	uint64_t parent_id;//文件夹id 0为根目录
	FileType type;//文件类型
	std::string name;//文件名或文件夹名
	uint64_t size;//文件大小（文件夹内id所占大小）
	uint64_t create_time;//创建时间
	uint64_t modify_time;//修改时间
	std::string ext;//文件后缀
	std::string mimetype;//文件类型
	bool deleted;//是否删除
	std::vector<char> data;//文件用
	std::vector<uint64_t> ids;// 文件夹用
	std::string data_path;//加密数据文件路径（新增）
};
