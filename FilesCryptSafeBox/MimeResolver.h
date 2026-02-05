#pragma once
#include <string>
#include <map>
class MimeResolver {
public:
    static std::string getMimeType(const std::string& filepath);
private:
    // 仅在此处声明
    static const std::map<std::string, std::string> mime_map;
};

