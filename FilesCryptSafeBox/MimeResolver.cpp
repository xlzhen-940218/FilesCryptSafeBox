#include "MimeResolver.h"
#include <algorithm>

// 在 CPP 文件中初始化静态成员
const std::map<std::string, std::string> MimeResolver::mime_map = {
    {".txt",   "text/plain"},
    {".html",  "text/html"},
    {".htm",   "text/html"},
    {".css",   "text/css"},
    {".csv",   "text/csv"},
    {".xml",   "application/xml"},
    {".jpg",   "image/jpeg"},
    {".jpeg",  "image/jpeg"},
    {".png",   "image/png"},
    {".gif",   "image/gif"},
    {".bmp",   "image/bmp"},
    {".webp",  "image/webp"},
    {".svg",   "image/svg+xml"},
    {".ico",   "image/x-icon"},
    {".tiff",  "image/tiff"},
    {".mp3",   "audio/mpeg"},
    {".wav",   "audio/wav"},
    {".ogg",   "audio/ogg"},
    {".m4a",   "audio/mp4"},
    {".flac",  "audio/flac"},
    {".aac",   "audio/aac"},
    {".mp4",   "video/mp4"},
    {".mpeg",  "video/mpeg"},
    {".mov",   "video/quicktime"},
    {".avi",   "video/x-msvideo"},
    {".wmv",   "video/x-ms-wmv"},
    {".webm",  "video/webm"},
    {".flv",   "video/x-flv"},
    {".mkv",   "video/x-matroska"},
    {".pdf",   "application/pdf"},
    {".doc",   "application/msword"},
    {".docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".xls",   "application/vnd.ms-excel"},
    {".xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".ppt",   "application/vnd.ms-powerpoint"},
    {".pptx",  "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".epub",  "application/epub+zip"},
    {".json",  "application/json"},
    {".zip",   "application/zip"},
    {".rar",   "application/vnd.rar"},
    {".7z",    "application/x-7z-compressed"},
    {".tar",   "application/x-tar"},
    {".gz",    "application/gzip"},
    {".js",    "application/javascript"},
    {".mjs",   "application/javascript"},
    {".php",   "application/x-httpd-php"},
    {".sh",    "application/x-sh"},
    {".py",    "text/x-python"},
    {".cpp",   "text/x-c++src"},
    {".h",     "text/x-c++hdr"},
    {".java",  "text/x-java-source"},
    {".wasm",  "application/wasm"}
};

std::string MimeResolver::getMimeType(const std::string& filepath)
{
    // 1. 手动提取后缀名 (C++14 替代 std::filesystem)
    size_t dotPos = filepath.find_last_of('.');
    if (dotPos == std::string::npos) {
        return "application/octet-stream";
    }

    std::string ext = filepath.substr(dotPos);

    // 2. 转换为小写（处理 .JPG, .Png 等情况）
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
        return std::tolower(c);
        });

    // 3. 查表
    auto it = mime_map.find(ext);
    if (it != mime_map.end()) {
        return it->second;
    }

    return "application/octet-stream";
}