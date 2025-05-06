SecureChat - a secure chat for online communication.

SecureChat allows users to communicate through a chat with guaranteed data protection.Encryption is performed using Advanced Encryption Standard (AES - 128).

# Using the project 🌐🔒
1. Download the Openssl library 🛠️
2. Specify the key in key.txt 🗝️
3. launching the server 🚀
4. launching the client 🚀
   
# Exchanging secret messages ✉️

# fork from https://github.com/Sergeyais/securechat

# 3p dependencies
https://wwxf.lanzn.com/ibZeE2u0gi0h

# Build
1. `cmake -B build__ -S . -DCMAKE_PREFIX_PATH=C:\Qt\6.8.3\msvc2022_64;D:\download\code\vcpkg\installed\x64-windows --fresh`
2. `cmake --build build__ --config Release`

# log
https://github.com/badaix/aixlog

# sqlite
https://github.com/SRombauts/SQLiteCpp
https://inloop.github.io/sqlite-viewer/

# httplib
https://github.com/yhirose/cpp-httplib

# vcpkg install dependencies
`vcpkg install OpenSSL SQLiteCpp rapidjson`

# charset
特性|Local8Bit|UTF-8
|---------|---------|---------|
编码范围|依赖于操作系统的本地编码|全局标准，支持所有 Unicode 字符
跨平台一致性|不一致，取决于系统环境|一致，跨平台统一
使用场景|本地化文件路径、系统交互|网络交互、文件存储、多语言支持
优缺点|快速但依赖环境，可能导致兼容性问题|通用但可能占用更多存储空间

`QString::toLocal8Bit()`
`QString::fromLocal8Bit()`

# curl send mail
`curl --url "smtps://smtp.163.com:465" --ssl-reqd --mail-from "19150952127@163.com" --mail-rcpt "wnpllr@163.com"  --upload-file mail.txt --user "19150952127@163.com:authorize_key_if_set"`

`curl --url "smtps://smtp.163.com:465" --ssl-reqd --mail-from "shxm.ma@163.com" --mail-rcpt "wnpllr@163.com"  --upload-file mail.txt --user "shxm.ma@163.com:password"`