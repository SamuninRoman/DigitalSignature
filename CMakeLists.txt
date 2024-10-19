cmake_minimum_required(VERSION 3.10)
set(CMAKE_C_STANDARD 11)
project(DigitalSignature)

# Добавление необходимых библиотек
find_package(OpenSSL REQUIRED)

# Исходные файлы
add_executable(DigitalSignature src/main.c)
target_link_libraries(DigitalSignature OpenSSL::Crypto)