cmake_minimum_required(VERSION 3.22.1)
project('crypto_lib')

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出目录
set(LIBRARY_OUTPUT_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

# 查找头文件
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/jni)

# 添加 Rust 预编译库
# 根据架构选择不同的库文件
if(ANDROID_ABI STREQUAL 'arm64-v8a')
    set(RUST_LIB_PATH ${CMAKE_SOURCE_DIR}/libs/arm64-v8a/libcrypto_lib.a)
elseif(ANDROID_ABI STREQUAL 'armeabi-v7a')
    set(RUST_LIB_PATH ${CMAKE_SOURCE_DIR}/libs/armeabi-v7a/libcrypto_lib.a)
elseif(ANDROID_ABI STREQUAL 'x86_64')
    set(RUST_LIB_PATH ${CMAKE_SOURCE_DIR}/libs/x86_64/libcrypto_lib.a)
elseif(ANDROID_ABI STREQUAL 'x86')
    set(RUST_LIB_PATH ${CMAKE_SOURCE_DIR}/libs/x86/libcrypto_lib.a)
endif()

# 添加源文件
add_library(crypto_lib SHARED
    jni/crypto_jni.cpp
)

# 链接 Rust 静态库
if(EXISTS ${RUST_LIB_PATH})
    target_link_libraries(crypto_lib ${RUST_LIB_PATH})
    message(STATUS 'Found Rust library: ${RUST_LIB_PATH}')
else()
    message(WARNING 'Rust library not found for ${ANDROID_ABI}: ${RUST_LIB_PATH}')
    message(WARNING 'Please build the Rust library first for each architecture')
endif()

# 链接系统库
target_link_libraries(crypto_lib
    log
    android
)

# 复制 crypto.h 到 include 目录
configure_file(
    ${CMAKE_SOURCE_DIR}/jni/crypto.h
    ${CMAKE_SOURCE_DIR}/include/crypto.h
    COPYONLY
)
