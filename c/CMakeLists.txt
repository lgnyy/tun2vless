# CMakeList.txt: tun2vless 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# 设置策略CMP0091为NEW，新策略
if (POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif (POLICY CMP0091)

project ("tun2vless")

#mongoose
add_definitions(-DMG_TLS_WINTLS=11 -DMG_TLS=11 -D__LITTLE_ENDIAN_BITFIELD)

set(MG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mongoose)
set(MG_SRC_DIR ${MG_DIR}/src)

include_directories(${MG_SRC_DIR})

file(GLOB MG_SRC_FILES ${MG_SRC_DIR}/*.c)


# 将源代码添加到此项目的可执行文件。
add_executable(tun2vless "tun2vless.c" "tun_wintun.c" ${MG_SRC_FILES})
#
# 设置MT/MTd
set_property(TARGET tun2vless PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	
if (WIN32)
	target_link_libraries(tun2vless Secur32.lib Crypt32.lib Iphlpapi.lib)
endif()
# TODO: 如有需要，请添加测试并安装目标。
 