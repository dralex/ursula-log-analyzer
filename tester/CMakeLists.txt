cmake_minimum_required(VERSION 3.12)

project(ursulalogchecktester VERSION 1.0)
add_executable(ursulalogchecktester main.c)
target_include_directories(ursulalogchecktester PUBLIC
			   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
			   $<INSTALL_INTERFACE:include/cyberiada>)
target_link_directories(ursulalogchecktester PUBLIC "${PROJECT_BINARY_DIR}")
target_link_libraries(ursulalogchecktester PUBLIC ursulalogcheck)
