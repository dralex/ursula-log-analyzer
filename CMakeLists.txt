cmake_minimum_required(VERSION 3.12)

project(ursulalogcheck VERSION 1.0 LANGUAGES C)

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sha256.c)
  message(FATAL_ERROR "Cannot find sha256.c file (download here: https://github.com/jb55/sha256.c)")
endif()
if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sha256.h)
  message(FATAL_ERROR "Cannot find sha256.h file (download here: https://github.com/jb55/sha256.c)")
endif()
if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/rotate-bits)
  message(FATAL_ERROR "Cannot find rotate-bits directory (download here: https://github.com/jb55/sha256.c)")
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D__DEBUG__")

if(CMAKE_BUILD_TYPE STREQUAL Debug)
  add_compile_options(-Wall)
  add_compile_options(-Wextra) 
  add_compile_options(-Wpedantic)
endif()

add_library(ursulalogcheck SHARED
			ursulalogcheck.c
			sha256.c
)

target_include_directories(ursulalogcheck PUBLIC
                                       	  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
			               	  $<INSTALL_INTERFACE:include/cyberiada>)
target_link_libraries(ursulalogcheck PUBLIC m)

add_library(ursulalogcheck_log SHARED
			ursulalogcheck.c
			sha256.c
)
target_compile_definitions(ursulalogcheck_log PUBLIC -DFULL_LOGS)
target_include_directories(ursulalogcheck_log PUBLIC
                                       	  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(ursulalogcheck_log PUBLIC m)

add_subdirectory(tester)

install(TARGETS ursulalogcheck DESTINATION lib EXPORT ursulalogcheck)
install(FILES ursulalogcheck.h ${CMAKE_CURRENT_SOURCE_DIR}/ursulalogcheck.h
        DESTINATION include/cyberiada)
