cmake_minimum_required(VERSION 3.16)

# wifix component 在 ../.. 目录
get_filename_component(WIFIX_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(EXTRA_COMPONENT_DIRS "${WIFIX_ROOT}/..")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wifix_basic)
