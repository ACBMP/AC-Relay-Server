cmake_minimum_required(VERSION 3.16)
project(ac-relay-server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(ac-relay src/main.cpp src/relay.cpp)
if(MSVC)
  target_compile_options(ac-relay PRIVATE /W4)
else()
  target_compile_options(ac-relay PRIVATE -Wall -Wextra)
endif()
if(WIN32)
  target_link_libraries(ac-relay PRIVATE ws2_32)
endif()

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_FOUND)
    add_test(NAME e2e
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e_test.py
                     $<TARGET_FILE:ac-relay>)
  endif()
endif()

install(TARGETS ac-relay RUNTIME DESTINATION bin)
