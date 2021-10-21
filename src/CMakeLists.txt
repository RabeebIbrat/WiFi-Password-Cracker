cmake_minimum_required(VERSION 3.19)
project(WiFi_Password_Cracker)

set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

add_executable(WiFi_Password_Cracker main.cpp inject.h std-tins.h sniff.h control.h wpa2.h)
target_link_libraries(WiFi_Password_Cracker -ltins)