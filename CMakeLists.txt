cmake_minimum_required(VERSION 3.15)

project(pcapreader VERSION 0.1)

add_executable(pcapreader main.cpp pcapreader.cpp)

set_property(TARGET pcapreader PROPERTY CXX_STANDARD 17)

target_link_libraries(pcapreader -lpcap)
