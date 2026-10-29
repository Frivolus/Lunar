add_library(lunar_injector STATIC
    remote.cpp
    process.cpp
    peb.cpp
    thread_hijack.cpp
    manual_map.cpp
)
target_include_directories(lunar_injector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(lunar_inject_cli cli.cpp)
target_link_libraries(lunar_inject_cli PRIVATE lunar_injector)
