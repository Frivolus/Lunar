add_library(lunar_hyperion STATIC
    dllmain.cpp
    page_guard.cpp
    antidebug.cpp
)
target_include_directories(lunar_hyperion PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
