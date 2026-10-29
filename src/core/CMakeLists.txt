add_library(lunar_core STATIC
    dllmain.cpp
    api/api_register.cpp
)
target_include_directories(lunar_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
