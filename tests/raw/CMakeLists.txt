add_library(lunar_raw_test SHARED raw.cpp)
target_compile_options(lunar_raw_test PRIVATE /GS- /Oi)
target_link_libraries(lunar_raw_test PRIVATE kernel32)
set_target_properties(lunar_raw_test PROPERTIES
    LINK_FLAGS "/NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS"
)
