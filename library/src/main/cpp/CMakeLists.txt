cmake_minimum_required(VERSION 3.18)
project(forgestore C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(RAPLT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ext/RaPLT)
set(RAPLT_SRC
    ${RAPLT_DIR}/src/raplt_core.c
    ${RAPLT_DIR}/src/raplt_elf.c
    ${RAPLT_DIR}/src/raplt_hash.c
    ${RAPLT_DIR}/src/raplt_signal.c
    ${RAPLT_DIR}/src/raplt_util.c
    ${RAPLT_DIR}/src/raplt_recon.c
    ${RAPLT_DIR}/src/raplt_dlopen.c
    ${RAPLT_DIR}/src/raplt_cfi.c
    ${RAPLT_DIR}/src/raplt_jni.c
    ${RAPLT_DIR}/src/raplt_mremap.c
)
foreach(src ${RAPLT_SRC})
    set_source_files_properties(${src} PROPERTIES COMPILE_FLAGS "-w")
endforeach()

set(RAPLT_INC ${RAPLT_DIR}/include)

add_library(utils SHARED stub_utils.cpp)
target_include_directories(utils PUBLIC ext)
target_compile_definitions(utils PRIVATE BUILDING_LIBBINDER)
target_compile_options(utils PRIVATE -fvisibility=default)

set_target_properties(utils PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/stubs"
)

add_library(binder SHARED stub_binder.cpp)
target_include_directories(binder PUBLIC ext)
target_compile_definitions(binder PRIVATE BUILDING_LIBBINDER)
target_link_libraries(binder PRIVATE utils)
target_compile_options(binder PRIVATE -fvisibility=default)

set_target_properties(binder PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/stubs"
)

add_library(forgestore SHARED
    main.c
    hook.cpp
    ${RAPLT_SRC}
)
target_include_directories(forgestore PRIVATE
    .
    ${RAPLT_INC}
    ext
)
target_link_libraries(forgestore PRIVATE binder utils log)

target_compile_options(forgestore PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
    -Wno-gnu-zero-variadic-macro-arguments
    -Wno-unused-private-field
)

add_executable(libinject.so injector.c)
target_include_directories(libinject.so PRIVATE .)
target_link_libraries(libinject.so log dl)
target_compile_options(libinject.so PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
