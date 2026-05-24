find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
# Set OpenSSL paths based on system
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(OPENSSL_LIBRARIES /usr/local/openssl/lib64/libcrypto.a /usr/local/openssl/lib64/libssl.a)
    set(OPENSSL_INCLUDE_DIR /usr/local/openssl/include)
    set(OPENSSL_DIR /usr/local/openssl/lib64)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(OPENSSL_LIBRARIES /usr/local/lib/libcrypto.a /usr/local/lib/libssl.a)
    set(OPENSSL_INCLUDE_DIR /usr/local/include)
    set(OPENSSL_DIR /usr/local/lib)
endif()

# Find OpenMP
find_package(OpenMP REQUIRED)

# Set compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -fpic -Wno-deprecated-declarations -Wno-unused-result -Xpreprocessor -O3")
set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -ldl")

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR} "/usr/local/include")

# Link directories
link_directories(/usr/local/lib)
find_package(Boost COMPONENTS program_options REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(NTL_LIB ntl)
if (NOT NTL_LIB)
    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

add_library(src
        common/functionalities.cpp
        common/helpers.cpp
        common/table_opprf.cpp
        ots/ots.cpp
        )

set_target_properties(src
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        )

target_compile_options(src
        PRIVATE
        -march=native
        -ffunction-sections -mpclmul -mbmi2 -maes
        -mavx -msse2 -msse3 -msse4.1 -mrdrnd
        -Wall -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses)

target_link_libraries(src INTERFACE
        ABY::aby
        ENCRYPTO_utils::encrypto_utils
        ${GLIB_LDFLAGS}
        gmp
        gmpxx
        ntl
        HashingTables
        libOTe
        Boost::program_options
        Threads::Threads
        # relic is a transitive dependency of libOTe right now
        # change relic to another library (if needed) if this changes
        relic_s
        ${OPENSSL_LIBRARIES} 
        OpenMP::OpenMP_CXX
        )

target_include_directories(src PUBLIC
        ${PSI_ANALYTICS_SOURCE_ROOT}/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe/cryptoTools
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/extern/ENCRYPTO_utils/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/HashingTables
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/EzPC/SCI/src
        ${GLIB_INCLUDE_DIRS}
        )

if (PSI_ANALYTICS_BUILD_EXAMPLE)
    add_executable(gcf_psi circuit_psi.cpp)

    target_link_libraries(gcf_psi PUBLIC
            src
            )
    set_target_properties(gcf_psi
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )

    add_executable(gcf_4cycle cycle4_psi.cpp)

    target_link_libraries(gcf_4cycle PUBLIC
            src
            )
    set_target_properties(gcf_4cycle
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif (PSI_ANALYTICS_BUILD_EXAMPLE)
