# This file is part of Desktop App Toolkit,
# a set of libraries for developing nice desktop applications.
#
# For license and copyright information please follow this link:
# https://github.com/desktop-app/legal/blob/master/LEGAL

add_library(lib_cryptovkr OBJECT)
add_library(desktop-app::lib_cryptovkr ALIAS lib_cryptovkr)
init_target(lib_cryptovkr)

get_filename_component(src_loc . REALPATH)

target_precompile_headers(lib_cryptovkr PRIVATE ${src_loc}/pch.h)

target_include_directories(lib_cryptovkr
PUBLIC
    ${src_loc}
)

nice_target_sources(lib_cryptovkr ${src_loc}
PRIVATE
    pch.h
    pch.cpp
    cryptovkr.h
    lib_cryptovkr.cpp
)

target_link_libraries(lib_cryptovkr
PUBLIC
    desktop-app::lib_base
PRIVATE
    desktop-app::external_xxhash
)
