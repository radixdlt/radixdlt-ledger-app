#*******************************************************************************
#*   (c) 2018 Zondax GmbH
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************
cmake_minimum_required(VERSION 3.0)
project(radixdlt-ledger VERSION 0.0.0)

cmake_policy(SET CMP0025 NEW)
set(CMAKE_CXX_STANDARD 11)

string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address -fno-omit-frame-pointer")
string(APPEND CMAKE_LINKER_FLAGS " -fsanitize=address -fno-omit-frame-pointer")

##############################################################
##############################################################
#  static libs

file(GLOB_RECURSE TINYAES
        deps/tiny-AES-c/*.c
        deps/tiny-AES-c/*.h
        )

file(GLOB_RECURSE TINYCBOR_SRC
        deps/tinycbor/src/*.c
        deps/tinycbor/src/*.h
        )

add_library(app_lib STATIC
        ${LIB_SRC}
        ${TINYAES}
        ${TINYCBOR_SRC}
        )

target_include_directories(app_lib PUBLIC
        deps/tiny-AES-c
        deps/tinycbor/src
        app/src
        )
