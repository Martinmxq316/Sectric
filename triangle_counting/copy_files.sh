#!/bin/bash

declare -A file_mapping
file_mapping=(
    ["batch_equality.h"]="../extern/2PC-Circuit-PSI/src/common/batch_equality.h"
    ["circuit_psi.cpp"]="../extern/2PC-Circuit-PSI/src/circuit_psi.cpp"
    ["cycle4_psi.cpp"]="../extern/2PC-Circuit-PSI/src/cycle4_psi.cpp"
    ["triangle.h"]="../extern/2PC-Circuit-PSI/src/triangle.h"
    ["cuckoo_hashing.cpp"]="../extern/2PC-Circuit-PSI/aux_hash/cuckoo_hashing.cpp"
    ["cuckoo_hashing.h"]="../extern/2PC-Circuit-PSI/aux_hash/cuckoo_hashing.h"
    ["equality.h"]="../extern/2PC-Circuit-PSI/src/common/equality.h"
    ["simple_hashing.cpp"]="../extern/2PC-Circuit-PSI/extern/HashingTables/simple_hashing/simple_hashing.cpp"
    ["simple_hashing.h"]="../extern/2PC-Circuit-PSI/extern/HashingTables/simple_hashing/simple_hashing.h"
    ["functionalities.cpp"]="../extern/2PC-Circuit-PSI/src/common/functionalities.cpp"
    ["functionalities.h"]="../extern/2PC-Circuit-PSI/src/common/functionalities.h"
    ["cuckoo_hashing.cpp"]="../extern/2PC-Circuit-PSI/extern/HashingTables/cuckoo_hashing/cuckoo_hashing.cpp"
    ["cuckoo_hashing.h"]="../extern/2PC-Circuit-PSI/extern/HashingTables/cuckoo_hashing/cuckoo_hashing.h"   
    ["CMakeLists.txt"]="../extern/2PC-Circuit-PSI/src/CMakeLists.txt" 
)

for src_file in "${!file_mapping[@]}"; do
    dest_file="${file_mapping[$src_file]}"

    if [[ -f "$src_file" ]]; then
        mkdir -p "$(dirname "$dest_file")"
        cp -f "$src_file" "$dest_file"
        echo "已将 $src_file 复制到 $dest_file"
    else
        echo "源文件 $src_file 不存在"
    fi
done

echo "文件复制完成"
