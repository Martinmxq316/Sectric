#!/bin/bash

cd extern/2PC-Circuit-PSI

mkdir build

cd build

cmake ..

cp ../aux_hash/* ../extern/HashingTables/cuckoo_hashing/.

cd ../../../debug_files
./replace_files.sh

cd ../triangle_counting
./copy_files.sh

cd ../extern/2PC-Circuit-PSI/build

make -j

mkdir -p ../../../bin
cp ./bin/gcf_psi ../../../bin/
cp ./bin/gcf_4cycle ../../../bin/


