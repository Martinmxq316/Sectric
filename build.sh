#!/bin/bash

cd triangle_counting
./copy_files.sh

cd ../extern/2PC-Circuit-PSI/build

make -j

mkdir -p ../../../bin
cp ./bin/gcf_psi ../../../bin/
cp ./bin/gcf_4cycle ../../../bin/

