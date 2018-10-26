#!/bin/bash
#assuming code has not been precompiled, in directory containing everything in https://github.com/dxing97/enee457-project3
sudo apt-update && sudo apt install cmake libssl-dev

mkdir build
cd build
    cmake ..
    make
    cp Crack ../
    cp GenTable ../
    cd  ..

chmod a+x GenTable
chmod a+x Crack

time ./GenTable 12
md5sum rainbow
du -sh rainbow
time ./Crack 12 970fc16e71b75463abafb3f8be939d1c

time ./GenTable 20
md5sum rainbow
du -sh rainbow
time ./Crack 20 8de0bcffe587f63ed5c823dcf9bf5131

time ./GenTable 20
md5sum rainbow
du -sh rainbow
time ./Crack 20 f7ef413cc51df04abf6872db315e694b

time ./GenTable 24
md5sum rainbow
du -sh rainbow
time ./Crack 24 ed078d9b527a81fe4725228d88b664ae

time ./GenTable 24
md5sum rainbow
du -sh rainbow
time ./Crack 24 ae955b027a3d0cb5401b63b4d26a10ba

time ./GenTable 24
md5sum rainbow
du -sh rainbow
time ./Crack 24 b8a1c2b0affbf389d6f0fc0584ccefb2

time ./GenTable 28
md5sum rainbow
du -sh rainbow
time ./Crack 28 86527077e1cb39b6b2e6f414b1a758f6


