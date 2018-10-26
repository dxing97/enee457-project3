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

cp rainbowchaintable1 rainbow

