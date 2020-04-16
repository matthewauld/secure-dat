#!/usr/bin/env bash

cd cppsrc/openabejs
make
cd ../..
node-gyp rebuild
