#!/usr/bin/env bash

. ./cppsrc/openabe/env
cd cppsrc/openabejs
make
cd ../..
node-gyp rebuild
