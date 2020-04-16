#!/usr/bin/env bash
node-gyp clean
rm cppsrc/openabejs/decrypt.o
rm cppsrc/openabejs/encrypt.o
rm cppsrc/openabejs/encrypt
rm cppsrc/openabejs/decrypt
rm -rf cppsrc/openabe
