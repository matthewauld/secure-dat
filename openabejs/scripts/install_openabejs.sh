#!/usr/bin/env bash
cd cppsrc/openabe
. ./env
cd ../openabejs
make
cd ../..
npm run build
