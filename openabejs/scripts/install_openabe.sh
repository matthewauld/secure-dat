#!/usr/bin/env bash
if [ ! -d "cppsrc/openabe" ]; then
  cd cppsrc
  git clone https://github.com/matthewauld/openabe
  cd openabe
  . ./env
  sudo -E ./deps/install_pkgs.sh
  make
  sudo -E make install

fi
