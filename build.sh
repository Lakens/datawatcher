#!/bin/sh
# Builds one self-contained program file per operating system into dist/.
# Requires Go (https://go.dev/dl/). Run from this folder: sh build.sh
set -e
mkdir -p dist
for target in windows/amd64 windows/arm64 darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  os=${target%/*}
  arch=${target#*/}
  ext=""
  [ "$os" = windows ] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "dist/datawatcher-$os-$arch$ext" .
  echo "built dist/datawatcher-$os-$arch$ext"
done
