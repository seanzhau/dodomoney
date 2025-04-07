#!/bin/bash

# Mac 打包
echo "Building macOS"
GOOS=darwin GOARCH=arm64 /Users/seanzhau/Documents/project/go/bin/fyne package -os darwin -icon images/btc1.png -appID "io.guoran.dodo" -name dodo
# codesign --deep --force --verify --verbose --sign "Developer ID: seanzhau" dodo.app
# codesign --verify -vvvv dodo.app
# spctl --assess --type execute --verbose dodo.app
# productbuild --component dodo.app /Applications --sign "Developer ID: seanzhau" dodo.pkg

# Windows 打包
# echo "Building Windows"
# GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1 /Users/seanzhau/Documents/project/go/bin/fyne package -os windows -icon images/btc1.png -name dodo

# Linux 打包
# echo "Building Linux"
# GOOS=linux GOARCH=amd64 CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ CGO_ENABLED=1 /Users/seanzhau/Documents/project/go/bin/fyne package -os linux -icon images/btc3.png -name dodo
