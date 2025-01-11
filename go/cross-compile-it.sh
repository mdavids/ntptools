#!/bin/sh

#
# go tool dist list
#

archs=(amd64 arm 386)

for arch in ${archs[@]}
do
        # env GOOS=linux GOARCH=${arch} go build -o tlscheck_${arch}
        env GOOS=linux GOARCH=${arch} go build -ldflags "-s -w" -o tlscheck_${arch}
done

# en voor mijn Mac:

arch=arm64
#env GOOS=darwin GOARCH=${arch} go build -o tlscheck_${arch}
env GOOS=darwin GOARCH=${arch} go build -ldflags "-s -w" -o tlscheck_${arch}
