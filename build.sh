#!/bin/bash

# Create bin directory if it doesn't exist
mkdir -p bin

# Version - using current date in YYYY.MM.DD format
VERSION=$(date +"%Y.%m.%d")

# Platforms to build for
PLATFORMS=(
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
)

# Build function
build() {
    GOOS=$1
    GOARCH=$2
    output_name="massmap"
    
    # Add .exe extension for Windows builds
    if [ $GOOS = "windows" ]; then
        output_name+=".exe"
    fi
    
    # Create final output name with version, os and arch
    final_name="bin/massmap-${VERSION}-${GOOS}-${GOARCH}-${output_name}"
    
    echo "Building for ${GOOS}/${GOARCH}..."
    # Build with version information embedded
    GOOS=$GOOS GOARCH=$GOARCH go build -o "${final_name}" -ldflags="-s -w -X main.Version=${VERSION}" ./cmd/massmap
    
    if [ $? -ne 0 ]; then
        echo "Build failed for ${GOOS}/${GOARCH}"
    fi
}

# Clean bin directory
echo "Cleaning bin directory..."
rm -rf bin/*

# Build for each platform
for platform in "${PLATFORMS[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    build $GOOS $GOARCH
done

echo "Build complete! Binaries are available in the bin directory." 
