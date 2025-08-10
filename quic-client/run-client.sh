#!/bin/bash

# Script to run QUIC client in the U namespace

set -e

cd $(dirname $0)

# Check if we're root (needed for netns)
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root to access network namespaces"
    exit 1
fi

# Build the client
echo "Building QUIC client..."
go build -o quic-client main.go

# Default values
URL="https://192.0.2.10:8889/index.html"
VERBOSE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -url)
            URL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="-verbose"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-url URL] [-v|--verbose]"
            echo "  -url URL: Target URL (default: https://192.0.2.10:8889)"
            echo "  -v, --verbose: Enable verbose output"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h for help"
            exit 1
            ;;
    esac
done

echo "Running QUIC client in U namespace..."
echo "Target URL: $URL"

# Run the client in the U namespace
ip netns exec U ./quic-client -url="$URL" $VERBOSE