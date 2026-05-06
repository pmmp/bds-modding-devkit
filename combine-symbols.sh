#!/usr/bin/env bash

INPUT="$1"
objcopy --decompress-debug-sections "$1/bedrock_server.debug" ./bedrock_server_decompressed.debug

eu-unstrip -o ./bedrock_server_symbols.debug "$1/bedrock_server" ./bedrock_server_decompressed.debug 

python3 export-symbols.py ./bedrock_server_symbols.debug ./bedrock_server_symbols_test.debug
