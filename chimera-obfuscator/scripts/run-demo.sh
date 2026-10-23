#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./gradlew --no-daemon -q clean build :samples:demo:jar
mkdir -p out
java -jar build/libs/chimera-0.1.0-all.jar \
  --input samples/demo/build/libs/demo.jar \
  --output out/demo-obf.jar \
  --key-pass demo-key-123 \
  --native-out out/native
CHIMERA_CONTENT_KEY=demo-key-123 java -jar out/demo-obf.jar
