#!/bin/bash
set -e

rm -rf src/
mkdir src/
touch src/lib.rs

cargo run --package generate-bindings src
