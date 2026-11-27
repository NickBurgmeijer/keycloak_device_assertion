#!/usr/bin/env bash
# Builds the provider jar into dist/.
# Uses local Maven if present, otherwise Docker/Podman with a Maven image.
# Set KC_HOME=/path/to/keycloak to also copy the jar into $KC_HOME/providers.
set -euo pipefail

cd "$(dirname "$0")"
JAR=target/device-check-authenticator.jar
MAVEN_IMAGE=maven:3.9-eclipse-temurin-21

if command -v mvn >/dev/null 2>&1; then
    mvn -q -B clean package
elif command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
    RUNTIME=$(command -v docker || command -v podman)
    mkdir -p "$HOME/.m2"
    "$RUNTIME" run --rm \
        -v "$PWD":/src -w /src \
        -v "$HOME/.m2":/root/.m2 \
        "$MAVEN_IMAGE" mvn -q -B clean package
else
    echo "Need Maven (+ JDK 17+) or Docker/Podman." >&2
    echo "  macOS: brew install openjdk@21 maven" >&2
    exit 1
fi

mkdir -p dist
cp "$JAR" dist/
echo "Built dist/$(basename "$JAR")"

if [[ -n "${KC_HOME:-}" ]]; then
    cp "$JAR" "$KC_HOME/providers/"
    echo "Copied to $KC_HOME/providers/ — run '$KC_HOME/bin/kc.sh build' (or restart start-dev)."
fi
