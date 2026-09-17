#!/usr/bin/env sh
set -eu
: "${IMAGE:?set IMAGE to an immutable image reference when possible}"
dockerls analyze "$IMAGE" --ci --fail-on critical > dockerls-result.json
