# Build from the repository root:
#   docker build --platform linux/amd64 -f verily_kit/Dockerfile -t verily-kit .
#
# MediaPipe's Linux native runtime is published for x86_64, so production images
# target linux/amd64.

FROM --platform=linux/amd64 rust:1.95-trixie AS build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY monosecret.toml ./
COPY verily_kit ./verily_kit

WORKDIR /workspace/verily_kit
RUN cargo build --release --bin verily-kit --locked
RUN cargo run --release --package verily_site -- /workspace/verily_kit/dist/site

FROM --platform=linux/amd64 debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl ffmpeg libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /workspace/verily_kit/target/release/verily-kit /app/bin/verily-kit
COPY --from=build /workspace/verily_kit/leptoskit.toml /app/leptoskit.toml
COPY --from=build /workspace/verily_kit/monosecret.toml /app/monosecret.toml
COPY --from=build /workspace/verily_kit/dist /app/dist

# Pre-bake and SHA-256 verify the pinned MediaPipe local-check models so the
# server never downloads model weights at runtime.
RUN mkdir -p /app/local-check-models \
    && cd /app/local-check-models \
    && curl --fail --silent --show-error --location \
       --output 97952348cf6a6a4915c2ea1496b4b37ebabc50cbbf80571435643c455f2b0482 \
       https://storage.googleapis.com/mediapipe-models/gesture_recognizer/gesture_recognizer/float16/1/gesture_recognizer.task \
    && curl --fail --silent --show-error --location \
       --output 0720bf247bd76e6594ea28fa9c6f7c5242be774818997dbbeffc4da460c723bb \
       https://storage.googleapis.com/mediapipe-models/object_detector/efficientdet_lite0/int8/1/efficientdet_lite0.tflite \
    && curl --fail --silent --show-error --location \
       --output 4d8b4a53282dc83ef04e3e7dbc4fbc98082e34e44ed798e16c3a0cdd4c584faf \
       https://storage.googleapis.com/mediapipe-models/audio_classifier/yamnet/float32/1/yamnet.tflite \
    && for file in *; do echo "$file  $file" | sha256sum --check --strict -; done

ENV VERILY_BIND_ADDRESS=0.0.0.0
ENV VERILY_PORT=8184
ENV LEPTOS_SITE_ROOT=/app/dist
ENV VERILY_LOCAL_CHECK_MODEL_CACHE=/app/local-check-models

EXPOSE 8184

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=4 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8184/healthz >/dev/null

ENTRYPOINT ["/app/bin/verily-kit"]
