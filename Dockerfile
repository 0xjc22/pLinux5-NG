FROM silkeh/clang:22-trixie AS build
WORKDIR /deps

RUN set -eux; \
    apt-get update; \
    case "$(dpkg --print-architecture)" in \
      amd64) pkgs="gcc libc6-dev" ;; \
      *)     pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
    esac; \
    apt-get install -y --no-install-recommends $pkgs binutils make unzip wget python3 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    x86_64-linux-gnu-gcc --version

RUN wget -O plabs5.zip "https://codeload.github.com/pLabs5/pLabs5-SDK/zip/refs/heads/main"
RUN unzip plabs5.zip

RUN wget -O p5sdk.zip "https://github.com/ps5-payload-dev/sdk/releases/download/v0.44/ps5-payload-sdk.zip"
RUN echo "4d06eab777bb135705b5a6816688c9132efb246093fe606ac488ab6cf65ca5b0  p5sdk.zip" | sha256sum --check -
RUN unzip p5sdk.zip

ENV LLVM_CONFIG="/deps/pLabs5-SDK-main/tools/nixos/llvm-config"
ENV PS5_PAYLOAD_SDK="/deps/ps5-payload-sdk"

WORKDIR /app
COPY . .
RUN make -j4

# Stamp the artifact with the manifest version, so the file name, the release
# name and kManifest.version cannot drift apart. `make version` reads the same
# field from source/manifest/manifest.c.
RUN set -eux; \
    ver="$(make -s version)"; \
    test -n "$ver"; \
    mkdir -p dist; \
    cp bin/pLinux5-NG.elf "dist/pLinux5-NG-${ver}.elf"; \
    cp bin/pLinux5-NG.elf dist/pLinux5-NG.elf; \
    sha256sum dist/pLinux5-NG.elf > dist/pLinux5-NG.elf.sha256

FROM scratch AS final
COPY --from=build /app/dist/ /
