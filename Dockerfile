FROM silkeh/clang:22-trixie AS build
WORKDIR /deps

RUN set -eux; \
    apt-get update; \
    case "$(dpkg --print-architecture)" in \
      amd64) pkgs="gcc libc6-dev" ;; \
      *)     pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
    esac; \
    apt-get install -y --no-install-recommends $pkgs unzip make wget; \
    rm -rf /var/lib/apt/lists/*; \
    x86_64-linux-gnu-gcc --version

RUN wget -O plabs5.zip "https://codeload.github.com/pLabs5/pLabs5-SDK/zip/refs/heads/main"
RUN unzip plabs5.zip

RUN wget -O p5sdk.zip "https://github.com/ps5-payload-dev/sdk/releases/download/v0.44/ps5-payload-sdk.zip"
RUN unzip p5sdk.zip

ENV LLVM_CONFIG="/deps/pLabs5-SDK-main/tools/nixos/llvm-config"
ENV PS5_PAYLOAD_SDK="/deps/ps5-payload-sdk"

WORKDIR /app
COPY . .
RUN make -j4

FROM scratch AS final
COPY --from=build /app/bin/pLinux5-NG.elf /pLinux5-NG.elf
