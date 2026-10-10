# Build: docker build -t ac-relay .
# Run:   docker run --rm --network host ac-relay --public-ip <your-public-ipv4>
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ cmake make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt .
COPY src src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build build -j

FROM debian:bookworm-slim
COPY --from=build /src/build/ac-relay /usr/local/bin/ac-relay
USER nobody
EXPOSE 21100/udp 40200-40999/udp
ENTRYPOINT ["/usr/local/bin/ac-relay"]
