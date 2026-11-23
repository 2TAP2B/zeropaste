# build - base images pinned by tag AND digest: reproducible, tamper-evident
# builds; Dependabot (docker) proposes the patch bumps, which doubles as the
# "Go security release landed" signal (ci.yml audits this exact toolchain)
FROM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
COPY web/ ./web/
# VERSION: the workflow passes the pushed tag; the binary shows it in the
# footer (the docker build context carries no .git, so VCS stamping is moot)
ARG VERSION=""
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/paste .

# seeded data dir so named volumes inherit non-root ownership
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS data
RUN mkdir /data && chown 65534:65534 /data

# run
FROM scratch
COPY --from=build /out/paste /paste
COPY --chown=65534:65534 --from=data /data /data
USER 65534:65534
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/paste"]
CMD ["-addr", ":8080", "-data", "/data"]
