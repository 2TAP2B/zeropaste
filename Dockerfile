# build
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
COPY web/ ./web/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/paste .

# seeded data dir so named volumes inherit non-root ownership
FROM alpine AS data
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
