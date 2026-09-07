# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/mailauthd ./cmd/mailauthd

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/mailauthd /mailauthd
EXPOSE 8080
ENTRYPOINT ["/mailauthd"]
