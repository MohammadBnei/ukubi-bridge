FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bridge ./cmd/bridge \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /kwatch ./cmd/kwatch

FROM gcr.io/distroless/static:nonroot
COPY --from=build /bridge /kwatch /
EXPOSE 8080
# CMD, not ENTRYPOINT: the chart's `args` replace it, so helm/kwatch.yaml runs /kwatch from the same image.
CMD ["/bridge"]
