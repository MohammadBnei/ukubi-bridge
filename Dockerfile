FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bridge ./cmd/bridge

FROM gcr.io/distroless/static:nonroot
COPY --from=build /bridge /bridge
EXPOSE 8080
ENTRYPOINT ["/bridge"]
