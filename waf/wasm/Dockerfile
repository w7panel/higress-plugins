ARG BUILDER=higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/wasm-go-builder:go1.24.4-oras1.0.0
FROM ${BUILDER} AS build
WORKDIR /workspace
COPY . .
RUN GOPROXY=https://goproxy.cn,direct GOOS=wasip1 GOARCH=wasm go build -tags=no_fs_access -buildmode=c-shared -buildvcs=false -o /plugin.wasm .

FROM scratch
COPY --from=build /plugin.wasm /plugin.wasm
