#!/bin/bash
REGISTRY=${REGISTRY:-"10.240.201.50:8891/visualizer/skydive"}
TAG=${TAG:-"latest"}
PROXY=${PROXY:-""}
make
opts=" --build-arg binary=${GOPATH}/bin/skydive"
if [[ -n "$PROXY" ]]; then
  opts+=" --build-arg http_proxy=${PROXY}"
  opts+=" --build-arg https_proxy=${PROXY}"
fi
docker build -t "${REGISTRY}:${TAG}" $opts
docker push "${REGISTRY}:${TAG}"
