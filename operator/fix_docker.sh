#/bin/bash
#
# Fix skaffold so it conencts to correct docker
#
echo "Setup docker to minikube"
eval $(minikube docker-env)
