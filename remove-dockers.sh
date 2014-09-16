docker ps -a | grep 'electrum-winbuild:latest'  | awk '{print $1}' | xargs docker rm
