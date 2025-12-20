NS=net-test

CLIENT_POD=$(kubectl -n $NS get pod -l app=net-client -o jsonpath='{.items[0].metadata.name}')
SERVER_POD=$(kubectl -n $NS get pod -l app=net-server -o jsonpath='{.items[0].metadata.name}')
SERVER_IP=$(kubectl -n $NS get pod "$SERVER_POD" -o jsonpath='{.status.podIP}')

echo "CLIENT_POD=$CLIENT_POD"
echo "SERVER_POD=$SERVER_POD"
echo "SERVER_IP=$SERVER_IP"

# 可选：client 侧也抓一下包，方便对照
kubectl -n $NS exec -it "$CLIENT_POD" -- sh -lc \
'tcpdump -ni any -vv "tcp port 8080"'


# 发包（你原来的命令）
kubectl -n $NS exec -it "$CLIENT_POD" -- sh -lc \
'echo "hello-tcp" | nc -w2 '"$SERVER_IP"' 8080'

