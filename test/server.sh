NS=net-test
SERVER_POD=$(kubectl -n $NS get pod -l app=net-server -o jsonpath='{.items[0].metadata.name}')
SERVER_IP=$(kubectl -n $NS get pod "$SERVER_POD" -o jsonpath='{.status.podIP}')

echo "SERVER_POD=$SERVER_POD"
echo "SERVER_IP=$SERVER_IP"

# 1) server 侧起 tcpdump（另开一个 terminal 更舒服）
kubectl -n $NS exec -it "$SERVER_POD" -- sh -lc \
'tcpdump -ni any -vv "tcp port 8080"'

# 2) server 侧起 nc 监听（再开一个 terminal）
kubectl -n $NS exec -it "$SERVER_POD" -- sh -lc \
'nc -l -p 8080 -vv'

