# print all layout 
# kubectl get nodes -o wide

NS=net-test
SERVER_NODE=ash1-au41-17-s4
CLIENT_NODE=ash1-as21-3-s3

# 固定 server 到 SERVER_NODE
kubectl -n $NS patch deploy net-server --type='merge' -p \
  "{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$SERVER_NODE\"}}}}}"

# 固定 client 到 CLIENT_NODE
kubectl -n $NS patch deploy net-client --type='merge' -p \
  "{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$CLIENT_NODE\"}}}}}"

# 触发重建（确保迁移到正确节点）
kubectl -n $NS rollout restart deploy/net-server
kubectl -n $NS rollout restart deploy/net-client

kubectl -n $NS rollout status deploy/net-server
kubectl -n $NS rollout status deploy/net-client

# 验证确实在不同 node
kubectl -n $NS get pod -o wide -l app=net-server
kubectl -n $NS get pod -o wide -l app=net-client

