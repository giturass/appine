# scripts/survey -s target/survey/docker docker-bridge-netfilter
# Exercise Docker's default bridge with both inter-container communication and its proxy disabled.
set -eu
unset DOCKER_IGNORE_BR_NETFILTER_ERROR
[ -x /usr/bin/dockerd ] || apk add -q docker
work=$(mktemp -d)
export DOCKER_HOST="unix://$work/docker.sock"
echo '{"storage-driver":"vfs","icc":false,"userland-proxy":false,"ip6tables":false}' > "$work/daemon.json"
dockerd --config-file "$work/daemon.json" -H "$DOCKER_HOST" >"$work/daemon.log" 2>&1 &
daemon=$!
server=""
client=""
cleanup() {
    [ -z "$client" ] || docker rm -f "$client" >/dev/null || true
    [ -z "$server" ] || docker rm -f "$server" >/dev/null || true
    kill "$daemon" 2>/dev/null || true
    wait "$daemon" || true
    rm -rf "$work"
}
trap cleanup EXIT
for i in $(seq 60); do
    kill -0 "$daemon" 2>/dev/null || { cat "$work/daemon.log"; exit 1; }
    docker info >/dev/null 2>&1 && break
    sleep 1
done
docker version --format '{{.Server.Version}}'
server=$(docker run -d -p 8080/tcp alpine:3.24 sh -c '
    while true; do printf "HTTP/1.0 200 OK\r\n\r\nbridge-ok\n" | nc -l -p 8080 >/dev/null; done')
client=$(docker run -d alpine:3.24 sleep 300)
ip=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' "$server")
gw=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.Gateway}}' "$client")
published=$(docker inspect -f '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$server")
fetch() { docker exec "$client" wget -Y off -q -T 4 -O - "http://$1/"; }

key=net.bridge.bridge-nf-call-iptables
test "$(sysctl -n "$key")" = 1
if sysctl -w "$key=invalid" >/dev/null 2>&1; then exit 1; fi
sysctl -w "$key=0"
test "$(docker exec "$client" cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 1
test "$(fetch "$ip:8080")" = bridge-ok
# The same peer reaching a published port goes through the gateway's IPv4 routing path.
iptables -I DOCKER-USER -i docker0 -o docker0 -d "$ip" -p tcp --dport 8080 -j REJECT
if fetch "$gw:$published"; then echo "Routed traffic skipped FORWARD"; exit 1; fi
iptables -D DOCKER-USER -i docker0 -o docker0 -d "$ip" -p tcp --dport 8080 -j REJECT
test "$(fetch "$gw:$published")" = bridge-ok
echo "Bridge filtering disabled, routed filtering active"

sysctl -w "$key=-1"
test "$(sysctl -n "$key")" = 1
if fetch "$ip:8080"; then echo "Unexpected direct connection with ICC disabled"; exit 1; fi
test "$(fetch "$gw:$published")" = bridge-ok
hostip=$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i+1); exit}}')
test -n "$hostip"
test "$(fetch "$hostip:$published")" = bridge-ok
echo "ICC blocked the container IP and the published port served the peer"

# Both namespaces rewrite a port. The bridge's FORWARD must see its own translation
# before the destination namespace translates the port again.
pid=$(docker inspect -f '{{.State.Pid}}' "$server")
nsenter -t "$pid" -n iptables -t nat -A PREROUTING -p tcp --dport 18083 -j DNAT --to-destination "$ip:8080"
iptables -t nat -I PREROUTING -i docker0 -d "$ip" -p tcp --dport 18082 -j DNAT --to-destination "$ip:18083"
iptables -I DOCKER-USER -i docker0 -o docker0 -d "$ip" -p tcp --dport 18083 -j ACCEPT
test "$(fetch "$ip:18082")" = bridge-ok
echo "Bridge and endpoint DNAT passed in order"
