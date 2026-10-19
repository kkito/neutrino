# nginx 接入（natproxy 侧）

neutrino server 是单端口明文 HTTP（默认 `127.0.0.1:7440`），TLS 由 nginx 卸载。
所有域名反代到**同一个** upstream，neutrino 按 `Host` 分流：
`tunnel` 域→WebUI、`/ws`→agent 信令、业务域名→对应 agent 隧道。
完整示例见 `deploy/tunnel-nginx.conf`。

## 1. http 段加 map（配一次）

`$connection_upgrade` 非内置，`nginx.conf` 的 `http {}` 里加：

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

缺了它：`proxy_set_header Connection $connection_upgrade` 启动报错，
agent `/ws` 连不上。

## 2. 管理域 + 业务域

```nginx
# 管理域：WebUI + agent 信令
server {
    listen 443 ssl;
    server_name tunnel.nat.kkito.cn;
    ssl_certificate /etc/nginx-certs/wildcard.nat.kkito.cn.crt;
    ssl_certificate_key /etc/nginx-certs/wildcard.nat.kkito.cn.key;
    location / {
        proxy_pass http://127.0.0.1:7440;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;  # ws 升级靠它
        proxy_set_header Host $host;                      # 必须原样透 Host
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1d; proxy_send_timeout 1d;      # ws 长连别被掐
    }
}

# 业务域：每加一个隧道加一个 server_name，upstream 还是同一个 7440
server {
    listen 443 ssl;
    server_name git.nat.kkito.cn;
    ssl_certificate /etc/nginx-certs/wildcard.nat.kkito.cn.crt;
    ssl_certificate_key /etc/nginx-certs/wildcard.nat.kkito.cn.key;
    location / {
        proxy_pass http://127.0.0.1:7440;
        proxy_http_version 1.1;
        proxy_set_header Host $host;       # 关键：neutrino 靠它路由到隧道
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

铁律：
- **别改 `Host`**：必须 `proxy_set_header Host $host`。写死或用 `$proxy_host`
  会导致全进 WebUI 或全 404。
- **业务域不另开端口**：旧版独立 7080 已废弃并入 `--listen`，共用 7440 即可。
- **agent 上行经 nginx 必须 `wss://`**：如 `wss://tunnel.nat.kkito.cn/ws`
 （直连 server 才用 `ws://127.0.0.1:7440/ws`；直连地址配 `wss://` 会报
  `InvalidContentType`）。token 与 server `--token` 一致。

## 3. tcp/udp 隧道

不走 nginx，直接在公网防火墙/podman 把 `remote_port` 映射出去：

```bash
-p 51413:51413[/udp]
```

## 4. 验证

```bash
nginx -t && nginx -s reload
curl -H 'Host: git.nat.kkito.cn' http://127.0.0.1:7440/  # 先确认隧道通
curl -k https://git.nat.kkito.cn/                        # 再走 nginx
open https://tunnel.nat.kkito.cn/                        # WebUI
```

DNS：业务域名指到 natproxy 公网 IP，泛域名证书 `*.nat.kkito.cn` 覆盖。
