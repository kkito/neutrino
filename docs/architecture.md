# neutrino 架构与典型流程

## 一句话：是 server/agent 模式吗？

**是，但方向反直觉**：不是 server 主动连内网，而是**内网 agent 单条 WSS 出站长连打到公网 server**，
所有隧道都复用这一条连接。公网进来的访问者流量，由 server 通过这条长连"反向"捎回内网。
所以内网主机不需要公网 IP、不开任何入站端口——这就是"隐身"的来源。

## 架构图

```mermaid
flowchart TB
    U[访问者<br/>浏览器/TCP客户端]
    A[管理员<br/>浏览器]

    subgraph SRV[neutrino server · 公网]
        direction TB
        WS["信令通道 /ws<br/>WSS连接复用"]
        HTTP["HTTP入口<br/>按Host路由"]
        TCP["TCP/UDP入口<br/>按端口监听"]
        WEB["WebUI + API<br/>总览/隧道/配置"]
        ST[(state.json<br/>流量+密码)]
        HTTP -.->|Open + 数据帧| WS
        TCP -.->|Open + 数据帧| WS
        WEB -.->|Config热下发| WS
        WEB -.->|读写| ST
    end

    subgraph AGT[client machine · 内网]
        direction TB
        AG["neutrino agent<br/>单条WSS出站长连"]
        L1[内网HTTP服务]
        L2[内网TCP服务]
        L3[内网UDP服务]
        AG -->|拨本地| L1
        AG -->|拨本地| L2
        AG -->|发本地| L3
    end

    subgraph RP[nginx 反向代理 · 可选]
        direction TB
        N["TLS卸载 + 分流<br/>直连端口同样可用"]
    end

    U --> HTTP
    U --> TCP
    A --> WEB
    AG <==>|hello/register| WS
    U -.->|经反代| N
    A -.->|经反代| N
    N -.->|/ws, WebUI| WS
    N -.->|业务域名| HTTP
```

关键点：

- **控制帧**走 WSS Text JSON（`hello/register/ping/pong/open/close/config`），**数据帧**走 WSS Binary
  `[stream_id:u32 BE][payload]`，server 用偶数 id。TCP/HTTP 每连接一个 stream 全双工；
  UDP 每个 peer 一个 stream，每帧即一个 datagram。
- HTTP 按 `Host` 路由、可注入 `X-Forwarded-Proto`；TCP/UDP 按 `remote_port` 路由（lazy 监听）；
  HTTPS 当 TCP 透传、不解密。
- WebUI 与全部 API 由 server 直出（页面编译进二进制），反向代理仅可选承担 TLS 卸载与分流，
  直连 server 端口同样可用。

## 典型场景

### 1. 建连注册（agent 上线，只出不进）

```mermaid
sequenceDiagram
    participant AG as agent(内网)
    participant SR as server(公网)
    AG->>SR: WSS握手 + hello{token}
    SR->>AG: welcome(校验token)
    AG->>SR: register{proxies[]}
    SR->>AG: 路由就绪(建表+lazy监听)
```

### 2. HTTP 穿透（最常用）

```mermaid
sequenceDiagram
    participant C as 访问者
    participant SR as server
    participant AG as agent
    participant L as 内网HTTP服务
    C->>SR: GET Host: 业务域名
    SR->>AG: Open{kind=http,host}
    AG->>L: 拨本地端口
    L->>AG: 响应字节流
    AG->>SR: Binary数据帧
    SR->>C: 写回(XFP已注入)
```

### 3. TCP/HTTPS 透传（TLS 不解密）

```mermaid
sequenceDiagram
    participant C as TCP客户端
    participant SR as server端口监听
    participant AG as agent
    participant L as 内网TCP/TLS服务
    C->>SR: 连 remote_port
    SR->>AG: Open{kind=tcp,port}
    AG->>L: 拨本地端口(原样透传)
    L->>AG: 内网发往客户端字节流
    AG->>L: 客户端发往内网字节流
    AG->>SR: Binary数据帧(双向)
    SR->>C: 写回访问者
```

任一方向 EOF 即发 `Close` 收尾（`select` 非 `join`，避免两端互等死锁）。

### 4. 保活、断线重连、热更新

```mermaid
sequenceDiagram
    participant SR as server
    participant AG as agent
    SR->>AG: Ping(定时,测RTT)
    AG->>SR: Pong
    Note over AG: 断线指数退避重连,重发hello+register
    SR->>AG: Config热下发(不断WSS)
    AG->>SR: ConfigAck,原子替换路由
```

管理员在 WebUI `POST /api/config` 推送新隧道列表，在途 stream 继续 draining；
`POST /api/tunnels/:agent/:name/enabled` 即时启停单个隧道。
