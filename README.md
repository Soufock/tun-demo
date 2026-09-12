# tun-demo

一个基于 Go + TUN + UDP 的三段式 VPN 演示项目（v3）。

```text
                         Internet
                            │
                            │ UDP
                            ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│    Client    │ UDP  │    Center    │ UDP  │   Gateway    │
│              │◄────►│              │◄────►│              │
│ Mac/Windows  │      │ 公网服务器    │      │ 公司内网机器  │
│ Linux        │      │ 纯转发        │      │ TUN + 路由   │
│ TUN          │      │ 不创建 TUN    │      │              │
└──────────────┘      └──────────────┘      └──────┬───────┘
                                                   │
                                            公司内部网络
```

完整设计文档见 [v3方案.md](v3方案.md)。

## 核心设计

- **Client 不直接连接 Gateway**，所有流量经过 Center 中继
- **Gateway 不需要公网 IP**，主动连接 Center，NAT 端口变化也能自动适应
- **Center 不创建 TUN**、不进入公司内网，只做 VPN 数据包中继和路由
- **Gateway** 负责把 VPN 流量送入公司内网
- 第一阶段使用唯一 VPN IP，不实现 NAT

## 项目结构

```
├── protocol/   # 三端共用的 VPN 协议（Pack/Unpack/包类型）
├── client/     # VPN 客户端（macOS）
├── center/     # 中继服务器（公网，纯 UDP，不创建 TUN）
└── gateway/    # 内网网关（Linux，TUN + 路由）
```

## 自定义协议

每个 UDP 报文携带一个 16 字节头部（全部大端）：

| 偏移 | 长度 | 字段      | 说明                  |
| ---- | ---- | --------- | --------------------- |
| 0    | 4    | Magic     | 固定为 `VTUN`         |
| 4    | 1    | Version   | 协议版本，当前为 `1`  |
| 5    | 1    | Type      | 包类型（见下表）      |
| 6    | 2    | Length    | Payload 长度          |
| 8    | 4    | SessionID | 会话 ID（鉴权时分配） |
| 12   | 4    | Sequence  | 序列号（预留）        |
| 16   | N    | Payload   | 载荷                  |

### 包类型

| Type | 名称              | 方向             | Payload                          |
| ---- | ----------------- | ---------------- | -------------------------------- |
| 1    | AUTH              | client→center    | Token 字符串                     |
| 2    | AUTH_OK           | center→client    | 4 字节 VPN IPv4                  |
| 3    | AUTH_FAIL         | center→client    | 失败原因                         |
| 4    | GATEWAY_AUTH      | gateway→center   | JSON（gateway_id/token/networks）|
| 5    | GATEWAY_AUTH_OK   | center→gateway   | 空                               |
| 6    | GATEWAY_AUTH_FAIL | center→gateway   | 失败原因                         |
| 7    | IP                | 双向             | 原始 IP 数据包                   |
| 8/9  | HEARTBEAT / OK    | 预留（第二阶段） | -                                |

### 工作流程

1. **Gateway 注册**：主动连接 Center，发送 GATEWAY_AUTH（携带内网网段），Center 自动建立 `网段 -> Gateway` 路由
2. **Client 认证**：发送 AUTH，Center 分配 SessionID 和 VPN IP（地址池 10.10.0.10–254）
3. **Client → 内网**：Center 按目的 IP 匹配路由，转发到对应 Gateway，写入 TUN 进入内网
4. **内网 → Client**：Gateway TUN 收到回程包发给 Center，Center 按目的 VPN IP 找到 Client Session 转发

## 地址规划

| 角色   | 地址                   | 说明                     |
| ------ | ---------------------- | ------------------------ |
| center | 103.217.197.174:19000  | 公网 UDP，不占用 VPN IP  |
| gateway| 10.10.0.2/24           | Gateway TUN 地址         |
| client | 10.10.0.10–254         | 由 Center 动态分配       |

Center 地址、Token、Gateway 网段等均为各端 `main.go` 顶部的常量，部署时按实际情况修改。

## 运行

三端都需要 root 权限（Center 除外，它不创建 TUN）。

### Center（公网服务器）

```bash
cd center
go build -o center .
./center
```

### Gateway（公司内网 Linux 机器）

```bash
cd gateway
go build -o gateway .
sudo ./gateway
```

启动后自动创建 TUN（10.10.0.2/24）并向 Center 注册内网网段。注意公司内网需要有回程路由：`10.10.0.0/24 via <Gateway 内网 IP>`。

### Client（macOS）

```bash
cd client
go build -o tun-demo .
sudo ./tun-demo
```

启动后自动创建 TUN、认证获取 VPN IP、配置路由，之后访问公司网段（默认 `192.168.0.0/24`）的流量即通过 `Client → Center → Gateway` 隧道转发。

## 测试

```bash
go test ./protocol/
```

## 第一阶段不包含

NAT、心跳与 Session 清理、多租户相同 VPN IP、ACL、Web 管理后台、数据库等（见设计文档第 34 节）。
