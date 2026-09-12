# tun-demo

一个基于 TUN 设备的极简 VPN 演示项目（v2），通过 UDP 将 IP 包封装后在客户端与服务器之间转发，支持 Token 鉴权、多客户端 Session 管理和 VPN IP 动态分配。

## 项目结构

```
├── client/   # VPN 客户端（macOS）
└── server/   # VPN 服务器（Linux）
```

两端都使用 [songgao/water](https://github.com/songgao/water) 创建 TUN 虚拟网卡，通过自定义协议把原始 IP 包封装进 UDP 报文传输。

## v2 相比 v1 的变化

- 协议头部从 8 字节扩展为 16 字节，新增 **SessionID** 和 **Sequence** 字段
- 新增**鉴权握手**：客户端先用 Token 认证，成功后才进入数据传输
- 服务器支持**多客户端**：按 SessionID 管理会话，从地址池动态分配 VPN IP
- 客户端 VPN IP 不再硬编码，由服务器在 AUTH_OK 中下发

## 自定义协议

每个 UDP 报文携带一个 16 字节头部（全部大端）：

| 偏移 | 长度 | 字段      | 说明                 |
| ---- | ---- | --------- | -------------------- |
| 0    | 4    | Magic     | 固定为 `VTUN`        |
| 4    | 1    | Version   | 协议版本，当前为 `1` |
| 5    | 1    | Type      | 包类型（见下表）     |
| 6    | 2    | Length    | Payload 长度         |
| 8    | 4    | SessionID | 会话 ID（鉴权时分配）|
| 12   | 4    | Sequence  | 序列号（预留）       |
| 16   | N    | Payload   | 载荷                 |

### 包类型

| Type | 名称      | 方向           | Payload           |
| ---- | --------- | -------------- | ----------------- |
| 1    | AUTH      | client→server  | Token 字符串      |
| 2    | AUTH_OK   | server→client  | 4 字节 VPN IPv4   |
| 3    | AUTH_FAIL | server→client  | 失败原因字符串    |
| 4    | IP        | 双向           | 原始 IP 数据包    |

### 握手流程

1. 客户端发送 `AUTH`（携带 Token）
2. 服务器校验 Token，失败则回复 `AUTH_FAIL`
3. 成功后服务器分配 SessionID 和 VPN IP，回复 `AUTH_OK`
4. 之后双方用 `TypeIP` 包传输数据，所有 IP 包携带 SessionID

## 地址规划

| 角色   | 地址            | 说明                           |
| ------ | --------------- | ------------------------------ |
| server | 10.10.0.2/24    | 服务器 TUN 地址                |
| client | 10.10.0.10–254  | 由服务器从地址池动态分配       |

客户端需要走 VPN 的网段默认为 `10.88.0.0/24`（`client/main.go` 中的 `VPNNetwork`），服务器 UDP 监听 `:19000`。

鉴权 Token 目前为硬编码的固定字符串（两端 `AuthToken` 常量，默认 `123456`），后续可替换为 JWT / API Key。

## 运行

两端都需要 root 权限（创建 TUN 设备、配置 IP 和路由）。

### 服务器（Linux）

```bash
cd server
go build -o server .
sudo ./server
```

启动后自动创建 TUN 设备并配置 `10.10.0.2/24`，监听 UDP 19000 端口，等待客户端鉴权接入。

### 客户端（macOS）

```bash
cd client
go build -o tun-demo .
sudo ./tun-demo
```

启动后自动创建 TUN 设备、向服务器鉴权获取 VPN IP、配置 TUN 和路由，之后访问 `VPNNetwork` 网段的流量即会通过 VPN 隧道转发。

## 注意

服务器地址硬编码在 `client/main.go` 的 `ServerAddr` 常量中，部署时按实际情况修改。
