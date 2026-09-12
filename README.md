# tun-demo

一个基于 TUN 设备的极简 VPN 演示项目，通过 UDP 将 IP 包封装后在客户端与服务器之间转发。

## 项目结构

```
├── client/   # VPN 客户端（macOS）
└── server/   # VPN 服务器（Linux）
```

两端都使用 [songgao/water](https://github.com/songgao/water) 创建 TUN 虚拟网卡，通过自定义的 8 字节头部把原始 IP 包封装进 UDP 报文传输。

## 自定义协议

每个 UDP 报文携带一个 8 字节头部：

| 偏移 | 长度 | 字段    | 说明                   |
| ---- | ---- | ------- | ---------------------- |
| 0    | 4    | Magic   | 固定为 `VTUN`          |
| 4    | 1    | Version | 协议版本，当前为 `1`   |
| 5    | 1    | Type    | 包类型，`1` 表示 IP 包 |
| 6    | 2    | Length  | 后续 IP 包长度（大端） |
| 8    | N    | Payload | 原始 IP 数据包         |

## 地址规划

| 角色   | TUN 地址   | 说明                       |
| ------ | ---------- | -------------------------- |
| client | 10.10.0.1  | 客户端 TUN 地址            |
| server | 10.10.0.2  | 服务器 TUN 地址（/30）     |

客户端需要走 VPN 的网段默认配置为 `10.88.0.0/24`（`client/main.go` 中的 `VPNNetwork`），服务器 UDP 监听 `:19000`。

## 运行

两端都需要 root 权限（创建 TUN 设备、配置 IP 和路由）。

### 服务器（Linux）

```bash
cd server
go build -o server .
sudo ./server
```

启动后自动创建 TUN 设备并配置 `10.10.0.2/30`，监听 UDP 19000 端口。

### 客户端（macOS）

```bash
cd client
go build -o tun-demo .
sudo ./tun-demo
```

启动后自动创建 TUN 设备（`10.10.0.1 -> 10.10.0.2`）、添加 `VPNNetwork` 网段路由，并连接服务器。之后访问该网段的流量即会通过 VPN 隧道转发。

## 注意

服务器地址硬编码在 `client/main.go` 中，部署时按实际情况修改。
