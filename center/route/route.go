// Package route 负责 Center 侧的路由表管理：
//
// 网段 -> Gateway 的映射，支持添加路由、
// 按 Gateway 删除路由（Gateway 重复注册时清理旧路由）、
// 按目的 IP 查找 Gateway。
//
// 纯数据管理，不做网络收发。
package route

import (
	"net"
	"sync"
)

// ============================================================
// Route
//
//     网段 -> Gateway
//
// 例如：
//
//     192.168.0.0/24  -> company-a
//     192.168.10.0/24 -> company-b
//
// ============================================================

type Route struct {
	Network   *net.IPNet
	GatewayID string
}

// ============================================================
// RouteTable
// ============================================================

type RouteTable struct {
	mu     sync.RWMutex
	routes []Route
}

func NewRouteTable() *RouteTable {

	return &RouteTable{}
}

// ============================================================
// 添加路由
// ============================================================

func (t *RouteTable) Add(
	network *net.IPNet,
	gatewayID string,
) {

	t.mu.Lock()
	defer t.mu.Unlock()

	t.routes = append(
		t.routes,
		Route{
			Network:   network,
			GatewayID: gatewayID,
		},
	)
}

// ============================================================
// 删除某个 Gateway 的全部路由
//
// Gateway 重复注册时用于清理旧路由
// ============================================================

func (t *RouteTable) DeleteByGateway(
	gatewayID string,
) {

	t.mu.Lock()
	defer t.mu.Unlock()

	kept := t.routes[:0]

	for _, route := range t.routes {
		if route.GatewayID != gatewayID {
			kept = append(kept, route)
		}
	}

	t.routes = kept
}

// ============================================================
// 查找：目的 IP -> GatewayID
//
// 第一阶段路由数量很少，线性扫描足够。
// 后续路由增多时可以换成前缀树（Trie），
// 并支持最长前缀匹配。
// ============================================================

func (t *RouteTable) FindGatewayID(
	dstIP net.IP,
) string {

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, route := range t.routes {
		if route.Network.Contains(dstIP) {
			return route.GatewayID
		}
	}

	return ""
}
