//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// ============================================================
// 配置 TUN（Linux）
//
// Linux TUN 是网络接口而非点对点，
// 直接配置 /24 地址使 10.10.0.0/24 整条网段进入 TUN：
//
//     ip addr flush dev tun0
//     ip addr add 10.10.0.10/24 dev tun0
//     ip link set dev tun0 up
//
// ============================================================

func configureTUN(
	tunName string,
	clientIP string,
	peerIP string,
) error {

	fmt.Printf(
		"Configuring TUN %s...\n",
		tunName,
	)

	// 删除旧配置
	_ = exec.Command(
		"ip",
		"addr",
		"flush",
		"dev",
		tunName,
	).Run()

	cmd := exec.Command(
		"ip",
		"addr",
		"add",
		clientIP+"/24",
		"dev",
		tunName,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure IP failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	cmd = exec.Command(
		"ip",
		"link",
		"set",
		"dev",
		tunName,
		"up",
	)

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"bring TUN up failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	fmt.Printf(
		"TUN configured: %s -> %s/24\n",
		tunName,
		clientIP,
	)

	return nil
}

// ============================================================
// 配置公司网段路由（Linux）
//
// TUN 上的 /24 connected 路由已经覆盖下一跳 10.10.0.2，
// 直接经由它转发：
//
//     ip route replace 192.168.0.0/24 via 10.10.0.2
//
// 用 replace 避免重复添加报错
// ============================================================

func configureRoute(
	network string,
	gatewayIP string,
) error {

	fmt.Printf(
		"Configuring route %s via %s...\n",
		network,
		gatewayIP,
	)

	cmd := exec.Command(
		"ip",
		"route",
		"replace",
		network,
		"via",
		gatewayIP,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"add route failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	fmt.Printf(
		"Route added: %s -> %s\n",
		network,
		gatewayIP,
	)

	return nil
}
