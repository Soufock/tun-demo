//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// ============================================================
// 配置 TUN（Windows）
//
// 前置条件：
//
//  songgao/water 在 Windows 上依赖 TAP-Windows 驱动
// （tap-windows6，OpenVPN 附带），tunName 为适配器名，
// 例如 "Ethernet 2"。以下命令需要以管理员权限运行。
//
// 使用 netsh 配置静态 IP：
//
//     netsh interface ip set address name="Ethernet 2" static 10.10.0.10 255.255.255.0
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

	cmd := exec.Command(
		"netsh",
		"interface",
		"ip",
		"set",
		"address",
		fmt.Sprintf("name=%s", tunName),
		"static",
		clientIP,
		"255.255.255.0",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure TUN failed (need administrator?): %v: %s",
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
// 配置公司网段路由（Windows）
//
//     route delete 192.168.0.0
//     route add 192.168.0.0 mask 255.255.255.0 10.10.0.2
//
// CIDR 需要拆成网段地址 + 点分掩码
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

	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf(
			"invalid network %q: %w",
			network,
			err,
		)
	}

	netAddr := ipNet.IP.String()
	mask := net.IP(
		ipNet.Mask,
	).String()

	// ============================================================
	// 先删除旧路由（不存在属于正常情况）
	// ============================================================

	_ = exec.Command(
		"route",
		"delete",
		netAddr,
	).Run()

	// ============================================================
	// 添加新路由
	// ============================================================

	cmd := exec.Command(
		"route",
		"add",
		netAddr,
		"mask",
		mask,
		gatewayIP,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"add route failed (need administrator?): %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	fmt.Printf(
		"Route added: %s mask %s -> %s\n",
		netAddr,
		mask,
		gatewayIP,
	)

	return nil
}
