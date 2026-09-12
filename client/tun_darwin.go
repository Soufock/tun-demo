//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// ============================================================
// 配置 TUN（macOS）
//
// utun 是点对点接口：
//
//     ifconfig utun4 10.10.0.10 10.10.0.2
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
		"ifconfig",
		tunName,
		clientIP,
		peerIP,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {

		return fmt.Errorf(
			"configure TUN failed: %v: %s",
			err,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	fmt.Printf(
		"TUN configured: %s -> %s -> %s\n",
		tunName,
		clientIP,
		peerIP,
	)

	return nil
}

// ============================================================
// 配置公司网段路由（macOS）
//
//     route delete -net 192.168.0.0/24
//     route add -net 192.168.0.0/24 10.10.0.2
//
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

	// ============================================================
	// 先删除旧路由
	// ============================================================

	fmt.Println(
		"Deleting old route if exists...",
	)

	delCmd := exec.Command(
		"route",
		"delete",
		"-net",
		network,
	)

	output, err := delCmd.CombinedOutput()

	if err != nil {

		// 路由不存在属于正常情况
		fmt.Printf(
			"Delete route result: %s\n",
			strings.TrimSpace(
				string(output),
			),
		)
	} else {

		fmt.Println(
			"Old route deleted.",
		)
	}

	// ============================================================
	// 添加新路由
	// ============================================================

	cmd := exec.Command(
		"route",
		"add",
		"-net",
		network,
		gatewayIP,
	)

	output, err = cmd.CombinedOutput()

	if err != nil {

		// 已经存在也可以忽略
		if strings.Contains(
			string(output),
			"File exists",
		) {

			fmt.Println(
				"Route already exists.",
			)

			return nil
		}

		return fmt.Errorf(
			"add route failed: %v: %s",
			err,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	fmt.Printf(
		"Route added: %s -> %s\n",
		network,
		gatewayIP,
	)

	return nil
}
