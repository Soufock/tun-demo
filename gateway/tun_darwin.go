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
// utun 是点对点接口，没有网段概念，
// 先配置本地地址（对端指向自己）：
//
//     ifconfig utun4 inet 10.10.0.2 10.10.0.2 up
//
// 再把整个 VPN 网段路由进 TUN：
//
//     route add -net 10.10.0.0/24 -interface utun4
//
// ============================================================

func configureTUN(name string) error {

	cmd := exec.Command(
		"ifconfig",
		name,
		"inet",
		TUNIP,
		TUNIP,
		"up",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure TUN failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	// VPN 网段进入 TUN
	cmd = exec.Command(
		"route",
		"add",
		"-net",
		"10.10.0.0/"+TUNMask,
		"-interface",
		name,
	)

	output, err = cmd.CombinedOutput()
	if err != nil {

		// 已经存在也可以忽略
		if !strings.Contains(
			string(output),
			"File exists",
		) {
			return fmt.Errorf(
				"add VPN route failed: %v: %s",
				err,
				strings.TrimSpace(string(output)),
			)
		}
	}

	fmt.Printf(
		"TUN configured: %s/%s\n",
		TUNIP,
		TUNMask,
	)

	return nil
}
