//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// ============================================================
// 配置 TUN（Windows）
//
// 前置条件：
//
//  songgao/water 在 Windows 上依赖 TAP-Windows 驱动
// （tap-windows6，OpenVPN 附带），name 为适配器名，
// 例如 "Ethernet 2"。以下命令需要以管理员权限运行。
//
// 使用 netsh 配置静态 IP：
//
//     netsh interface ip set address name="Ethernet 2" static 10.10.0.2 255.255.255.0
//
// ============================================================

func configureTUN(name string) error {

	cmd := exec.Command(
		"netsh",
		"interface",
		"ip",
		"set",
		"address",
		fmt.Sprintf("name=%s", name),
		"static",
		TUNIP,
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
		"TUN configured: %s/%s\n",
		TUNIP,
		TUNMask,
	)

	return nil
}
