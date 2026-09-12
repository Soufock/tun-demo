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
//     ip addr flush dev tun0
//     ip addr add 10.10.0.2/24 dev tun0
//     ip link set dev tun0 up
//
// ============================================================

func configureTUN(name string) error {

	// 删除旧配置
	_ = exec.Command(
		"ip",
		"addr",
		"flush",
		"dev",
		name,
	).Run()

	// 10.10.0.2/24
	cmd := exec.Command(
		"ip",
		"addr",
		"add",
		TUNIP+"/"+TUNMask,
		"dev",
		name,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure IP failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	// UP
	cmd = exec.Command(
		"ip",
		"link",
		"set",
		"dev",
		name,
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
		"TUN configured: %s/%s\n",
		TUNIP,
		TUNMask,
	)

	return nil
}
