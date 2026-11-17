package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/internal/platform"
	"github.com/zema1/watchvuln/plugins/legacy"
)

var Version = "v2.7.0"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--collector-worker" {
		golog.Default.SetLevel("disable")
		exitOnError(platform.CollectorWorker(os.Args[2]))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "plugin" {
		if len(os.Args) < 3 || os.Args[2] != "legacy" {
			exitOnError(fmt.Errorf("支持的插件：legacy"))
			return
		}
		os.Args = append([]string{os.Args[0]}, os.Args[3:]...)
		legacy.Run(Version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] != "web" {
		legacy.Run(Version)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	exitOnError(platform.Run(ctx, env("WATCHVULN_ADDR", ":18080"), env("WATCHVULN_DATA", "data"), env("WATCHVULN_ASSETS", "frontend/dist")))
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func exitOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
