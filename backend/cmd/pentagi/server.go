package main

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

func listenerNetwork(host string) string {
	if host == "" {
		return "tcp"
	}

	if host == "0.0.0.0" {
		return "tcp4"
	}

	if host == "::" {
		return "tcp6"
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "tcp"
	}

	if ip.To4() != nil {
		return "tcp4"
	}

	return "tcp6"
}

func serveEngine(engine *gin.Engine, listen, network, certFile, keyFile string) error {
	listener, err := net.Listen(network, listen)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: engine.Handler(),
	}

	if certFile != "" && keyFile != "" {
		return server.ServeTLS(listener, certFile, keyFile)
	}

	return server.Serve(listener)
}
