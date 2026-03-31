package main

import "testing"

func TestListenerNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "wildcard ipv4 uses tcp4",
			host: "0.0.0.0",
			want: "tcp4",
		},
		{
			name: "loopback ipv4 uses tcp4",
			host: "127.0.0.1",
			want: "tcp4",
		},
		{
			name: "wildcard ipv6 uses tcp6",
			host: "::",
			want: "tcp6",
		},
		{
			name: "named hosts stay generic",
			host: "localhost",
			want: "tcp",
		},
		{
			name: "empty host stays generic",
			host: "",
			want: "tcp",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := listenerNetwork(tt.host); got != tt.want {
				t.Fatalf("listenerNetwork(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
