package runtime

import (
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Invocation
	}{
		{
			name: "containerd shim create",
			args: []string{"--root", "/var/run/docker/runtime-runc/moby", "--log", "/run/x/log.json", "--log-format", "json", "--systemd-cgroup",
				"create", "--bundle", "/run/b", "--pid-file", "/run/b/init.pid", "--console-socket", "/tmp/s", "abc"},
			want: Invocation{Command: "create", ID: "abc", Bundle: "/run/b", Log: "/run/x/log.json", LogFormat: "json"},
		},
		{
			name: "equals and single dash",
			args: []string{"-log=/l", "--log-format=text", "create", "-b=/b", "id"},
			want: Invocation{Command: "create", ID: "id", Bundle: "/b", Log: "/l", LogFormat: "text"},
		},
		{
			name: "short bundle",
			args: []string{"run", "-d", "-b", "/b", "id"},
			want: Invocation{Command: "run", ID: "id", Bundle: "/b"},
		},
		{
			name: "value flag named like command",
			args: []string{"--root", "create", "start", "id"},
			want: Invocation{Command: "start"},
		},
		{
			name: "no bundle",
			args: []string{"create", "--pid-file", "-b", "id"},
			want: Invocation{Command: "create", ID: "id"},
		},
		{
			name: "checkpoint",
			args: []string{"--root", "/r", "checkpoint", "--image-path", "/img", "--leave-running", "abc"},
			want: Invocation{Command: "checkpoint", ID: "abc"},
		},
		{
			name: "terminated options",
			args: []string{"--", "checkpoint", "--", "id"},
			want: Invocation{Command: "checkpoint", ID: "id"},
		},
		{
			name: "restore with bundle and list flags",
			args: []string{"restore", "--empty-ns", "net", "--empty-ns=net", "-b=/bundle", "--", "id"},
			want: Invocation{Command: "restore", ID: "id", Bundle: "/bundle"},
		},
		{
			name: "unrelated payload is not parsed",
			args: []string{"exec", "id", "example", "--unknown", "checkpoint"},
			want: Invocation{Command: "exec"},
		},
		{
			name: "version",
			args: []string{"--version"},
			want: Invocation{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseArgs(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			got.Global = nil
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
