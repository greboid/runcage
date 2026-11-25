package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/varlink/go/varlink"
)

const CredsInterface = "io.systemd.Credentials"

var defaultSockets = []string{
	"/run/systemd/io.systemd.Credentials",
	"/run/varlink/registry/io.systemd.Credentials",
}

// Accept=yes socket: one connection per call.
type CredsClient struct {
	address string
}

func NewCredsClient() (*CredsClient, error) {
	var lastErr error
	for _, path := range defaultSockets {
		conn, err := net.DialTimeout("unix", path, 2*time.Second)
		if err == nil {
			conn.Close()
			return &CredsClient{address: "unix:" + path}, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("systemd credential varlink socket not reachable (tried %s): requires systemd >= 258 with systemd-creds.socket active: %w", strings.Join(defaultSockets, ", "), lastErr)
}

func NewCredsClientAt(address string) *CredsClient {
	return &CredsClient{address: address}
}

// blob is the credential file's base64 content.
func (c *CredsClient) Decrypt(ctx context.Context, name, blob string) ([]byte, error) {
	if _, err := base64.StdEncoding.DecodeString(blob); err != nil {
		return nil, errors.New("credential file is not base64")
	}
	type params struct {
		Name string `json:"name,omitempty"`
		Blob string `json:"blob"`
	}
	var reply struct {
		Data string `json:"data"`
	}
	conn, err := varlink.NewConnection(ctx, c.address)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w", c.address, err)
	}
	defer conn.Close()
	if err := conn.Call(ctx, CredsInterface+".Decrypt", params{Name: name, Blob: blob}, &reply); err != nil {
		return nil, callError("Decrypt", err)
	}
	data, err := base64.StdEncoding.DecodeString(reply.Data)
	if err != nil {
		return nil, fmt.Errorf("%s.Decrypt returned invalid plaintext", CredsInterface)
	}
	return data, nil
}

func callError(method string, err error) error {
	if _, ok := errors.AsType[*varlink.InterfaceNotFound](err); ok {
		return fmt.Errorf("%s interface is not provided by this systemd (requires systemd >= 258)", CredsInterface)
	}
	if _, ok := errors.AsType[*varlink.MethodNotImplemented](err); ok {
		return fmt.Errorf("%s.%s is not implemented by this systemd (requires systemd >= 258)", CredsInterface, method)
	}
	if invalidParam, ok := errors.AsType[*varlink.InvalidParameter](err); ok {
		return fmt.Errorf("%s.%s rejected parameter %s", CredsInterface, method, invalidParam.Parameter)
	}
	vlerr, ok := errors.AsType[*varlink.Error](err)
	if !ok {
		return fmt.Errorf("%s.%s failed: %w", CredsInterface, method, err)
	}
	reason := map[string]string{
		"io.systemd.System":                        "not available on this system (for example no TPM for a tpm2 binding, or no host key)",
		CredsInterface + ".NameMismatch":           "the credential name does not match the name it was encrypted with",
		CredsInterface + ".TimeMismatch":           "the credential is not valid at this time",
		CredsInterface + ".BadFormat":              "the credential is corrupt or in an unsupported format",
		CredsInterface + ".NullKeyNotAllowed":      "the credential uses null encryption, which is not permitted",
		CredsInterface + ".KeyBelongsToOtherTPM":   "the credential is bound to a different TPM",
		CredsInterface + ".UnexpectedPCRState":     "TPM PCR state does not match the state the credential was sealed against",
		CredsInterface + ".TPMInDictionaryLockout": "the TPM is in dictionary lockout",
		CredsInterface + ".NoSuchUser":             "the credential is scoped to a user that does not exist",
		CredsInterface + ".BadScope":               "the credential does not match the requested scope",
		"org.varlink.service.MethodNotImplemented": "not implemented by this systemd (requires systemd >= 258)",
		"org.varlink.service.InterfaceNotFound":    "interface not provided by this systemd (requires systemd >= 258)",
	}[vlerr.Name]
	if reason == "" {
		reason = vlerr.Name
	}
	return fmt.Errorf("%s.%s failed: %s", CredsInterface, method, reason)
}
