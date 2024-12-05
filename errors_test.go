package extism

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewHostFuncError(t *testing.T) {
	tests := []struct {
		name     string
		inputErr error
		wantNil  bool
	}{
		{
			name:     "nil error input",
			inputErr: nil,
			wantNil:  true,
		},
		{
			name:     "non-nil error input",
			inputErr: errors.New("test error"),
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newHostFuncError(tt.inputErr)
			if (err == nil) != tt.wantNil {
				t.Errorf("got nil: %v, want nil: %v", err == nil, tt.wantNil)
			}
		})
	}
}

func TestBytes(t *testing.T) {
	tests := []struct {
		name       string
		inputErr   error
		wantPrefix []byte
		wantMsg    string
		wantNil    bool
	}{
		{
			name:       "nil inner error",
			inputErr:   nil,
			wantPrefix: nil,
			wantMsg:    "",
			wantNil:    true,
		},
		{
			name:       "non-nil inner error",
			inputErr:   errors.New("test error"),
			wantPrefix: errPrefix,
			wantMsg:    "test error",
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &hostFuncError{inner: tt.inputErr}
			b := e.bytes()

			if tt.wantNil {
				if b != nil {
					t.Errorf("expected nil, got %x", b)
				}
				return
			}

			if len(b) < len(tt.wantPrefix) {
				t.Fatalf("returned bytes too short, got %x, want prefix %x", b, tt.wantPrefix)
			}

			if !bytes.HasPrefix(b, tt.wantPrefix) {
				t.Errorf("expected prefix %x, got %x", tt.wantPrefix, b[:len(tt.wantPrefix)])
			}

			gotMsg := string(b[len(tt.wantPrefix):])
			if gotMsg != tt.wantMsg {
				t.Errorf("expected message %q, got %q", tt.wantMsg, gotMsg)
			}
		})
	}
}

func TestIsHostFuncError(t *testing.T) {
	tests := []struct {
		name     string
		inputErr []byte
		want     bool
	}{
		{
			name:     "nil error input",
			inputErr: nil,
			want:     false,
		},
		{
			name:     "not a hostFuncError",
			inputErr: []byte("normal error"),
			want:     false,
		},
		{
			name:     "valid hostFuncError",
			inputErr: newHostFuncError(errors.New("host function error")).bytes(),
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHostFuncError(tt.inputErr)
			if got != tt.want {
				t.Errorf("isHostFuncError(%v) = %v, want %v", tt.inputErr, got, tt.want)
			}
		})
	}
}
