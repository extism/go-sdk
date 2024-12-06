package extism

import "bytes"

// errPrefix is a sentinel byte sequence used to identify errors originating from host functions.
// It helps distinguish these errors when serialized to bytes.
var errPrefix = []byte{0xFF, 0xFE, 0xFD}

// hostFuncError wraps another error and identifies it as a host function error.
// When a host function is called and that host function wants to return an error,
// internally extism will wrap that error in this type before serializing the error
// using the bytes method, and writing the error into WASM memory so that the guest
// can read the error.
//
// The bytes method appends a set of sentinel bytes which the host can later read
// when calls `error_get` to see if the error that was previously set was set by
// the host or the guest. If we see the matching sentinel bytes in the prefix of
// the error bytes, then we know that the error was a host function error, and the
// host can ignore it.
//
// The purpose of this is to allow us to piggyback off the existing `error_get` and
// `error_set` extism kernel functions. These previously were only used by guests to
// communicate errors to the host. In order to prevent host plugin function calls from
// seeing their own host function errors, the plugin can check and see if the error
// was created via a host function using this type.
//
// This is an effort to preserve backwards compatibility with existing PDKs which
// may not know to call `error_get` to see if there are any host->guest errors. We
// need the host SDKs to handle the scenario where the host calls `error_set` but
// the guest never calls `error_get` resulting in the host seeing their own error.
type hostFuncError struct {
	inner error // The underlying error being wrapped.
}

// Error implements the error interface for hostFuncError.
// It returns the message of the wrapped error or an empty string if there is no inner error.
func (e *hostFuncError) Error() string {
	if e.inner == nil {
		return ""
	}
	return e.inner.Error()
}

// bytes serializes the hostFuncError into a byte slice.
// If there is no inner error, it returns nil. Otherwise, it prefixes the error message
// with a sentinel byte sequence to facilitate identification during deserialization.
func (e *hostFuncError) bytes() []byte {
	if e.inner == nil {
		return nil
	}
	return append(errPrefix, []byte(e.inner.Error())...)
}

// isHostFuncError checks if the given byte slice represents a serialized host function error.
// It verifies the presence of the sentinel prefix to make this determination.
func isHostFuncError(error []byte) bool {
	if error == nil {
		return false
	}
	if len(error) < len(errPrefix) {
		return false // The slice is too short to contain the prefix.
	}
	return bytes.Equal(error[:len(errPrefix)], errPrefix)
}

// newHostFuncError creates a new hostFuncError instance wrapping the provided error.
// If the input error is nil, it returns nil to avoid creating redundant wrappers.
func newHostFuncError(err error) *hostFuncError {
	if err == nil {
		return nil
	}
	return &hostFuncError{inner: err}
}
