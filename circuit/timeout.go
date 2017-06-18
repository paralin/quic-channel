package circuit

// circuitTimeoutError is returned for any timeouts.
type circuitTimeoutError struct {
	error
	temp bool
}

// Timeout returns if this is a timeout or not.
func (c *circuitTimeoutError) Timeout() bool {
	return true
}

// Temporary returns if this is a temporary error or not.
func (c *circuitTimeoutError) Temporary() bool {
	return c.temp
}
