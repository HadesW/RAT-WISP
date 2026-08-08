package commands

// mockCapture is a deterministic screen-capture stub shared by tests on every
// platform (used by the RDP stream tests on Windows and the screenshot test
// everywhere).
func mockCapture(quality int) ([]byte, int, int, error) {
	return []byte{0xff, 0xd8, 0xff, 0x01}, 4, 4, nil
}
