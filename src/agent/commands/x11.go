//go:build !windows

package commands

// Minimal pure-Go X11 client used for remote desktop / remote control on Unix.
// It speaks the X11 wire protocol directly (no cgo, no external libraries):
// screen capture via GetImage on the root window and input injection via the
// XTEST FakeInput extension. The connection byte order is little-endian.

import (
	"errors"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	xOpcodeGetImage       = 73
	xOpcodeQueryExtension = 98
	xOpcodeWarpPointer    = 41
	zPixmap               = 2

	// XTEST extension subopcodes (major opcode from QueryExtension).
	xtQueryVersion = 0
	xtFakeInput    = 2

	// FakeInput "type" uses the core X event types (X.h): KeyPress=2,
	// KeyRelease=3, ButtonPress=4, ButtonRelease=5, MotionNotify=6.
	xtButtonDown  = 4
	xtButtonUp    = 5
	xtKeyDown     = 2
	xtKeyRelease  = 3
)

// x11 is a minimal X11 connection to a single screen.
type x11 struct {
	conn      net.Conn
	root      uint32
	w         int
	h         int
	depth     int
	lsbFirst  bool // image byte order (LSBFirst on x86 Linux)
	xtest     byte // XTEST extension major opcode
	composite byte // Composite extension major opcode (0 = not queried)
}

// xError is an X protocol error reply.
type xError struct {
	code  byte
	major byte
	minor uint16
	value uint32
}

func (e *xError) Error() string {
	return fmt.Sprintf("x11 error 0x%02x (major %d minor %d value 0x%x)", e.code, e.major, e.minor, e.value)
}

// x11Open connects to the display in $DISPLAY and prepares capture + XTEST.
func x11Open() (*x11, error) {
	disp := os.Getenv("DISPLAY")
	if disp == "" {
		return nil, fmt.Errorf("X11 DISPLAY is not set")
	}
	host, dnum, err := parseDisplay(disp)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	if host == "" {
		conn, err = net.DialTimeout("unix", fmt.Sprintf("/tmp/.X11-unix/X%d", dnum), 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("connect to X display %s: %w", disp, err)
		}
	} else {
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(6000+dnum)), 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("connect to X display %s: %w", disp, err)
		}
	}

	c := &x11{conn: conn}

	// Most servers require MIT-MAGIC-COOKIE-1 authorization. Try with a cookie
	// from XAUTHORITY / ~/.Xauthority first, then fall back to an open server.
	if err := c.setup(authForDisplay(dnum)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	opcode, err := c.queryExtension("XTEST")
	if err != nil {
		conn.Close()
		return nil, err
	}
	if opcode == 0 {
		conn.Close()
		return nil, fmt.Errorf("XTEST extension is not available on this X server")
	}
	c.xtest = byte(opcode)
	return c, nil
}

// authForDisplay returns the MIT-MAGIC-COOKIE-1 name/data for a display number
// read from XAUTHORITY (or ~/.Xauthority). Returns empty values when no cookie
// is available so callers can try an unauthenticated connection.
func authForDisplay(dnum int) (string, []byte) {
	path := os.Getenv("XAUTHORITY")
	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			path = home + "/.Xauthority"
		}
	}
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	for len(data) > 0 {
		if len(data) < 2 {
			break
		}
		family := binary.BigEndian.Uint16(data[0:2])
		addrLen := int(binary.BigEndian.Uint16(data[2:4]))
		off := 4 + addrLen
		if len(data) < off+2 {
			break
		}
		numLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if len(data) < off+numLen {
			break
		}
		number := string(data[off : off+numLen])
		off += numLen
		if len(data) < off+2 {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if len(data) < off+nameLen {
			break
		}
		name := string(data[off : off+nameLen])
		off += nameLen
		if len(data) < off+2 {
			break
		}
		dataLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if len(data) < off+dataLen {
			break
		}
		cookie := data[off : off+dataLen]
		data = data[off+dataLen:]

		// FamilyWild (256) or FamilyLocal (0) entries match a local display.
		if (family == 256 || family == 0) && name == "MIT-MAGIC-COOKIE-1" {
			if n, err := strconv.Atoi(number); err == nil && n == dnum {
				return name, cookie
			}
		}
	}
	return "", nil
}

// parseDisplay splits a DISPLAY value into host and display number.
// Accepted forms: ":N[.screen]", "host:N[.screen]", "[proto/]host:N".
func parseDisplay(disp string) (host string, dnum int, err error) {
	// Strip an optional transport prefix, e.g. "unix/" or "tcp/".
	if i := strings.IndexByte(disp, '/'); i >= 0 {
		disp = disp[i+1:]
	}
	i := strings.LastIndexByte(disp, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("invalid DISPLAY: %s", disp)
	}
	host = disp[:i]
	num := disp[i+1:]
	// Drop the ".screen" suffix (dots in the host must be left alone).
	if j := strings.IndexByte(num, '.'); j >= 0 {
		num = num[:j]
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return "", 0, fmt.Errorf("invalid display number in DISPLAY: %s", disp)
	}
	return host, n, nil
}

// setup performs the X11 connection handshake and parses the first screen.
// It first tries the supplied authorization, then retries without any so that
// open (unauthenticated) servers also work.
func (c *x11) setup(authName string, authData []byte) error {
	if err := c.trySetup(authName, authData); err != nil {
		if authName != "" {
			if err2 := c.trySetup("", nil); err2 == nil {
				return nil
			}
		}
		return err
	}
	return nil
}

// trySetup writes the setup request, validates the reply and locates the first
// screen. Some servers (e.g. Xwayland) order the additional data as
// vendor -> pixmap-formats -> screens, which breaks the offsets in the classic
// spec; the screen is therefore found by scanning for its 40-byte structure.
func (c *x11) trySetup(authName string, authData []byte) error {
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	// The auth name is padded to a 4-byte boundary before the auth data.
	nameLen := len(authName)
	namePad := (4 - nameLen%4) % 4
	req := make([]byte, 12+nameLen+namePad+len(authData))
	req[0] = 'l'
	// The byte-order byte ('l') applies to the setup request fields too:
	// multi-byte values are little-endian (Xlib and libxcb do the same).
	binary.LittleEndian.PutUint16(req[2:4], 11) // protocol version 11.0
	binary.LittleEndian.PutUint16(req[4:6], 0)  // protocol minor version 0
	binary.LittleEndian.PutUint16(req[6:8], uint16(nameLen))
	binary.LittleEndian.PutUint16(req[8:10], uint16(len(authData)))
	copy(req[12:], authName)
	copy(req[12+nameLen+namePad:], authData)
	if _, err := c.conn.Write(req); err != nil {
		return fmt.Errorf("x11 setup write: %w", err)
	}

	// Byte 0 of the reply is the success flag (1) or failure reason (0).
	first := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, first); err != nil {
		return fmt.Errorf("x11 setup read: %w", err)
	}
	if first[0] != 1 {
		reason := string(c.readAvailable())
		msg := strings.TrimSpace(strings.TrimRight(reason, "\x00 "))
		if msg == "" {
			msg = "authorization failed"
		}
		return fmt.Errorf("x11 %s", msg)
	}

	// Success: the rest of the 40-byte header is unused by us; read the
	// remaining additional data and scan it for the screen structure.
	if _, err := io.ReadFull(c.conn, make([]byte, 39)); err != nil {
		return fmt.Errorf("x11 setup read header: %w", err)
	}
	extra := c.readAvailable()

	// Default to little-endian pixel order (LSBFirst) — the norm on x86 Linux.
	c.lsbFirst = true

	if root, w, h, depth, ok := findScreen(extra); ok {		c.root = root
		c.w = w
		c.h = h
		c.depth = depth
		return nil
	}
	return fmt.Errorf("could not locate the X screen in the setup reply")
}

// readAvailable drains the connection until the server goes quiet. Used to
// collect the setup reply whose length is not advertised in a reliable field
// on every server.
func (c *x11) readAvailable() []byte {
	_ = c.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var buf []byte
	tmp := make([]byte, 8192)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			continue
		}
		if err != nil {
			break
		}
	}
	_ = c.conn.SetReadDeadline(time.Time{})
	return buf
}

// findScreen scans a setup-reply buffer for a 40-byte screen structure. A
// screen block has width/height at +20/+22, root depth at +38 and a plausible
// (aligned, non-zero) root window id at +0.
func findScreen(buf []byte) (root uint32, w, h, depth int, ok bool) {
	for o := 0; o+40 <= len(buf); o += 4 {
		w := int(binary.LittleEndian.Uint16(buf[o+20 : o+22]))
		h := int(binary.LittleEndian.Uint16(buf[o+22 : o+24]))
		d := int(buf[o+38])
		if w < 64 || w > 32768 || h < 64 || h > 32768 {
			continue
		}
		if d != 15 && d != 16 && d != 24 && d != 32 {
			continue
		}
		r := binary.LittleEndian.Uint32(buf[o : o+4])
		if r == 0 || r%4 != 0 {
			continue
		}
		return r, w, h, d, true
	}
	return 0, 0, 0, 0, false
}

// request sends an X11 request: opcode, data byte, then body (LE multi-byte),
// padding to a 4-byte boundary.
func (c *x11) request(opcode, data byte, body []byte) error {
	n := 4 + len(body)
	padded := (n + 3) &^ 3
	buf := make([]byte, padded)
	buf[0] = opcode
	buf[1] = data
	binary.LittleEndian.PutUint16(buf[2:4], uint16(padded/4))
	copy(buf[4:], body)
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err := c.conn.Write(buf)
	return err
}

// readReply reads a 32-byte reply header and its trailing data. X error
// replies (first byte 0) are returned as *xError.
func (c *x11) readReply() (hdr, data []byte, err error) {
	hdr = make([]byte, 32)
	if _, err := io.ReadFull(c.conn, hdr); err != nil {
		return nil, nil, err
	}
	if hdr[0] != 1 {
		if hdr[0] == 0 {
			// X error reply: code(1) seq(2-3) value(4-7) minor(8-9) major(10)
			return nil, nil, &xError{
				code:  hdr[1],
				major: hdr[10],
				minor: binary.LittleEndian.Uint16(hdr[8:10]),
				value: binary.LittleEndian.Uint32(hdr[4:8]),
			}
		}
		return nil, nil, fmt.Errorf("expected x11 reply, got 0x%02x", hdr[0])
	}
	n := int(binary.LittleEndian.Uint32(hdr[4:8])) * 4
	if n > 0 {
		data = make([]byte, n)
		if _, err := io.ReadFull(c.conn, data); err != nil {
			return nil, nil, err
		}
	}
	return hdr, data, nil
}

// isXErrorCode reports whether err is an X error with the given code.
func isXErrorCode(err error, code byte) bool {
	var xe *xError
	return errors.As(err, &xe) && xe.code == code
}

// getImage captures the root window as raw pixels (ZPixmap).
func (c *x11) getImage() ([]byte, int, error) {
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[0:4], c.root)
	binary.LittleEndian.PutUint16(body[4:6], 0) // x
	binary.LittleEndian.PutUint16(body[6:8], 0) // y
	binary.LittleEndian.PutUint16(body[8:10], uint16(c.w))
	binary.LittleEndian.PutUint16(body[10:12], uint16(c.h))
	binary.LittleEndian.PutUint32(body[12:16], 0xffffffff) // all planes

	if err := c.request(xOpcodeGetImage, zPixmap, body); err != nil {
		return nil, 0, err
	}
	hdr, data, err := c.readReply()
	if err != nil {
		return nil, 0, err
	}
	depth := int(hdr[2])
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("x11 GetImage returned no data")
	}
	return data, depth, nil
}

// grabImage captures the root window. On rootless Xwayland / composited
// servers the root has no direct backing, so GetImage fails with BadMatch;
// the root is then captured through its Composite window pixmap.
func (c *x11) grabImage() ([]byte, int, error) {
	data, depth, err := c.getImage()
	if err == nil {
		return data, depth, nil
	}
	if !isXErrorCode(err, 8) { // 8 = BadMatch
		return nil, 0, err
	}

	// Redirect the root offscreen (tolerate "already redirected" by a running
	// compositor), then capture the backing pixmap instead of the window.
	if cerr := c.compositeRedirect(); cerr != nil && !isXErrorCode(cerr, 10) {
		return nil, 0, err // report the original BadMatch
	}
	pix, perr := c.compositeNameWindowPixmap()
	if perr != nil || pix == 0 {
		return nil, 0, err
	}
	savedRoot := c.root
	c.root = pix
	data, depth, err = c.getImage()
	c.root = savedRoot
	if err != nil {
		return nil, 0, err
	}
	return data, depth, nil
}

// compositeRedirect redirects the root window offscreen via Composite so its
// contents can be captured with GetImage. update = Automatic (0). Returns
// BadAccess (code 10) when a compositor has already redirected the window.
func (c *x11) compositeRedirect() error {
	if err := c.ensureComposite(); err != nil {
		return err
	}
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], c.root)
	body[4] = 0 // update = Automatic
	return c.request(c.composite, 2 /* RedirectWindow */, body)
}

// compositeNameWindowPixmap returns the window's backing pixmap (which works
// on rootless Xwayland where GetImage on the window itself fails with
// BadMatch). NameWindowPixmap is Composite request code 6.
func (c *x11) compositeNameWindowPixmap() (uint32, error) {
	if err := c.ensureComposite(); err != nil {
		return 0, err
	}
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body[0:4], c.root)
	if err := c.request(c.composite, 6 /* NameWindowPixmap */, body); err != nil {
		return 0, err
	}
	hdr, _, err := c.readReply()
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(hdr[8:12]), nil
}

func (c *x11) ensureComposite() error {
	if c.composite != 0 {
		return nil
	}
	opcode, err := c.queryExtension("Composite")
	if err != nil {
		return err
	}
	if opcode == 0 {
		return fmt.Errorf("Composite extension is not available")
	}
	c.composite = byte(opcode)
	// The Composite protocol requires a QueryVersion handshake first.
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], 0) // client major
	binary.LittleEndian.PutUint32(body[4:8], 0) // client minor
	if err := c.request(c.composite, 0 /* QueryVersion */, body); err != nil {
		return err
	}
	if _, _, err := c.readReply(); err != nil {
		return err
	}
	return nil
}

// queryExtension resolves an extension name to its major opcode (0 = absent).
// The request layout is: header(4) + nbytes(2) + pad(2) + name(aligned to 4),
// i.e. the name starts at offset 8 (matching Xlib's xQueryExtensionReq). The
// reply carries the opcode as a single byte at offset 9 (offset 8 = present).
func (c *x11) queryExtension(name string) (int, error) {
	namePad := (4 - len(name)%4) % 4
	body := make([]byte, 4+len(name)+namePad)
	binary.LittleEndian.PutUint16(body[0:2], uint16(len(name)))
	copy(body[4:], name)
	if err := c.request(xOpcodeQueryExtension, 0, body); err != nil {
		return 0, err
	}
	hdr, _, err := c.readReply()
	if err != nil {
		return 0, err
	}
	if hdr[8] != 1 {
		return 0, nil // extension not present
	}
	return int(hdr[9]), nil
}

// fakeInput injects an XTEST FakeInput event (subopcode 2). mtype is one of
// xtButtonDown/xtButtonUp/xtKeyDown/xtKeyRelease. The request layout matches
// libXtst: type(1) detail(1) pad(2) time(4) root(4) x(2) y(2) — time at
// offset 8, root may be None on Wayland.
func (c *x11) fakeInput(mtype, detail byte, x, y int) error {
	body := make([]byte, 32)
	body[0] = mtype
	body[1] = detail
	binary.LittleEndian.PutUint32(body[4:8], 0) // time = CurrentTime
	binary.LittleEndian.PutUint32(body[8:12], 0) // root = None
	binary.LittleEndian.PutUint16(body[12:14], uint16(x))
	binary.LittleEndian.PutUint16(body[14:16], uint16(y))
	return c.request(c.xtest, xtFakeInput, body)
}

// warpPointer moves the pointer absolutely via the core WarpPointer request
// (opcode 41). This is what xdotool uses for mousemove and works on Xwayland,
// whereas XTEST motion events are unreliable there.
func (c *x11) warpPointer(x, y int) error {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[4:8], c.root) // destination = root
	binary.LittleEndian.PutUint16(body[16:18], uint16(x))
	binary.LittleEndian.PutUint16(body[18:20], uint16(y))
	return c.request(xOpcodeWarpPointer, 0, body)
}

// close shuts down the connection.
func (c *x11) close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// vkToKeycode maps a Windows virtual-key code (as sent by the frontend's
// e.keyCode) to an X11 keycode on the standard US evdev layout.
func vkToKeycode(code int) int {
	switch code {
	case 8:
		return 22 // Backspace
	case 9:
		return 23 // Tab
	case 13:
		return 36 // Enter
	case 27:
		return 9 // Escape
	case 32:
		return 65 // Space
	case 33:
		return 112 // PageUp
	case 34:
		return 117 // PageDown
	case 35:
		return 115 // End
	case 36:
		return 110 // Home
	case 37:
		return 113 // Left
	case 38:
		return 111 // Up
	case 39:
		return 114 // Right
	case 40:
		return 116 // Down
	case 45:
		return 118 // Insert
	case 46:
		return 119 // Delete
	case 16:
		return 50 // Shift_L
	case 17:
		return 37 // Control_L
	case 18:
		return 64 // Alt_L
	case 20:
		return 66 // Caps_Lock
	case 91:
		return 133 // Super_L (Meta)
	case 48:
		return 19 // '0'
	}
	if code >= 49 && code <= 57 { // '1'..'9'
		return 10 + (code - 49)
	}
	if code >= 65 && code <= 90 { // 'A'..'Z' by US keyboard rows
		idx := strings.IndexByte("qwertyuiopasdfghjklzxcvbnm", byte(code+32))
		switch {
		case idx < 0:
			return 0
		case idx < 10:
			return 24 + idx
		case idx < 19:
			return 38 + (idx - 10)
		default:
			return 52 + (idx - 19)
		}
	}
	if code >= 112 && code <= 121 { // F1..F10
		return 67 + (code - 112)
	}
	switch code {
	case 122:
		return 95 // F11
	case 123:
		return 96 // F12
	}
	// US punctuation.
	switch code {
	case 186:
		return 47 // ;
	case 187:
		return 21 // =
	case 188:
		return 59 // ,
	case 189:
		return 20 // -
	case 190:
		return 60 // .
	case 191:
		return 61 // /
	case 192:
		return 49 // `
	case 219:
		return 34 // [
	case 220:
		return 51 // \
	case 221:
		return 35 // ]
	case 222:
		return 48 // '
	}
	return 0
}
