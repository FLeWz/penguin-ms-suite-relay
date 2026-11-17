package main

// Minimal RFC 6455 server side: enough for a text-only push channel.
// Server frames are unmasked, client frames must be masked, fragmented
// messages are accepted but their payload is discarded (clients send nothing
// we act on).

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	opCont  = 0x0
	opText  = 0x1
	opBin   = 0x2
	opClose = 0x8
	opPing  = 0x9
	opPong  = 0xA

	maxFramePayload = 64 << 10
	writeTimeout    = 10 * time.Second
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsConn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
}

// upgrade performs the handshake and hijacks the connection.
func upgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if r.Method != http.MethodGet ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(r.Header, "Connection", "upgrade") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("not an upgrade request")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported websocket version", http.StatusUpgradeRequired)
		return nil, errors.New("bad version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return nil, errors.New("missing key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return nil, errors.New("no hijacker")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.Write([]byte(resp)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetWriteDeadline(time.Time{})
	return &wsConn{c: c, br: brw.Reader}, nil
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

func (w *wsConn) writeFrame(op byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	hdr := []byte{0x80 | op, 0}
	switch n := len(payload); {
	case n < 126:
		hdr[1] = byte(n)
	case n <= 0xFFFF:
		hdr[1] = 126
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr[1] = 127
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	w.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := w.c.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

// readFrame returns the next frame. Payload is unmasked.
func (w *wsConn) readFrame() (op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(w.br, h[:]); err != nil {
		return
	}
	op = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(w.br, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(w.br, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if !masked {
		return 0, nil, errors.New("unmasked client frame")
	}
	if n > maxFramePayload {
		return 0, nil, errors.New("frame too large")
	}
	var mask [4]byte
	if _, err = io.ReadFull(w.br, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(w.br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return
}

func (w *wsConn) close() { w.c.Close() }
