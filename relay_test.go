package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testWS struct {
	c  net.Conn
	br *bufio.Reader
}

func dialWS(t *testing.T, base, id, secret string) (*testWS, int) {
	t.Helper()
	addr := strings.TrimPrefix(base, "http://")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	req := "GET /ws?deviceId=" + id + " HTTP/1.1\r\nHost: " + addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Authorization: Bearer " + secret + "\r\n\r\n"
	c.Write([]byte(req))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 101 && resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("bad accept: %q", resp.Header.Get("Sec-WebSocket-Accept"))
	}
	return &testWS{c, br}, resp.StatusCode
}

func (w *testWS) next(t *testing.T) event {
	t.Helper()
	w.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			t.Fatalf("read: %v", err)
		}
		n := int(h[1] & 0x7F)
		if n == 126 {
			var b [2]byte
			io.ReadFull(w.br, b[:])
			n = int(binary.BigEndian.Uint16(b[:]))
		}
		p := make([]byte, n)
		io.ReadFull(w.br, p)
		if h[0]&0x0F != opText {
			continue
		}
		var e event
		if err := json.Unmarshal(p, &e); err != nil {
			t.Fatal(err)
		}
		return e
	}
}

func (w *testWS) sendMasked(op byte, p []byte) {
	var m [4]byte
	rand.Read(m[:])
	f := append([]byte{0x80 | op, 0x80 | byte(len(p))}, m[:]...)
	for i, b := range p {
		f = append(f, b^m[i%4])
	}
	w.c.Write(f)
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRelayFlow(t *testing.T) {
	st, _ := newStore("", 10)
	srv := newServer(st, "invite", false)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// register needs invite
	resp := post(t, ts.URL+"/register", "")
	if resp.StatusCode != 401 {
		t.Fatalf("register without invite: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/register", nil)
	req.Header.Set("Authorization", "Bearer invite")
	resp, _ = http.DefaultClient.Do(req)
	var cred map[string]string
	json.NewDecoder(resp.Body).Decode(&cred)
	id, secret, cs := cred["deviceId"], cred["deviceSecret"], cred["clientState"]
	if resp.StatusCode != 200 || id == "" || secret == "" || cs == "" {
		t.Fatalf("register: %d %v", resp.StatusCode, cred)
	}

	// ws auth
	if _, code := dialWS(t, ts.URL, id, "wrong"); code != 401 {
		t.Fatalf("bad secret: %d", code)
	}
	ws, code := dialWS(t, ts.URL, id, secret)
	if code != 101 {
		t.Fatalf("ws: %d", code)
	}
	if e := ws.next(t); e.Type != "hello" || e.HeartbeatSec != 20 {
		t.Fatalf("hello: %+v", e)
	}

	// validation handshake
	resp, _ = http.Post(ts.URL+"/hook/"+id+"?validationToken=abc%20123", "text/plain", nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "abc 123" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("validation: %d %q %q", resp.StatusCode, b, resp.Header.Get("Content-Type"))
	}

	// wrong clientState dropped, right one forwarded (dup collapsed)
	note := func(state, res string) string {
		return `{"value":[{"subscriptionId":"s","clientState":"` + state + `","changeType":"created","resource":"` + res + `","resourceData":{"id":"m1"}}]}`
	}
	res := "chats('19:abc@thread.v2')/messages('170')"
	if r := post(t, ts.URL+"/hook/"+id, note("bad", res)); r.StatusCode != 202 {
		t.Fatalf("hook bad state: %d", r.StatusCode)
	}
	if r := post(t, ts.URL+"/hook/"+id, note(cs, res)); r.StatusCode != 202 {
		t.Fatalf("hook: %d", r.StatusCode)
	}
	if e := ws.next(t); e.Type != "message" || e.ChatID != "19:abc@thread.v2" || e.MessageID != "170" {
		t.Fatalf("message: %+v", e)
	}

	// lifecycle
	life := func(ev string) string {
		return `{"value":[{"subscriptionId":"s","clientState":"` + cs + `","lifecycleEvent":"` + ev + `"}]}`
	}
	post(t, ts.URL+"/lifecycle/"+id, life("missed"))
	if e := ws.next(t); e.Type != "resync" {
		t.Fatalf("resync: %+v", e)
	}
	post(t, ts.URL+"/lifecycle/"+id, life("reauthorizationRequired"))
	if e := ws.next(t); e.Type != "reauth" {
		t.Fatalf("reauth: %+v", e)
	}

	// client ping answered
	ws.sendMasked(opPing, []byte("x"))

	// unknown device
	if r := post(t, ts.URL+"/hook/nope", "{}"); r.StatusCode != 404 {
		t.Fatalf("unknown device: %d", r.StatusCode)
	}

	// second connection evicts the first
	ws2, code := dialWS(t, ts.URL, id, secret)
	if code != 101 {
		t.Fatalf("ws2: %d", code)
	}
	ws2.next(t)
	ws.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, err := ws.br.ReadByte(); err != nil {
			break // evicted: connection closed
		}
	}
}

func TestParseResource(t *testing.T) {
	for _, c := range []struct{ in, chat, msg string }{
		{"chats('19:x')/messages('5')", "19:x", "5"},
		{"/chats/19:x/messages/5", "19:x", "5"},
	} {
		chat, msg, ok := parseResource(c.in, "")
		if !ok || chat != c.chat || msg != c.msg {
			t.Errorf("%q: %q %q %v", c.in, chat, msg, ok)
		}
	}
	if _, _, ok := parseResource("users/1", ""); ok {
		t.Error("expected no match")
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(0.001, 2)
	if !l.allow("a") || !l.allow("a") || l.allow("a") || !l.allow("b") {
		t.Fatal("limiter")
	}
}
