/*
Copyright (c) 2026 TheErrorExe, SkibidiCraft

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)
// Warum alles in eine Datei? 1. Weil ich es kann, 2. Weil der Code klein ist

type Config struct {
	Host          string
	Port          int
	ProtocolVer   int
	VersionName   string
	MOTD          string
	MaxPlayers    int
	OnlinePlayers int
	KickMessage   string
	IconFile      string
	LogFile       string
}

func parseYAML(path string) (Config, error) {
	cfg := Config{
		Host:        "0.0.0.0",
		Port:        25565,
		ProtocolVer: 767,
		VersionName: "1.21",
		MOTD:        "A Minecraft Server",
		KickMessage: "Server offline.",
		IconFile:    "server-icon.png",
		LogFile:     "access.log",
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		val = strings.ReplaceAll(val, `\n`, "\n")
		switch key {
		case "host":
			cfg.Host = val
		case "port":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.Port = n
			}
		case "protocol_version":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.ProtocolVer = n
			}
		case "version_name":
			cfg.VersionName = val
		case "motd":
			cfg.MOTD = val
		case "max_players":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.MaxPlayers = n
			}
		case "online_players":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.OnlinePlayers = n
			}
		case "kick_message":
			cfg.KickMessage = val
		case "icon_file":
			cfg.IconFile = val
		case "log_file":
			cfg.LogFile = val
		}
	}
	return cfg, scanner.Err()
}

var (
	cfg             Config
	serverPrivKey   *rsa.PrivateKey
	serverPubKeyDER []byte
	iconBase64      string
	debugMode       bool
	verboseMode     bool
	accessLog       *log.Logger
)

func logAccess(format string, args ...any) {
	if accessLog != nil {
		accessLog.Printf(format, args...)
	}
}
func logDebug(format string, args ...any) {
	if debugMode {
		log.Printf("[DEBUG] "+format, args...) // geile debug scheisse
	}
}
func logVerbose(format string, args ...any) {
	if verboseMode {
		log.Printf("[VERBOSE] "+format, args...)
	}
}


func readVarInt(r io.Reader) (int, error) {
	result, shift := 0, uint(0)
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		b := buf[0]
		result |= int(b&0x7F) << shift
		shift += 7
		if shift > 35 {
			return 0, fmt.Errorf("varint too long")
		}
		if b&0x80 == 0 {
			break
		}
	}
	return result, nil
}

func writeVarInt(v int) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

func readString(r io.Reader) (string, error) {
	l, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func writeString(s string) []byte {
	b := []byte(s)
	return append(writeVarInt(len(b)), b...)
}

func writePacket(id int, payload []byte) []byte {
	body := append(writeVarInt(id), payload...)
	return append(writeVarInt(len(body)), body...)
}

func readPacket(conn net.Conn) (int, []byte, error) {
	length, err := readVarInt(conn)
	if err != nil {
		return 0, nil, err
	}
	data := make([]byte, length)
	if _, err = io.ReadFull(conn, data); err != nil {
		return 0, nil, err
	}
	r := strings.NewReader(string(data))
	id, err := readVarInt(r)
	if err != nil {
		return 0, nil, err
	}
	idLen := len(writeVarInt(id))
	return id, data[idLen:], nil
}

func readHandshake(payload []byte) (int, error) {
	r := strings.NewReader(string(payload))
	if _, err := readVarInt(r); err != nil {
		return 0, err
	}
	if _, err := readString(r); err != nil {
		return 0, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return 0, err
	}
	_ = binary.BigEndian.Uint16(portBuf[:])
	return readVarInt(r)
}

func handleStatus(conn net.Conn) {
	status := map[string]any{
		"version":     map[string]any{"name": cfg.VersionName, "protocol": cfg.ProtocolVer},
		"players":     map[string]any{"max": cfg.MaxPlayers, "online": cfg.OnlinePlayers, "sample": []any{}},
		"description": map[string]any{"text": cfg.MOTD},
	}
	if iconBase64 != "" {
		status["favicon"] = "data:image/png;base64," + iconBase64 // minecraft will base64 :sob:
	}
	j, _ := json.Marshal(status)
	conn.Write(writePacket(0x00, writeString(string(j))))
}

func sendDisconnect(conn net.Conn, msg string) {
	j, _ := json.Marshal(map[string]string{"text": msg})
	conn.Write(writePacket(0x00, writeString(string(j))))
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	addr := conn.RemoteAddr().String()

	id, payload, err := readPacket(conn)
	if err != nil || id != 0x00 {
		return
	}
	nextState, err := readHandshake(payload)
	if err != nil {
		return
	}

	switch nextState {
	case 1:
		id2, _, err := readPacket(conn)
		if err != nil || id2 != 0x00 {
			return
		}
		logVerbose("Status ping von %s", addr) // debugging und so
		handleStatus(conn)
		id3, pingPayload, err := readPacket(conn)
		if err == nil && id3 == 0x01 {
			conn.Write(writePacket(0x01, pingPayload))
		}

	case 2:
		id2, loginPayload, err := readPacket(conn)
		if err != nil || id2 != 0x00 {
			return
		}
		r := strings.NewReader(string(loginPayload))
		username, err := readString(r)
		if err != nil {
			return
		}
		logAccess("Loginversuch | %s | %s", addr, username)
		logDebug("%s (%s) wird gekickt", username, addr)
		sendDisconnect(conn, cfg.KickMessage)
	}
}

func main() {
	cfgFile := "config.yml"
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--debug":
			debugMode = true
		case "--verbose":
			verboseMode = true
			debugMode = true
		case "--config":
			if i+2 <= len(os.Args[1:]) {
				cfgFile = os.Args[i+2]
			}
		}
	}

	var err error
	cfg, err = parseYAML(cfgFile)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	if debugMode {
		accessLog = log.New(os.Stdout, "[ACCESS] ", log.LstdFlags)
	} else {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Cannot open log file %q: %v", cfg.LogFile, err)
		}
		accessLog = log.New(f, "", log.LstdFlags)
	}

	if cfg.IconFile != "" {
		if iconData, err := os.ReadFile(cfg.IconFile); err == nil {
			iconBase64 = base64.StdEncoding.EncodeToString(iconData)
			logDebug("Loaded icon %s (%d bytes)", cfg.IconFile, len(iconData))
		} else {
			logDebug("Icon not loaded: %v", err)
		}
	}

	serverPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("RSA keygen: %v", err)
	}
	serverPubKeyDER, err = x509.MarshalPKIXPublicKey(&serverPrivKey.PublicKey)
	if err != nil {
		log.Fatalf("RSA marshal: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	log.Printf("Listening on %s | config: %s | debug=%v verbose=%v", addr, cfgFile, debugMode, verboseMode)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logDebug("Accept error: %v", err)
			continue
		}
		go handleClient(conn)
	}
}
