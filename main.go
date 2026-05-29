package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
	"strings"
	"encoding/base64"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const appName = "ssh-auth-logger"

var version string

var telnetBind string

var telnetLogClearPassword bool

var telnetRate int

var errAuthenticationFailed = errors.New(":)")

var commonFields = logrus.Fields{
	"destinationServicename": "sshd",
	"product":                appName,
}
var logger = logrus.WithFields(commonFields)
var allowedLogFields map[string]bool

var (
	sshd_bind    string
	sshd_key_key string
	rate         int
	maxAuthTries int
	rsaBits      int    // only used if hostKeyType == "rsa"
	profileScope string // "host" or "remote_ip"
	sendBanner   bool
	logClearPassword bool
)

// rateLimitedConn is a wrapper around net.Conn that limits the bandwidth.
type rateLimitedConn struct {
	net.Conn
	rate       int // bytes per second
	bufferSize int // buffer size for token bucket algorithm
	tokens     int // current tokens
	lastUpdate time.Time
}

// Currently state is not shared between connections
// multiple attackers can "reset” delays by opening new connections
type authState struct {
	attempts int
}

// Create profile to match banner and Server Version
type serverProfile struct {
	ServerVersion string
	LoginBanner   string
	HostKeyType   string // "rsa" or "ed25519"
    Kex           []string
    Ciphers       []string
    Macs          []string
}

// Telnet handler
func handleTelnetConnection(conn net.Conn) {
	defer conn.Close()

	logger.WithFields(connLogParameters(conn)).
		WithField("destinationServicename", "telnetd").
		Info("Telnet connection")

	limitedConn := newRateLimitedConn(conn, telnetRate)


	// Determine profile key (same logic as SSH)
	var profileKey string
	if profileScope == "remote_ip" {
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			host = conn.RemoteAddr().String()
		}
		profileKey = host
	} else {
		profileKey = getHost(conn.LocalAddr().String())
	}

	profile := getServerProfile(profileKey)

	// Start from SSH login banner
	banner := profile.LoginBanner

	// Replace protocol-specific words for Telnet realism
	banner = strings.ReplaceAll(banner, "SSH", "Telnet")
	banner = strings.ReplaceAll(banner, "ssh", "telnet")

	// Convert LF to CRLF for telnet
	banner = strings.ReplaceAll(banner, "\n", "\r\n")

	if banner != "" {
		limitedConn.Write([]byte(banner))
	}

	limitedConn.Write([]byte("login: "))

	username, _ := readLine(limitedConn)

	limitedConn.Write([]byte("Password: "))
	password, _ := readLine(limitedConn)

	// This will show the password in cleartext if telnetLogClearPassword is true, otherwise it will log the base64 encoded if telnetLogClearPassword is false
	var loggedPassword any
	if telnetLogClearPassword {
		loggedPassword = string(password)
	} else {
		loggedPassword = base64.StdEncoding.EncodeToString([]byte(password))
	}

	fields := connLogParameters(conn)
	fields["duser"] = username
	fields["password"] = loggedPassword
	fields["protocol"] = "telnet"

	logger.WithFields(fields).
		WithField("destinationServicename", "telnetd").
		Info("Telnet login attempt")

	time.Sleep(2 * time.Second)
	limitedConn.Write([]byte("\r\nLogin incorrect\r\n"))
}

// Simple Telnet Parser
func readLine(conn net.Conn) (string, error) {
	buf := make([]byte, 1)
	var result []byte

	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return "", err
		}

		b := buf[0]

		// TELNET IAC handling (skip command sequences)
		if b == 255 { // IAC
			// read next two bytes (command + option)
			conn.Read(buf)
			conn.Read(buf)
			continue
		}

		// Ignore CR
		if buf[0] == '\r' {
			continue
		}

		// End on LF
		if buf[0] == '\n' {
			break
		}

		result = append(result, buf[0])
	}

	return strings.TrimSpace(string(result)), nil
}

// newRateLimitedConn returns a new rateLimitedConn.
func newRateLimitedConn(conn net.Conn, rate int) *rateLimitedConn {
	return &rateLimitedConn{
		Conn:       conn,
		rate:       rate,
		bufferSize: rate * 2, // Allow for bursts up to twice the rate
		tokens:     rate,
		lastUpdate: time.Now(),
	}
}

// Read implements the Read method of net.Conn.
func (r *rateLimitedConn) Read(p []byte) (n int, err error) {
	n, err = r.Conn.Read(p)
	if err != nil {
		return
	}

	// Limit the read based on the rate.
	r.limit(n)
	return
}

// Write implements the Write method of net.Conn.
func (r *rateLimitedConn) Write(p []byte) (n int, err error) {
	n, err = r.limitWrite(p)
	return
}

func (r *rateLimitedConn) limitWrite(p []byte) (int, error) {
	var totalWritten int
	for len(p) > 0 {
		// Calculate available tokens.
		now := time.Now()
		elapsed := now.Sub(r.lastUpdate).Seconds()
		r.tokens += int(elapsed * float64(r.rate))
		if r.tokens > r.bufferSize {
			r.tokens = r.bufferSize
		}
		r.lastUpdate = now

		// Determine how many bytes we can write.
		availableTokens := r.tokens
		if availableTokens > len(p) {
			availableTokens = len(p)
		}

		// Write data.
		n, err := r.Conn.Write(p[:availableTokens])
		totalWritten += n
		r.tokens -= n
		if err != nil {
			return totalWritten, err
		}

		// Adjust the buffer.
		p = p[n:]

		// If there are still bytes to write, sleep to accumulate tokens.
		if len(p) > 0 {
			time.Sleep(time.Duration(availableTokens) * time.Second / time.Duration(r.rate))
		}
	}
	return totalWritten, nil
}

func (r *rateLimitedConn) limit(n int) {
	// Simple sleep-based rate limiting for read.
	time.Sleep(time.Duration(n) * time.Second / time.Duration(r.rate))
}

func connLogParameters(conn net.Conn) logrus.Fields {
	src, spt, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dst, dpt, _ := net.SplitHostPort(conn.LocalAddr().String())

	return logrus.Fields{
		"src": src,
		"spt": spt,
		"dst": dst,
		"dpt": dpt,
	}
}

func logParameters(conn ssh.ConnMetadata) logrus.Fields {

	src, spt, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dst, dpt, _ := net.SplitHostPort(conn.LocalAddr().String())

	return logrus.Fields{
		"duser": conn.User(),
		//"session_id":          string(conn.SessionID()),
		"src":            src,
		"spt":            spt,
		"dst":            dst,
		"dpt":            dpt,
		"client_version": string(conn.ClientVersion()),
		"server_version": string(conn.ServerVersion()),
	}
}

func HashToInt64(message, key []byte) int64 {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	hash := mac.Sum(nil)
	i := binary.LittleEndian.Uint64(hash[:8])
	return int64(i)
}

func getHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		logrus.Fatal(err)
	}
	return host
}

func getHostKeySigner(host, keyType string) (ssh.Signer, error) {
	seed := HashToInt64([]byte(host+":"+keyType), []byte(sshd_key_key))
	// Fine for honeypot — no security issue. Do not use for real keys.
	rng := rand.New(rand.NewSource(seed))

	switch keyType {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rng)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(priv)

	case "rsa":
		key, err := rsa.GenerateKey(rng, rsaBits)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(key)

	default:
		return nil, errors.New("unsupported host key type")
	}
}

var serverProfiles = []serverProfile{
	{
		ServerVersion: "SSH-2.0-OpenSSH_7.4",
		LoginBanner:   "CentOS Linux 7 (Core)\n\nAll connections are monitored.\n",
		HostKeyType:   "rsa",

		Kex: []string{
			"curve25519-sha256@libssh.org",
			"curve25519-sha256",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		},

		Ciphers: []string{
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
			"aes128-gcm@openssh.com",
			"aes256-gcm@openssh.com",
			"chacha20-poly1305@openssh.com",
		},

		Macs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha2-512",
		},
	},

	{
		ServerVersion: "SSH-2.0-OpenSSH_7.9p1 Debian-10",
		LoginBanner:   "Debian GNU/Linux 10\n\nAuthorized users only.\n",
		HostKeyType:   "rsa",

		Kex: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group14-sha256",
		},

		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
		},

		Macs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha2-512",
		},
	},

	{
		ServerVersion: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
		LoginBanner:   "Ubuntu 20.04.6 LTS\n\nUnauthorized access prohibited.\n",
		HostKeyType:   "ed25519",

		Kex: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group14-sha256",
		},

		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
		},

		Macs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha2-512",
		},
	},

	{
		ServerVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14",
		LoginBanner:   "Ubuntu 24.04.1 LTS\n\nUnauthorized access prohibited.\n",
		HostKeyType:   "ed25519",

		Kex: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"diffie-hellman-group16-sha512",
		},

		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes128-ctr",
		},

		Macs: []string{
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256-etm@openssh.com",
		},
	},

	{
		ServerVersion: "SSH-2.0-OpenSSH_8.4",
		LoginBanner:   "Debian GNU/Linux 11\n\nAuthorized users only.\n",
		HostKeyType:   "ed25519",

		Kex: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group14-sha256",
		},

		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-ctr",
			"aes256-ctr",
		},

		Macs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha2-512",
		},
	},

	{
		ServerVersion: "SSH-2.0-dropbear_2019.78",
		LoginBanner:   "Welcome to Dropbear SSH Server\n\nUnauthorized access is prohibited.\n",
		HostKeyType:   "rsa",

		Kex: []string{
			"curve25519-sha256",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		},

		Ciphers: []string{
			"aes128-ctr",
			"aes256-ctr",
			"aes128-cbc",
			"3des-cbc",
		},

		Macs: []string{
			"hmac-sha2-256",
			"hmac-sha1",
		},
	},
}

func getServerProfile(host string) serverProfile {
	seed := HashToInt64([]byte("profile:"+host), []byte(sshd_key_key))
	if seed < 0 {
		seed = -seed
	}
	return serverProfiles[int(seed)%len(serverProfiles)]
}

func makeSSHConfig(conn net.Conn) ssh.ServerConfig {
	state := &authState{}
	// per‑local host profile
//	profile := getServerProfile(host)
	// per‑IP profile
//	profile := getServerProfile(conn.RemoteAddr().String())

	var actualHostKeyType string
	// Determine the key for profile lookup
	var profileKey string
	if profileScope == "remote_ip" {
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			host = conn.RemoteAddr().String() // fallback, should not happen
		}
		profileKey = host
	} else { // default "host"
		profileKey = getHost(conn.LocalAddr().String())
	}

	profile := getServerProfile(profileKey)
	
	config := ssh.ServerConfig{
		NoClientAuth: false,

		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			state.attempts++

			base := time.Duration(200*state.attempts) * time.Millisecond
			jitter := time.Duration(rand.Intn(700)) * time.Millisecond
			time.Sleep(base + jitter)

			var loggedPassword any = password
			// This will convert bytes to string if logClearPassword is true, otherwise it will log the byte slice (which will be base64 encoded if LogClearPassword is false)
			if logClearPassword {
				loggedPassword = string(password)
			}

			logger.WithFields(logParameters(conn)).
				WithFields(logrus.Fields{
					"password":        loggedPassword,
					"server_key_type": actualHostKeyType,
				}).Info("Request with password")

			return nil, errAuthenticationFailed
		},

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			state.attempts++

			base := time.Duration(200*state.attempts) * time.Millisecond
			jitter := time.Duration(rand.Intn(400)) * time.Millisecond
			time.Sleep(base + jitter)

			logger.WithFields(logParameters(conn)).
				WithFields(logrus.Fields{
					"keytype": key.Type(),
					"fingerprint": ssh.FingerprintSHA256(key),
					"server_key_type": actualHostKeyType,
				}).Info("Request with key")

			return nil, errAuthenticationFailed
		},

		ServerVersion: profile.ServerVersion,
		MaxAuthTries:  maxAuthTries + rand.Intn(5),
		Config: ssh.Config{
			KeyExchanges: profile.Kex,
			Ciphers:      profile.Ciphers,
			MACs:         profile.Macs,
		},
	}

	// 🔐 Banner only if enabled
	if sendBanner {
		config.BannerCallback = func(conn ssh.ConnMetadata) string {
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			return profile.LoginBanner
		}
	}

	// Generate host keys with OpenSSH-like ordering
	var signers []ssh.Signer

	// Generate primary host key signer
	primarySigner, err := getHostKeySigner(profileKey, profile.HostKeyType)
	if err != nil {
		logrus.Panic(err)
	}

	primaryType := primarySigner.PublicKey().Type()

	// ED25519 first if available
	if primaryType == "ssh-ed25519" {
		signers = append(signers, primarySigner)

		if rsaSigner, err := getHostKeySigner(profileKey, "rsa"); err == nil {
			signers = append(signers, rsaSigner)
		}
	} else {
		// RSA primary
		signers = append(signers, primarySigner)

		if edSigner, err := getHostKeySigner(profileKey, "ed25519"); err == nil {
			signers = append(signers, edSigner)
		}
	}

	// Add keys to config in correct order
	for _, s := range signers {
		config.AddHostKey(s)
	}

	// capture primary type for logging
	actualHostKeyType = primaryType

	return config
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {

	// Random early disconnect (~10%)
	if rand.Intn(10) == 0 {
		logger.WithFields(connLogParameters(conn)).
			Info("Connection dropped (simulated network issue)")
		conn.Close()
		return
	}

	// Simulate OpenSSH banner timing
	time.Sleep(time.Duration(20+rand.Intn(120)) * time.Millisecond)

	_, _, _, err := ssh.NewServerConn(conn, config)
	if err == nil {
		// This should never happen because auth never succeeds
		logrus.Panic("Successful login? why!?")
	}
	if err != nil {
		// Auth failed or client closed connection — expected behavior
		return
	}
}

//getEnvWithDefault returns the environment value for key
//returning fallback instead if it is missing or blank
func getEnvWithDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

// parseAllowedFields parses a comma-separated list of allowed fields
func parseAllowedFields(env string) map[string]bool {
	fields := make(map[string]bool)
	for _, f := range strings.Split(env, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			fields[f] = true
		}
	}
	return fields
}

type FilteredJSONFormatter struct {
	Allowed map[string]bool
	Base    *logrus.JSONFormatter
}

// Format filters the log entry to include only allowed fields
func (f *FilteredJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Avoid null pointer if Base is not set
	base := f.Base
	if base == nil {
		base = &logrus.JSONFormatter{}
	}

	filtered := logrus.Fields{}

	// Filter ONLY structured fields
	for k, v := range entry.Data {
		if f.Allowed[k] {
			filtered[k] = v
		}
	}

	// Clone entry safely
	newEntry := *entry
	newEntry.Data = filtered

	return f.Base.Format(&newEntry)
}

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	version = getEnvWithDefault("VERSION", "dev")

	telnetBind = getEnvWithDefault("TELNET_BIND", ":23")

	sshd_bind = getEnvWithDefault("SSHD_BIND", ":22")
	sshd_key_key = getEnvWithDefault("SSHD_KEY_KEY", "Take me to your leader")
	rateStr := getEnvWithDefault("SSHD_RATE", "320") // default rate is 320 bytes per second very slow...
	var err error
	rate, err = strconv.Atoi(rateStr)
	if err != nil {
		logrus.Fatal("Invalid SSHD_RATE environment variable")
	}
	telnetRateStr := getEnvWithDefault("TELNET_RATE", "20") // Could be slower than SSH
	telnetRate, err = strconv.Atoi(telnetRateStr)
	if err != nil || telnetRate <= 0 {
		logrus.Fatal("Invalid TELNET_RATE environment variable")
	}
	maxAuthTriesStr := getEnvWithDefault("SSHD_MAX_AUTH_TRIES", "6") // default amount of tries is 6-10.
	maxAuthTries, err = strconv.Atoi(maxAuthTriesStr)
	if err != nil {
		logrus.Fatal("Invalid SSHD_MAX_AUTH_TRIES environment variable")
	}
	rsaBitsStr := getEnvWithDefault("SSHD_RSA_BITS", "3072")
	rsaBits, err = strconv.Atoi(rsaBitsStr)
	if err != nil || rsaBits < 2048 {
		logrus.Fatal("Invalid SSHD_RSA_BITS (must be >= 2048)")
	}
	profileScope = getEnvWithDefault("SSHD_PROFILE_SCOPE", "host")
	// Seed for non-deterministic uses to avoid identical timing patterns across restarts
	// Fine for delays and banner selection — no security issue.
	rand.Seed(time.Now().UnixNano())
	// Banner sending option
	sendBannerStr := getEnvWithDefault("SSHD_SEND_BANNER", "false")
	sendBanner = sendBannerStr == "1" || sendBannerStr == "true" || sendBannerStr == "yes"
	logClearPasswordStr := getEnvWithDefault("SSHD_LOG_CLEAR_PASSWORD", "true")
	logClearPassword = logClearPasswordStr == "1" || logClearPasswordStr == "true" || logClearPasswordStr == "yes"
	telnetLogClearPasswordStr := getEnvWithDefault("TELNET_LOG_CLEAR_PASSWORD", "true")
	telnetLogClearPassword = telnetLogClearPasswordStr == "1" || telnetLogClearPasswordStr == "true" || telnetLogClearPasswordStr == "yes"
	// Comma-separated list of allowed fields, "" means all, " " means none
	logsEnv := getEnvWithDefault("SSHD_LOGS_FILTER", "")

	// Show Configuration on Startup
	logrus.WithFields(logrus.Fields{
		"Version":                   version,
		"SSHD_BIND":                 sshd_bind,
		"SSHD_KEY_KEY":              sshd_key_key,
		"SSHD_RATE":                 rate,
		"SSHD_MAX_AUTH_TRIES":       maxAuthTries,
		"SSHD_RSA_BITS":             rsaBitsStr,
		"SSHD_PROFILE_SCOPE":        profileScope,
		"SSHD_SEND_BANNER":          sendBanner,
		"SSHD_LOG_CLEAR_PASSWORD":   logClearPassword,
		"SSHD_LOGS_FILTER":	         logsEnv,
		"TELNET_BIND":               telnetBind,
		"TELNET_LOG_CLEAR_PASSWORD": telnetLogClearPassword,
		"TELNET_RATE":               telnetRate,
	}).Info("Starting SSH Auth Logger")

	// Configure allowed log fields from environment variable
	if logsEnv != "" {
		allowedLogFields = parseAllowedFields(logsEnv)
		logrus.SetFormatter(&FilteredJSONFormatter{
			Allowed: allowedLogFields,
			Base: &logrus.JSONFormatter{
				TimestampFormat: time.RFC3339Nano,
			},
		})
	}

	logsEnv, isSet := os.LookupEnv("SSHD_LOGS_FILTER")
	if isSet {
		allowedLogFields = parseAllowedFields(logsEnv)
		if len(allowedLogFields) == 0 {
			logrus.Warn("SSHD_LOGS_FILTER is set but empty; no structured fields will be logged")
		}
	}
}

func main() {
	// SSH listener
	go func() {
		socket, err := net.Listen("tcp", sshd_bind)
		if err != nil {
			panic(err)
		}
		// logrus.Infof("SSH listening on %s", sshd_bind)
		for {
			conn, err := socket.Accept()
			if err != nil {
				logrus.WithError(err).Warn("SSH listener accept failed")
				continue
			}

			logger.WithFields(connLogParameters(conn)).Info("SSH connection")

			limitedConn := newRateLimitedConn(conn, rate)
			config := makeSSHConfig(conn)
			go handleConnection(limitedConn, &config)
		}
	}()

	// Telnet listener
	go func() {
		telnetSocket, err := net.Listen("tcp", telnetBind)
		if err != nil {
			panic(err)
		}
		// logrus.Infof("Telnet listening on %s", telnetBind)
		for {
			conn, err := telnetSocket.Accept()
			if err != nil {
				logrus.WithError(err).Warn("Telnet listener accept failed")
				continue
			}
			go handleTelnetConnection(conn)
		}
	}()

	// Block forever
	select {}
}