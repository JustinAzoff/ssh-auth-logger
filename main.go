package main

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
	"strconv"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const appName = "ssh-auth-logger"

var errAuthenticationFailed = errors.New(":)")

var commonFields = logrus.Fields{
	"destinationServicename": "sshd",
	"product":                appName,
}
var logger = logrus.WithFields(commonFields)

var (
	sshd_bind    string
	sshd_key_key string
	rate         int
)

// rateLimitedConn is a wrapper around net.Conn that limits the bandwidth.
type rateLimitedConn struct {
	net.Conn
	rate       int // bytes per second
	bufferSize int // buffer size for token bucket algorithm
	tokens     int // current tokens
	lastUpdate time.Time
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

func authenticatePassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	fields := logrus.Fields{
		"password": string(password),
	}
	logger.WithFields(logParameters(conn)).WithFields(fields).Info("Request with password")
	return nil, errAuthenticationFailed
}

func authenticateKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fields := logrus.Fields{
		"keytype":     key.Type(),
		"fingerprint": ssh.FingerprintSHA256(key),
	}
	logger.WithFields(logParameters(conn)).WithFields(fields).Info("Request with key")
	return nil, errAuthenticationFailed
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

func getKey(host string) (*rsa.PrivateKey, error) {
	logrus.WithFields(logrus.Fields{"addr": host}).Debug("Generating host key")

	randomSeed := HashToInt64([]byte(host), []byte(sshd_key_key))
	randomSource := rand.New(rand.NewSource(randomSeed))

	key, err := rsa.GenerateKey(randomSource, 1024)
	if err != nil {
		return key, err
	}
	return key, err
}

var serverVersions = []string{
	"SSH-2.0-libssh-0.6.1",
}

func getServerVersion(host string) string {
	randomSeed := HashToInt64([]byte(host), []byte(sshd_key_key))
	if randomSeed < 0 {
		randomSeed = -randomSeed
	}
	n := int(randomSeed) % len(serverVersions)
	return serverVersions[n]
}

func makeSSHConfig(host string) ssh.ServerConfig {
	config := ssh.ServerConfig{
		PasswordCallback:  authenticatePassword,
		PublicKeyCallback: authenticateKey,
		ServerVersion:     getServerVersion(host),
		MaxAuthTries:      3,
	}

	privateKey, err := getKey(host)
	if err != nil {
		logrus.Panic(err)
	}
	hostPrivateKeySigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		logrus.Panic(err)
	}
	config.AddHostKey(hostPrivateKeySigner)
	return config
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	_, _, _, err := ssh.NewServerConn(conn, config)
	if err == nil {
		logrus.Panic("Successful login? why!?")
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

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	sshd_bind = getEnvWithDefault("SSHD_BIND", ":22")
	sshd_key_key = getEnvWithDefault("SSHD_KEY_KEY", "Take me to your leader")
	rateStr := getEnvWithDefault("SSHD_RATE", "120") // default rate is 120 bytes per second very slow...
	var err error
	rate, err = strconv.Atoi(rateStr)
	if err != nil {
		logrus.Fatal("Invalid RATE environment variable")
	}

	// Show Configuration on Startup
	logrus.WithFields(logrus.Fields{
		"SSHD_BIND":    sshd_bind,
		"SSHD_KEY_KEY": sshd_key_key,
		"SSHD_RATE":    rate,
	}).Info("Starting SSH Auth Logger")
}

func main() {
	sshConfigMap := make(map[string]ssh.ServerConfig)
	socket, err := net.Listen("tcp", sshd_bind)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Panic(err)
		}
		logger.WithFields(connLogParameters(conn)).Info("Connection")

		limitedConn := newRateLimitedConn(conn, rate)

		host := getHost(conn.LocalAddr().String())
		config, existed := sshConfigMap[host]
		if !existed {
			config = makeSSHConfig(host)
			sshConfigMap[host] = config
		}
		go handleConnection(limitedConn, &config)
	}
}