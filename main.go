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

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
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
)

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

func makeSSHConfig(host string) ssh.ServerConfig {
	config := ssh.ServerConfig{
		PasswordCallback:          authenticatePassword,
		PublicKeyCallback:         authenticateKey,
		ServerVersion:             "SSH-2.0-OpenSSH_5.3",
		MaxAuthenticationAttempts: 10,
	}

	//keyPath := viper.GetString("host_key")
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

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	viper.BindEnv("sshd_bind", "SSHD_BIND")
	viper.SetDefault("sshd_bind", ":22")

	viper.BindEnv("sshd_key_key", "SSHD_KEY_KEY")
	viper.SetDefault("sshd_key_key", "Take me to your leader")

	sshd_bind = viper.GetString("sshd_bind")
	sshd_key_key = viper.GetString("sshd_key_key")
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
		host := getHost(conn.LocalAddr().String())

		config, existed := sshConfigMap[host]
		if !existed {
			config = makeSSHConfig(host)
			sshConfigMap[host] = config
		}
		go handleConnection(conn, &config)
	}
}
