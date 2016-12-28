package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

const appName = "go0r"

var errAuthenticationFailed = errors.New(":)")

var commonFields = logrus.Fields{
	"destinationServicename": "sshd",
	"product":                "ssh-auth-logger",
}
var logger = logrus.WithFields(commonFields)

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

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	viper.BindEnv("port", "GOOR_PORT")
	viper.SetDefault("port", ":22")

	viper.BindEnv("host_key", "GOOR_HOST_KEY")
	viper.SetDefault("host_key", "./host_key")

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
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return key, err
	}
	//keyBytes := x509.MarshalPKCS1PrivateKey(key)
	//TODO: Save and restore keyBytes somewhere persistently
	return key, err
}

func makeSSHConfig(host string) ssh.ServerConfig {
	config := ssh.ServerConfig{
		PasswordCallback:  authenticatePassword,
		PublicKeyCallback: authenticateKey,
		ServerVersion:     "SSH-2.0-OpenSSH_5.3",
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

func main() {
	sshConfigMap := make(map[string]ssh.ServerConfig)
	socket, err := net.Listen("tcp", viper.GetString("port"))
	if err != nil {
		panic(err)
	}
	for {
		conn, err := socket.Accept()
		if err != nil {
			logrus.Panic(err)
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
