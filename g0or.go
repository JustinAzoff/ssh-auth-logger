package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

const appName = "go0r"

var errAuthenticationFailed = errors.New(":)")

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
	logrus.WithFields(logParameters(conn)).WithFields(
		logrus.Fields{"password": string(password)}).Info(fmt.Sprintf("Request with password"))
	return nil, errAuthenticationFailed
}

func authenticateKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	logrus.WithFields(logParameters(conn)).WithFields(
		logrus.Fields{"keytype": key.Type(), "fingerprint": ssh.FingerprintSHA256(key)}).Info(fmt.Sprintf("Request with key"))
	return nil, errAuthenticationFailed
}

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	usr, err := user.Current()
	if err != nil {
		logrus.Warn(err)
	}
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logrus.Warn(err)
	}

	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/" + appName)
	viper.AddConfigPath(usr.HomeDir + "/" + appName)
	viper.AddConfigPath(dir + "/configs/")

	viper.BindEnv("port", "GOOR_PORT")
	viper.SetDefault("port", ":22")

	viper.BindEnv("host_key", "GOOR_HOST_KEY")
	viper.SetDefault("host_key", "./host_key")
}

func main() {
	config := ssh.ServerConfig{
		PasswordCallback:  authenticatePassword,
		PublicKeyCallback: authenticateKey,
		ServerVersion:     "SSH-2.0-OpenSSH_5.3",
	}

	keyPath := viper.GetString("host_key")
	hostPrivateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		logrus.Panic(err)
	}
	hostPrivateKeySigner, err := ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		logrus.Panic(err)
	}
	config.AddHostKey(hostPrivateKeySigner)
	socket, err := net.Listen("tcp", viper.GetString("port"))
	if err != nil {
		panic(err)
	}
	for {
		conn, err := socket.Accept()
		if err != nil {
			logrus.Panic(err)
		}
		_, _, _, err = ssh.NewServerConn(conn, &config)
		if err == nil {
			logrus.Panic("Successful login? why!?")
		}
	}
}
