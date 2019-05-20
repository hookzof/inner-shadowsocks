package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/ihciah/go-shadowsocks2/core"
)

const (
	channelBufferSize    = 128
	defaultMaxfail       = 10
	defaultRecovertime   = 600
	defaultListen        = "0.0.0.0"
	defaultStartTimeout  = 8
	defaultRemoteTimeout = 60
	defaultInsideTimeout = 60
)

type Server struct {
	server string
	ciph   core.Cipher
	addr   string
}

type Config struct {
	listenAddr net.TCPAddr
	servers    []Server
	auth       bool
	username   []byte
	password   []byte
	scheduler  Scheduler
	verbose    bool
	rtimeout   time.Duration
	itimeout   time.Duration
	stimeout   time.Duration
	whitelist  Whitelist
}

type userConfig struct {
	Listen           string   `json:"listen"`
	Port             int      `json:"port"`
	Auth             bool     `json:"auth"`
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	Servers          []string `json:"servers"`
	Maxfail          int      `json:"maxfail"`
	Recovertime      int      `json:"recovertime"`
	Starttimeout     int      `json:"starttimeout"`
	Remotetimeout    int      `json:"remotetimeout"`
	Insidetimeout    int      `json:"insidetimeout"`
	Whitelistenable  bool     `json:"whitelistenable"`
	Whitelistdomains []string `json:"whitelistdomains"`
	Whitelistips     []string `json:"whitelistips"`
}

type timeoutConn struct {
	net.Conn
	timelimit time.Duration
	starttime time.Duration
	active    bool
}

func (uc *userConfig) loadServers() []Server {
	servers := make([]Server, 0, len(uc.Servers))
	for _, st := range uc.Servers {
		s, err := makeServer(st)
		if err != nil {
			continue
		}
		servers = append(servers, s)
	}
	return servers
}

func (uc *userConfig) loadWhitelist() (w Whitelist) {
	domains := make([]string, 0, len(uc.Whitelistdomains))
	ips := make([]net.IPNet, 0, len(uc.Whitelistips))
	if !uc.Whitelistenable {
		return
	}
	for _, domain := range uc.Whitelistdomains {
		domains = append(domains, domain)
	}
	for _, ip := range uc.Whitelistips {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			continue
		}
		ips = append(ips, *ipnet)
	}
	return Whitelist{enable: uc.Whitelistenable, domainlist: domains, iplist: ips}
}

func (config *Config) log(f string, v ...interface{}) {
	if config.verbose {
		log.Printf(f, v...)
	}
}

func (tc timeoutConn) heartbeat() {
	if tc.active {
		_ = tc.Conn.SetDeadline(time.Now().Add(tc.timelimit))
	} else {
		_ = tc.Conn.SetDeadline(time.Now().Add(tc.starttime))
		tc.active = true
	}
}
func (tc timeoutConn) Read(buf []byte) (int, error) {
	tc.heartbeat()
	return tc.Conn.Read(buf)
}

func (tc timeoutConn) Write(buf []byte) (int, error) {
	tc.heartbeat()
	return tc.Conn.Write(buf)
}

func (config *Config) StartServer() {
	listener, err := net.ListenTCP("tcp", &config.listenAddr)
	defer listener.Close()
	if err != nil {
		panic("[inner-ss] Cannot listen on given ip and port!")
	}
	config.log("[inner-ss] Auth: %t, WhiteList: %t, RemoteTimeout: %d sec, InsideTimeout: %d sec.",
		config.auth, config.whitelist.enable, config.rtimeout/time.Second, config.itimeout/time.Second)
	config.log("[inner-ss] Listening %s on port %d.", config.listenAddr.IP, config.listenAddr.Port)
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			config.log("[inner-ss] Failed to accept %s", err)
			continue
		}
		config.log("[inner-ss] Accept connection from %s", conn.RemoteAddr())
		go config.handleConnection(conn)
	}
}

func bytein(y []byte, x byte) bool {
	for _, b := range y {
		if b == x {
			return true
		}
	}
	return false
}

func (config *Config) handleConnection(conn *net.TCPConn) error {
	defer conn.Close()
	_ = conn.SetKeepAlive(true)
	if err := config.handleSocksEncrypt(conn); err != nil {
		config.log("[inner-ss] Error when validating user. %s", err)
		return err
	}
	addr, err := getAddr(conn)
	if err != nil {
		config.log("[inner-ss] Error when getAddr. %s", err)
		return err
	}
	if err := config.whitelist.check(addr); err != nil {
		config.log("[inner-ss] Error when checking ip or domain. %s", err)
		return err
	}
	serverId := config.scheduler.get()
	server, ciph := config.servers[serverId].addr, config.servers[serverId].ciph
	rc, err := net.Dial("tcp", server)
	if err != nil {
		config.log("[inner-ss] Cannot connect to shadowsocks server %s\n", server)
		config.scheduler.reportFail(serverId)
		return err
	}
	config.scheduler.reportSuccess(serverId)
	defer rc.Close()
	_ = rc.(*net.TCPConn).SetKeepAlive(true)
	rc = ciph.StreamConn(rc)
	if _, err := rc.Write(addr); err != nil {
		return err
	}
	_, _, rerr, err := relay(rc, conn, config.rtimeout, config.itimeout, config.stimeout)
	if rerr != nil {
		config.log("[inner-ss] Remote connection error. %s", rerr)
		return rerr
	}
	return err
}

func (config *Config) handleSocksEncrypt(conn *net.TCPConn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	methods := buf[2:n]
	auth := byte(0x00)
	if config.auth {
		auth = 0x02
	}
	if buf[0] != 0x05 || !bytein(methods, auth) {
		return errors.New("Not Socks5 or auth type incorrect.")
	}
	_, _ = conn.Write([]byte{0x05, auth})
	if config.auth {
		n, err = conn.Read(buf)
		if err != nil {
			return err
		}
		if n < 3 || n < int(buf[1])+3 {
			return errors.New("Data not correct.")
		}
		usernameLen := int(buf[1])
		username := buf[2 : 2+usernameLen]
		password := buf[3+usernameLen : n]
		if bytes.Equal(username, config.username) && bytes.Equal(password, config.password) {
			_, _ = conn.Write([]byte{0x01, 0x00})
			return nil
		}
		return errors.New("Invalid username or password.")
	}
	return nil
}

func getAddr(conn *net.TCPConn) ([]byte, error) {
	buf := make([]byte, 259)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 7 {
		return nil, errors.New("Invalid packet.")
	}
	var dstAddr []byte
	switch buf[3] {
	case 0x01:
		if n < 6+net.IPv4len {
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3 : 6+net.IPv4len]
	case 0x03:
		if n < 8 || n < 6+int(buf[4]) {
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3 : 7+int(buf[4])]
	case 0x04:
		if n < 6+net.IPv6len {
			return nil, errors.New("Invalid packet.")
		}
		dstAddr = buf[3 : 6+net.IPv6len]
	default:
		return nil, errors.New("Invalid packet.")
	}

	switch buf[1] {
	case 0x01:
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10})
	default:
		_, _ = conn.Write([]byte{0x05, 0x07})
		return nil, errors.New("Unsupported command.")
	}
	return dstAddr, nil
}

func relay(left, right net.Conn, rtimeout, itimeout, stimeout time.Duration) (int64, int64, error, error) {
	tleft := timeoutConn{Conn: left, timelimit: rtimeout, starttime: stimeout}
	tright := timeoutConn{Conn: right, timelimit: itimeout, starttime: stimeout}
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(tright, tleft)
		ch <- res{n, err}
	}()
	n, err := io.Copy(tleft, tright)
	rs := <-ch
	return n, rs.N, err, rs.Err
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func LoadUserConfig(configFile string, verbose bool) (Config, error) {
	userConfig := userConfig{Maxfail: defaultMaxfail, Recovertime: defaultRecovertime, Listen: defaultListen,
		Remotetimeout: defaultRemoteTimeout, Insidetimeout: defaultInsideTimeout, Starttimeout: defaultStartTimeout,
		Whitelistenable: false}
	config := Config{verbose: verbose}
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(data, &userConfig); err != nil {
		return config, err
	}
	if userConfig.Listen == "" || userConfig.Port == 0 {
		return config, errors.New("Cannot load config.")
	}
	config.listenAddr = net.TCPAddr{IP: net.ParseIP(userConfig.Listen), Port: userConfig.Port}
	config.auth, config.username, config.password = userConfig.Auth, []byte(userConfig.Username), []byte(userConfig.Password)
	config.servers = userConfig.loadServers()
	config.whitelist = userConfig.loadWhitelist()
	config.whitelist.logger = config.log
	config.scheduler = Scheduler{}
	config.scheduler.init(len(config.servers), userConfig.Maxfail, channelBufferSize, userConfig.Recovertime, verbose)
	config.rtimeout = time.Duration(userConfig.Remotetimeout) * time.Second
	config.itimeout = time.Duration(userConfig.Insidetimeout) * time.Second
	config.stimeout = time.Duration(userConfig.Starttimeout) * time.Second
	return config, nil
}

func makeServer(s string) (Server, error) {
	addr, cipher, password, err := parseURL(s)
	if err != nil {
		return Server{}, err
	}
	ciph, err := core.PickCipher(cipher, []byte{}, password)
	if err != nil {
		return Server{}, err
	}
	return Server{s, ciph, addr}, nil
}

func main() {
	var configFile string
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flag.StringVar(&configFile, "c", "config.json", "config file path")
	flag.Parse()

	c, err := LoadUserConfig(configFile, verbose)
	if err != nil {
		log.Println("Error!", err)
		return
	}
	c.StartServer()
}
