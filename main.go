package main

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	dnsConf  *dns.ClientConfig
	config   *Config
)

type Config struct {
	Checks  map[string]Answer `json:"checks"`
	Timeout uint16            `json:"timeout"`
	Once    bool              `json:"once"`
	ShutdownDelay uint16      `json:"shutdown-delay"`
}

type Answer struct {
	Question   string `json:"question"`
	Response   string `json:"response"`
	RecordType string `json:"recordType"`
}

type Output struct {
	Answer
	Success   bool   `json:"success"`
	Duration  int64  `json:"duration"`
	Error     error  `json:"error"`
	RCode     string `json:"responseCode"`
	Timestamp string `json:"timestamp"`
}

type OnceSignal struct{}

func (s *OnceSignal) String() string {
	return "once flag is set"
}

func (s *OnceSignal) Signal() {}

func main() {
	if len(os.Args) < 2 {
		panic("Please provide config file path as first arg")
	}
	setup(os.Args[1])
	var sChans = make([]chan os.Signal, 0)
	exitChan := make(chan os.Signal)
	signal.Notify(exitChan, syscall.SIGINT, syscall.SIGTERM)

	wg := &sync.WaitGroup{}
	for r, a := range config.Checks {
		if !strings.HasSuffix(r, ".") {
			r = r + "."
		}
		wg.Add(1)
		subChan := make(chan os.Signal)
		sChans = append(sChans, subChan)
		go check(config, r, dns.TypeA, a, wg, subChan)
	}

	go signaller(config, exitChan)

	signl := <-exitChan
	fmt.Printf("{\"type\":\"event\",\"signal\":\"%s\"}\n", signl.String())
	for _, c := range sChans {
		c <- signl
	}
	if _, ok := signl.(*OnceSignal); ok {
		fmt.Printf("{\"type\":\"info\",\"msg\":\"waiting for shutdown delay: %d\"}\n", config.ShutdownDelay)
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			time.Sleep(time.Duration(config.ShutdownDelay) * time.Second)
			wg.Done()
		}(wg)
	}
	wg.Wait()
	os.Exit(0)
}

func setup(confFile string) {
	confContent, err := ioutil.ReadFile(confFile)
	if err != nil {
		panic(err)
	}
	config = &Config{}
	err = json.Unmarshal(confContent, config)
	if err != nil {
		panic(err)
	}
	if config.Timeout < 1 {
		config.Timeout = 5
	}

	dnsConf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		panic(err)
	}

	if len(dnsConf.Servers) == 0 {
		panic("No nameservers configured")
	}

	if len(config.Checks) == 0 {
		panic("No records configured")
	}
}

func signaller(config *Config, exitChan chan<- os.Signal) {
	if config.Once {
		exitChan <- &OnceSignal{}
	}
}

func check(config *Config, name string, recordType uint16, expected Answer, wg *sync.WaitGroup, exitChan <-chan os.Signal) {
	localm := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	localc := &dns.Client{
		ReadTimeout: time.Duration(config.Timeout) * time.Second,
	}
	for {
		localm.SetQuestion(name, recordType)
		for _, server := range dnsConf.Servers {
			now := time.Now()
			before := now.UnixNano()
			r, _, err := localc.Exchange(localm, server+":"+dnsConf.Port)
			after := time.Now().UnixNano()
			duration := after - before
			if err != nil {
				output(nil, err, expected, now, duration)
			}
			if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
				output(r, err, expected, now, duration)
			}
		}

		select {
		case <-exitChan:
			wg.Done()
			return
		default:
			delay := time.Duration(rand.Intn(5000)) + 500
			time.Sleep(delay * time.Millisecond)
		}
	}
}

func output(msg *dns.Msg, err error, expected Answer, checkTime time.Time, duration int64) {

	actual := Output{}
	actual.Timestamp = checkTime.Format(time.RFC3339)
	actual.Duration = duration / 1000 // microseconds
	if err != nil {
		actual.Error = err
	}
	if msg != nil && len(msg.Question) > 0 {
		actual.Question = msg.Question[0].Name
	}
	if msg != nil && len(msg.Answer) > 0 {
		actual.RecordType = dns.TypeToString[msg.Answer[0].Header().Rrtype]
		if actual.RecordType == "A" {
			actual.Response = msg.Answer[0].(*dns.A).A.String()
		} else if actual.RecordType == "CNAME" {
			actual.Response = msg.Answer[0].(*dns.CNAME).Target
		}
		actual.RCode = dns.RcodeToString[msg.MsgHdr.Rcode]
	}

	actual.Success = actual.Error == nil && (expected.Response == "*" || actual.Response == expected.Response) && actual.RecordType == expected.RecordType && actual.RCode == "NOERROR"
	outputJSON(actual)
}

func outputJSON(actual Output) {
	s, err := json.Marshal(actual)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(s))
}
