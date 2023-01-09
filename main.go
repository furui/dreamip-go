package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DreamhostAPI    = "api.dreamhost.com"
	AddDNSRecord    = "dns-add_record"
	RemoveDNSRecord = "dns-remove_record"
	ListDNSRecord   = "dns-list_records"
)

type DNSRecord struct {
	Record    string `json:"record,omitempty"`
	Type      string `json:"type,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Value     string `json:"value,omitempty"`
	Editable  string `json:"editable,omitempty"`
	AccountID string `json:"account_id,omitempty"`
}

type DNSRecords []DNSRecord

type DNSRecordData struct {
	Result string     `json:"result,omitempty"`
	Data   DNSRecords `json:"data,omitempty"`
}

type DNSResult struct {
	Result string `json:"result,omitempty"`
	Data   string `json:"data,omitempty"`
}

func (d *DNSRecords) FindByRecord(record string) DNSRecords {
	foundRecords := make(DNSRecords, 0)
	for _, r := range *d {
		if r.Record == record {
			foundRecords = append(foundRecords, r)
		}
	}
	return foundRecords
}

type IPAddress string

func (i *IPAddress) IsIPV4() bool {
	return strings.Count(string(*i), ":") < 2
}

func (i *IPAddress) IsIPV6() bool {
	return strings.Count(string(*i), ":") >= 2
}

func (i *IPAddress) Match(other IPAddress) bool {
	this := net.ParseIP(string(*i))
	that := net.ParseIP(string(other))
	return this.Equal(that)
}

func GetIPAddress() (IPAddress, error) {
	var (
		zeroDialer net.Dialer
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return zeroDialer.DialContext(ctx, "tcp6", addr)
	}
	httpClient.Transport = transport
	resp, err := httpClient.Get("https://api64.ipify.org")
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ipify returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return IPAddress(strings.ToUpper(string(body))), nil
}

func GetIPV4Address() (IPAddress, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ipify returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return IPAddress(body), nil
}

func GetDreamhostRecords(key string) (DNSRecords, error) {
	url, err := url.Parse(fmt.Sprintf("https://%s/?key=%s&cmd=%s&format=json", DreamhostAPI, key, ListDNSRecord))
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("dreamhost returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var records DNSRecordData
	err = json.Unmarshal(body, &records)
	if err != nil {
		return nil, err
	}
	if records.Result != "success" {
		return nil, fmt.Errorf("api returned: %s", records.Result)
	}
	return records.Data, nil

}

func AddDreamhostRecord(key string, record string, recordtype string, ip string) error {
	url, err := url.Parse(fmt.Sprintf("https://%s?key=%s&cmd=%s&record=%s&type=%s&value=%s&format=json", DreamhostAPI, key, AddDNSRecord, record, recordtype, ip))
	if err != nil {
		return err
	}
	resp, err := http.Get(url.String())
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("dreamhost returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var res DNSResult
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}
	if res.Result != "success" {
		return fmt.Errorf("api returned: [%s] %s", res.Result, res.Data)
	}
	log.Printf("added Record: %s Type: %s Value: %s", record, recordtype, ip)
	return nil
}

func RemoveDreamhostRecord(key string, record string, recordtype string, ip string) error {
	url, err := url.Parse(fmt.Sprintf("https://%s?key=%s&cmd=%s&record=%s&type=%s&value=%s&format=json", DreamhostAPI, key, RemoveDNSRecord, record, recordtype, ip))
	if err != nil {
		return err
	}
	resp, err := http.Get(url.String())
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("dreamhost returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var res DNSResult
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}
	if res.Result != "success" {
		return fmt.Errorf("api returned: [%s] %s", res.Result, res.Data)
	}
	log.Printf("removed Record: %s Type: %s Value: %s", record, recordtype, ip)
	return nil
}

func main() {
	keyPtr := flag.String("key", "", "DreamHost API Key")
	hostnamePtr := flag.String("record", "subdomain.example.com", "Record to update")
	forceIPV4 := flag.String("ipv4", "", "Set to force an IPv4 address")
	forceIPV6 := flag.String("ipv6", "", "Set to force an IPv6 address")
	flag.Parse()

	var err error
	ip := IPAddress("")
	ipv4 := IPAddress("")

	if *keyPtr == "" {
		log.Fatal("please specify a key")
	}
	if *hostnamePtr == "" {
		log.Fatal("please specify a record")
	}

	// Get current IP Addresses
	if *forceIPV6 != "" {
		ip = IPAddress(strings.ToUpper(*forceIPV6))
	} else if *forceIPV4 != "" {
		ip = IPAddress(*forceIPV4)
	} else {
		ip, err = GetIPAddress()
		if err != nil {
			log.Printf("couldn't get ip: %s", err)
		}
	}
	if ip.IsIPV6() {
		if *forceIPV4 != "" {
			ipv4 = IPAddress(*forceIPV4)
		} else {
			ipv4, err = GetIPV4Address()
			if err != nil {
				log.Fatal(err)
			}
		}
		log.Printf("got IPV6: %s IPV4: %s", ip, ipv4)
	} else {
		ipv4 = ip
		log.Printf("got IPV4: %s", ipv4)
	}

	// Get all records
	records, err := GetDreamhostRecords(*keyPtr)
	if err != nil {
		log.Fatal(err)
	}
	oldRecords := records.FindByRecord(*hostnamePtr)
	matchesv4 := false
	matchesv6 := false
	// Check if any match our current (don't update if they do)
	for _, rec := range oldRecords {
		log.Printf("current Record: %s Type: %s Value: %s", rec.Record, rec.Type, rec.Value)
		if rec.Type == "AAAA" && ip.Match(IPAddress(rec.Value)) {
			matchesv6 = true
		}
		if rec.Type == "A" && ipv4.Match(IPAddress(rec.Value)) {
			matchesv4 = true
		}
	}

	if string(ip) == "" {
		log.Fatal("no ip specified")
	}

	// Add new entries
	if ip.IsIPV6() && !matchesv6 {
		err = AddDreamhostRecord(*keyPtr, *hostnamePtr, "AAAA", string(ip))
		if err != nil {
			log.Fatal(err)
		}
		if string(ipv4) != "" && ipv4.IsIPV4() && !matchesv4 {
			err = AddDreamhostRecord(*keyPtr, *hostnamePtr, "A", string(ipv4))
			if err != nil {
				log.Fatal(err)
			}
		}
	} else if !matchesv4 {
		err = AddDreamhostRecord(*keyPtr, *hostnamePtr, "A", string(ip))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Remove old entries if they don't match
	for _, rec := range oldRecords {
		if rec.Type == "AAAA" && !matchesv6 {
			RemoveDreamhostRecord(*keyPtr, rec.Record, rec.Type, rec.Value)
		}
		if rec.Type == "A" && !matchesv4 {
			RemoveDreamhostRecord(*keyPtr, rec.Record, rec.Type, rec.Value)
		}
	}
}
