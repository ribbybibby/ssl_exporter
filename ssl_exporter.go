package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/prober"
	"golang.org/x/crypto/ocsp"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	namespace = "ssl"
)

var (
	tlsConnectSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "tls_connect_success"),
		"If the TLS connection was a success",
		nil, nil,
	)
	tlsVersion = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "tls_version_info"),
		"The TLS version used",
		[]string{"version"}, nil,
	)
	proberType = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "prober"),
		"The prober used by the exporter to connect to the target",
		[]string{"prober"}, nil,
	)
	notBefore = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_not_before"),
		"NotBefore expressed as a Unix Epoch Time",
		[]string{"serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"}, nil,
	)
	notAfter = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_not_after"),
		"NotAfter expressed as a Unix Epoch Time",
		[]string{"serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"}, nil,
	)
	verifiedNotBefore = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "verified_cert_not_before"),
		"NotBefore expressed as a Unix Epoch Time for a certificate in the list of verified chains",
		[]string{"chain_no", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"}, nil,
	)
	verifiedNotAfter = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "verified_cert_not_after"),
		"NotAfter expressed as a Unix Epoch Time for a certificate in the list of verified chains",
		[]string{"chain_no", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"}, nil,
	)
	ocspStapled = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ocsp_response_stapled"),
		"If the connection state contains a stapled OCSP response",
		nil, nil,
	)
	ocspStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ocsp_response_status"),
		"The status in the OCSP response 0=Good 1=Revoked 2=Unknown",
		nil, nil,
	)
	ocspProducedAt = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ocsp_response_produced_at"),
		"The producedAt value in the OCSP response, expressed as a Unix Epoch Time",
		nil, nil,
	)
	ocspThisUpdate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ocsp_response_this_update"),
		"The thisUpdate value in the OCSP response, expressed as a Unix Epoch Time",
		nil, nil,
	)
	ocspNextUpdate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ocsp_response_next_update"),
		"The nextUpdate value in the OCSP response, expressed as a Unix Epoch Time",
		nil, nil,
	)
	ocspRevokedAt = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ocsp_response_revoked_at"),
		"The revocationTime value in the OCSP response, expressed as a Unix Epoch Time",
		nil, nil,
	)
)

// Exporter is the exporter type...
type Exporter struct {
	target         string
	prober         prober.ProbeFn
	timeout        time.Duration
	module         config.Module
	tlsConfig      *tls.Config
	verifiedChains [][]*x509.Certificate
}

// Describe metrics
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- tlsConnectSuccess
	ch <- tlsVersion
	ch <- proberType
	ch <- notAfter
	ch <- notBefore
	ch <- verifiedNotAfter
	ch <- verifiedNotBefore
	ch <- ocspStapled
	ch <- ocspStatus
	ch <- ocspProducedAt
	ch <- ocspThisUpdate
	ch <- ocspNextUpdate
	ch <- ocspRevokedAt
}

// Collect metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		proberType, prometheus.GaugeValue, 1, e.module.Prober,
	)

	state, err := e.probe()
	if err != nil {
		log.Errorf("error=%s target=%s prober=%s timeout=%s", err, e.target, e.module.Prober, e.timeout)
		ch <- prometheus.MustNewConstMetric(
			tlsConnectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	// If the probe returned a nil error then consider the tls connection a success
	ch <- prometheus.MustNewConstMetric(
		tlsConnectSuccess, prometheus.GaugeValue, 1,
	)

	// Get the TLS version from the connection state and export it as a metric
	ch <- prometheus.MustNewConstMetric(
		tlsVersion, prometheus.GaugeValue, 1, getTLSVersion(state),
	)

	// Retrieve certificates from the connection state and remove duplicates
	peerCertificates := uniq(state.PeerCertificates)

	// Loop through peer certificates and create metrics
	for _, cert := range peerCertificates {
		if !cert.NotAfter.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				notAfter,
				prometheus.GaugeValue,
				float64(cert.NotAfter.UnixNano()/1e9),
				cert.SerialNumber.String(),
				cert.Issuer.CommonName,
				cert.Subject.CommonName,
				getDNSNames(cert),
				getIPAddresses(cert),
				getEmailAddresses(cert),
				getOrganizationalUnits(cert),
			)
		}

		if !cert.NotBefore.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				notBefore,
				prometheus.GaugeValue,
				float64(cert.NotBefore.UnixNano()/1e9),
				cert.SerialNumber.String(),
				cert.Issuer.CommonName,
				cert.Subject.CommonName,
				getDNSNames(cert),
				getIPAddresses(cert),
				getEmailAddresses(cert),
				getOrganizationalUnits(cert),
			)
		}
	}

	// The custom TLS verification should have populated the verifiedChains
	// on the exporter (if there are any)
	verifiedChains := e.verifiedChains

	// Sort the verified chains from the chain that is valid for longest to the chain
	// that expires the soonest
	sort.Slice(verifiedChains, func(i, j int) bool {
		iExpiry := time.Time{}
		for _, cert := range verifiedChains[i] {
			if (iExpiry.IsZero() || cert.NotAfter.Before(iExpiry)) && !cert.NotAfter.IsZero() {
				iExpiry = cert.NotAfter
			}
		}
		jExpiry := time.Time{}
		for _, cert := range verifiedChains[j] {
			if (jExpiry.IsZero() || cert.NotAfter.Before(jExpiry)) && !cert.NotAfter.IsZero() {
				jExpiry = cert.NotAfter
			}
		}

		return iExpiry.After(jExpiry)
	})

	// Loop through the verified chains creating metrics. Label the metrics
	// with the index of the chain.
	for i, chain := range verifiedChains {
		chain = uniq(chain)
		for _, cert := range chain {
			chainNo := strconv.Itoa(i)

			if !cert.NotAfter.IsZero() {
				ch <- prometheus.MustNewConstMetric(
					verifiedNotAfter,
					prometheus.GaugeValue,
					float64(cert.NotAfter.UnixNano()/1e9),
					chainNo,
					cert.SerialNumber.String(),
					cert.Issuer.CommonName,
					cert.Subject.CommonName,
					getDNSNames(cert),
					getIPAddresses(cert),
					getEmailAddresses(cert),
					getOrganizationalUnits(cert),
				)
			}

			if !cert.NotBefore.IsZero() {
				ch <- prometheus.MustNewConstMetric(
					verifiedNotBefore,
					prometheus.GaugeValue,
					float64(cert.NotBefore.UnixNano()/1e9),
					chainNo,
					cert.SerialNumber.String(),
					cert.Issuer.CommonName,
					cert.Subject.CommonName,
					getDNSNames(cert),
					getIPAddresses(cert),
					getEmailAddresses(cert),
					getOrganizationalUnits(cert),
				)
			}
		}
	}

	if err := collectOCSPMetrics(ch, state); err != nil {
		log.Errorf("error=%s target=%s prober=%s timeout=%s", err, e.target, e.module.Prober, e.timeout)
	}
}

func collectOCSPMetrics(ch chan<- prometheus.Metric, state *tls.ConnectionState) error {
	if len(state.OCSPResponse) > 0 {
		resp, err := ocsp.ParseResponse(state.OCSPResponse, nil)
		if err != nil {
			ch <- prometheus.MustNewConstMetric(
				ocspStapled, prometheus.GaugeValue, 0,
			)
			return err
		}
		ch <- prometheus.MustNewConstMetric(
			ocspStapled, prometheus.GaugeValue, 1,
		)
		ch <- prometheus.MustNewConstMetric(
			ocspStatus, prometheus.GaugeValue, float64(resp.Status),
		)
		ch <- prometheus.MustNewConstMetric(
			ocspProducedAt, prometheus.GaugeValue, float64(resp.ProducedAt.Unix()),
		)
		ch <- prometheus.MustNewConstMetric(
			ocspThisUpdate, prometheus.GaugeValue, float64(resp.ThisUpdate.Unix()),
		)
		ch <- prometheus.MustNewConstMetric(
			ocspNextUpdate, prometheus.GaugeValue, float64(resp.NextUpdate.Unix()),
		)
		ch <- prometheus.MustNewConstMetric(
			ocspRevokedAt, prometheus.GaugeValue, float64(resp.RevokedAt.Unix()),
		)
	} else {
		ch <- prometheus.MustNewConstMetric(
			ocspStapled, prometheus.GaugeValue, 0,
		)
	}

	return nil
}

// probe configures the TLSConfig, probes the target and returns the resulting
// connection state
func (e *Exporter) probe() (*tls.ConnectionState, error) {
	if err := e.configureTLSConfig(); err != nil {
		return nil, err
	}

	state, err := e.prober(e.target, e.module, e.timeout, e.tlsConfig)
	if err != nil {
		return nil, err
	}

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("No certificates found in connection state")
	}

	return state, nil
}

// configureTLSConfig creates and customizes the tls.Config used for the
// connection
func (e *Exporter) configureTLSConfig() error {
	tlsConfig, err := config.NewTLSConfig(&e.module.TLSConfig)
	if err != nil {
		return err
	}

	// Override the standard connection verification with our own
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = e.verifyConnection

	if e.module.Prober == "tcp" && tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(e.target)
		if err != nil {
			return err
		}
		tlsConfig.ServerName = host
	}

	e.tlsConfig = tlsConfig

	return nil
}

// verifyConnection provides custom verification for the TLS connection
func (e *Exporter) verifyConnection(state tls.ConnectionState) error {
	if !e.module.TLSConfig.InsecureSkipVerify {
		var verifyFunc func(*tls.ConnectionState) ([][]*x509.Certificate, error)

		verifyFunc = e.verifyPKIX
		if e.module.TLSConfig.DANE.Verify {
			verifyFunc = e.verifyDANE
		}

		verifiedChains, err := verifyFunc(&state)
		if err != nil {
			return err
		}

		e.verifiedChains = verifiedChains
	}

	return nil
}

// verifyPKIX performs typical PKIX verification of the target certificates
func (e *Exporter) verifyPKIX(state *tls.ConnectionState) ([][]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots:         e.tlsConfig.RootCAs,
		DNSName:       state.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	return state.PeerCertificates[0].Verify(opts)
}

// verifyDANE performs DANE verification
func (e *Exporter) verifyDANE(state *tls.ConnectionState) ([][]*x509.Certificate, error) {
	// Get the TLSA record name from the target
	host, port, err := net.SplitHostPort(e.target)
	if err != nil {
		return [][]*x509.Certificate{}, err
	}
	name, err := dns.TLSAName(dns.Fqdn(host), port, "tcp")
	if err != nil {
		return [][]*x509.Certificate{}, err
	}

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Id:               dns.Id(),
		},
		Question: []dns.Question{
			dns.Question{
				Name:   name,
				Qtype:  dns.TypeTLSA,
				Qclass: dns.ClassINET,
			},
		},
	}

	c := &dns.Client{}

	// Retrieve nameservers from resolv.conf
	resolvConf := "/etc/resolv.conf"
	cc, err := dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		return [][]*x509.Certificate{}, err
	}
	if len(cc.Servers) == 0 {
		return [][]*x509.Certificate{}, fmt.Errorf("no nameservers found in %s", resolvConf)
	}

	for _, server := range cc.Servers {
		in, _, err := c.Exchange(m, server+":53")
		if err != nil {
			log.Errorln(err)
			continue
		}

		for _, rr := range in.Answer {
			tr, ok := rr.(*dns.TLSA)
			if !ok {
				continue
			}
			switch tr.Usage {
			case 0:
				// Record must be in the verified chain,
				// not including leaf AND must pass pkix
				verifiedChains, err := e.verifyPKIX(state)
				if err == nil {
					for _, chain := range verifiedChains {
						for _, cert := range chain[1:] {
							if err := tr.Verify(cert); err == nil {
								return verifiedChains, nil
							}
						}
					}
				}
			case 1:
				// Must match leaf certificate
				// AND must pass pkix
				verifiedChains, err := e.verifyPKIX(state)
				if err == nil {
					if err := tr.Verify(state.PeerCertificates[0]); err == nil {
						return verifiedChains, nil
					}
				}
			case 2:
				// Must be in peer certificate chain, not
				// including leaf
				chains, err := verifyChain(state.PeerCertificates)
				if err == nil {
					for _, chain := range chains {
						for _, cert := range chain[1:] {
							if err := tr.Verify(cert); err == nil {
								if err := state.PeerCertificates[0].VerifyHostname(e.tlsConfig.ServerName); err == nil {
									return chains, nil
								}
							}
						}
					}
				}
			case 3:
				// Must match leaf certificate
				if err := tr.Verify(state.PeerCertificates[0]); err == nil {
					return [][]*x509.Certificate{}, nil
				}
			}
		}
	}

	return [][]*x509.Certificate{}, fmt.Errorf("can't find matching TLSA record for %s", name)
}

// verifyChain performs PKIX verification against the chain presented by the
// server, without considering the root certificates of the client
func verifyChain(certs []*x509.Certificate) ([][]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}
	opts.Roots.AddCert(certs[len(certs)-1])
	if len(certs) >= 3 {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	return certs[0].Verify(opts)
}

func probeHandler(w http.ResponseWriter, r *http.Request, conf *config.Config) {
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "tcp"
	}
	module, ok := conf.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		return
	}

	timeout := module.Timeout
	if timeout == 0 {
		// The following timeout block was taken wholly from the blackbox exporter
		//   https://github.com/prometheus/blackbox_exporter/blob/master/main.go
		var timeoutSeconds float64
		if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
			var err error
			timeoutSeconds, err = strconv.ParseFloat(v, 64)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
				return
			}
		} else {
			timeoutSeconds = 10
		}
		if timeoutSeconds == 0 {
			timeoutSeconds = 10
		}

		timeout = time.Duration((timeoutSeconds) * 1e9)
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "Target parameter is missing", http.StatusBadRequest)
		return
	}

	prober, ok := prober.Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}

	exporter := &Exporter{
		target:  target,
		prober:  prober,
		timeout: timeout,
		module:  module,
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)

	// Serve
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func uniq(certs []*x509.Certificate) []*x509.Certificate {
	r := []*x509.Certificate{}

	for _, c := range certs {
		if !contains(r, c) {
			r = append(r, c)
		}
	}

	return r
}

func contains(certs []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range certs {
		if (c.SerialNumber.String() == cert.SerialNumber.String()) && (c.Issuer.CommonName == cert.Issuer.CommonName) {
			return true
		}
	}
	return false
}

func getTLSVersion(state *tls.ConnectionState) string {
	switch state.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func getDNSNames(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return "," + strings.Join(cert.DNSNames, ",") + ","
	}

	return ""
}

func getEmailAddresses(cert *x509.Certificate) string {
	if len(cert.EmailAddresses) > 0 {
		return "," + strings.Join(cert.EmailAddresses, ",") + ","
	}

	return ""
}

func getIPAddresses(cert *x509.Certificate) string {
	if len(cert.IPAddresses) > 0 {
		ips := ","
		for _, ip := range cert.IPAddresses {
			ips = ips + ip.String() + ","
		}
		return ips
	}

	return ""
}

func getOrganizationalUnits(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ","
	}

	return ""
}

func init() {
	prometheus.MustRegister(version.NewCollector(namespace + "_exporter"))
}

func main() {
	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9219").String()
		metricsPath   = kingpin.Flag("web.metrics-path", "Path under which to expose metrics").Default("/metrics").String()
		probePath     = kingpin.Flag("web.probe-path", "Path under which to expose the probe endpoint").Default("/probe").String()
		configFile    = kingpin.Flag("config.file", "SSL exporter configuration file").Default("").String()
		err           error
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print(namespace + "_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	conf := config.DefaultConfig
	if *configFile != "" {
		conf, err = config.LoadConfig(*configFile)
		if err != nil {
			log.Fatalln(err)
		}
	}

	log.Infoln("Starting "+namespace+"_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc(*probePath, func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, conf)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
						 <head><title>SSL Exporter</title></head>
						 <body>
						 <h1>SSL Exporter</h1>
						 <p><a href="` + *probePath + `?target=example.com:443">Probe example.com:443 for SSL cert metrics</a></p>
						 <p><a href='` + *metricsPath + `'>Metrics</a></p>
						 </body>
						 </html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
