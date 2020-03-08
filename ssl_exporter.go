package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
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
	clientProtocol = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "client_protocol"),
		"The protocol used by the exporter to connect to the target",
		[]string{"protocol"}, nil,
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
)

// Exporter is the exporter type...
type Exporter struct {
	target    string
	timeout   time.Duration
	tlsConfig *tls.Config
}

// Describe metrics
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- tlsConnectSuccess
	ch <- clientProtocol
	ch <- notAfter
	ch <- notBefore
}

// Collect metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	var state tls.ConnectionState

	// Parse the target and return the appropriate connection protocol and target address
	target, proto, err := parseTarget(e.target)
	if err != nil {
		log.Errorln(err)
		ch <- prometheus.MustNewConstMetric(
			tlsConnectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		clientProtocol, prometheus.GaugeValue, 1, proto,
	)

	if proto == "https" {
		ch <- prometheus.MustNewConstMetric(
			clientProtocol, prometheus.GaugeValue, 0, "tcp",
		)

		// Create the http client
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: e.tlsConfig,
				Proxy:           http.ProxyFromEnvironment,
			},
			Timeout: e.timeout,
		}

		// Issue a GET request to the target
		resp, err := client.Get(target)
		if err != nil {
			log.Errorln(err)
			ch <- prometheus.MustNewConstMetric(
				tlsConnectSuccess, prometheus.GaugeValue, 0,
			)
			return
		}

		// Check if the response from the target is encrypted
		if resp.TLS == nil {
			log.Errorln("The response from " + target + " is unencrypted")
			ch <- prometheus.MustNewConstMetric(
				tlsConnectSuccess, prometheus.GaugeValue, 0,
			)
			return
		}

		state = *resp.TLS

	} else if proto == "tcp" {
		ch <- prometheus.MustNewConstMetric(
			clientProtocol, prometheus.GaugeValue, 0, "https",
		)

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: e.timeout}, "tcp", target, e.tlsConfig)
		if err != nil {
			log.Errorln(err)
			ch <- prometheus.MustNewConstMetric(
				tlsConnectSuccess, prometheus.GaugeValue, 0,
			)
			return
		}

		state = conn.ConnectionState()
	} else {
		log.Errorln("Unrecognised protocol: " + string(proto) + " for target: " + target)
		ch <- prometheus.MustNewConstMetric(
			tlsConnectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	// Get the TLS version from the connection state and export it as a metric
	ch <- prometheus.MustNewConstMetric(
		tlsVersion, prometheus.GaugeValue, 1, getTLSVersion(&state),
	)

	// Retrieve certificates from the connection state
	peerCertificates := state.PeerCertificates
	if len(peerCertificates) < 1 {
		log.Errorln("No certificates found in connection state for " + target)
		ch <- prometheus.MustNewConstMetric(
			tlsConnectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		tlsConnectSuccess, prometheus.GaugeValue, 1,
	)

	// Remove duplicate certificates from the response
	peerCertificates = uniq(peerCertificates)

	// Loop through returned certificates and create metrics
	for _, cert := range peerCertificates {
		var DNSNamesLabel, emailsLabel, ipsLabel, OULabel string

		commonName := cert.Subject.CommonName
		issuerCommonName := cert.Issuer.CommonName
		serialNo := cert.SerialNumber.String()
		DNSNames := cert.DNSNames
		emailAddresses := cert.EmailAddresses
		IPAddresses := cert.IPAddresses
		OU := cert.Subject.OrganizationalUnit

		if len(DNSNames) > 0 {
			DNSNamesLabel = "," + strings.Join(DNSNames, ",") + ","
		}

		if len(emailAddresses) > 0 {
			emailsLabel = "," + strings.Join(DNSNames, ",") + ","
		}

		if len(IPAddresses) > 0 {
			ipsLabel = ","
			for _, ip := range IPAddresses {
				ipsLabel = ipsLabel + ip.String() + ","
			}
		}

		if len(OU) > 0 {
			OULabel = "," + strings.Join(OU, ",") + ","
		}

		if !cert.NotAfter.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				notAfter, prometheus.GaugeValue, float64(cert.NotAfter.UnixNano()/1e9), serialNo, issuerCommonName, commonName, DNSNamesLabel, ipsLabel, emailsLabel, OULabel,
			)
		}

		if !cert.NotBefore.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				notBefore, prometheus.GaugeValue, float64(cert.NotBefore.UnixNano()/1e9), serialNo, issuerCommonName, commonName, DNSNamesLabel, ipsLabel, emailsLabel, OULabel,
			)
		}
	}
}

func probeHandler(w http.ResponseWriter, r *http.Request, tlsConfig *tls.Config) {
	target := r.URL.Query().Get("target")

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

	timeout := time.Duration((timeoutSeconds) * 1e9)

	exporter := &Exporter{
		target:    target,
		timeout:   timeout,
		tlsConfig: tlsConfig,
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

func parseTarget(target string) (parsedTarget string, proto string, err error) {
	if !strings.Contains(target, "://") {
		target = "//" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", proto, err
	}

	if u.Scheme != "" {
		if u.Scheme == "https" {
			return u.String(), "https", nil
		}
		return "", proto, errors.New("can't handle the scheme '" + u.Scheme + "' - try providing the target in the format <host>:<port>")
	} else if u.Port() == "" {
		return "https://" + u.Host, "https", nil
	}
	return u.Host, "tcp", nil
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

func init() {
	prometheus.MustRegister(version.NewCollector(namespace + "_exporter"))
}

func main() {
	var (
		tlsConfig     *tls.Config
		certificates  []tls.Certificate
		rootCAs       *x509.CertPool
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9219").String()
		metricsPath   = kingpin.Flag("web.metrics-path", "Path under which to expose metrics").Default("/metrics").String()
		probePath     = kingpin.Flag("web.probe-path", "Path under which to expose the probe endpoint").Default("/probe").String()
		insecure      = kingpin.Flag("tls.insecure", "Skip certificate verification").Default("false").Bool()
		clientAuth    = kingpin.Flag("tls.client-auth", "Enable client authentication").Default("false").Bool()
		caFile        = kingpin.Flag("tls.cacert", "Local path to an alternative CA cert bundle").String()
		certFile      = kingpin.Flag("tls.cert", "Local path to a client certificate file (for client authentication)").Default("cert.pem").String()
		keyFile       = kingpin.Flag("tls.key", "Local path to a private key file (for client authentication)").Default("key.pem").String()
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print(namespace + "_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	if *caFile != "" {
		caCert, err := ioutil.ReadFile(*caFile)
		if err != nil {
			log.Fatalln(err)
		}

		rootCAs = x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caCert)
	}

	if *clientAuth {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalln(err)
		}
		certificates = append(certificates, cert)
	}

	tlsConfig = &tls.Config{
		InsecureSkipVerify: *insecure,
		Certificates:       certificates,
		RootCAs:            rootCAs,
	}

	log.Infoln("Starting "+namespace+"_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc(*probePath, func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, tlsConfig)
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
