package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
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
	httpsConnectSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "https_connect_success"),
		"If the TLS connection was a success",
		nil, nil,
	)
	notBefore = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_not_before"),
		"NotBefore expressed as a Unix Epoch Time",
		[]string{"serial_no", "issuer_cn"}, nil,
	)
	notAfter = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_not_after"),
		"NotAfter expressed as a Unix Epoch Time",
		[]string{"serial_no", "issuer_cn"}, nil,
	)
	commonName = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_subject_common_name"),
		"Subject Common Name",
		[]string{"serial_no", "issuer_cn", "subject_cn"}, nil,
	)
	subjectAlernativeDNSNames = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_subject_alternative_dnsnames"),
		"Subject Alternative DNS Names",
		[]string{"serial_no", "issuer_cn", "dnsnames"}, nil,
	)
	subjectAlernativeIPs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_subject_alternative_ips"),
		"Subject Alternative DNS Names",
		[]string{"serial_no", "issuer_cn", "ips"}, nil,
	)
	subjectAlernativeEmailAddresses = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_subject_alternative_emails"),
		"Subject Alternative DNS Names",
		[]string{"serial_no", "issuer_cn", "emails"}, nil,
	)
)

type Exporter struct {
	target   string
	timeout  time.Duration
	insecure bool
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- httpsConnectSuccess
	ch <- notAfter
	ch <- commonName
	ch <- subjectAlernativeDNSNames
	ch <- subjectAlernativeIPs
	ch <- subjectAlernativeEmailAddresses
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	// Create the HTTP client and make a get request of the target
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: e.insecure},
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout: e.timeout,
	}
	resp, err := client.Get(e.target)
	
	if err != nil {
		log.Errorln(err)
		ch <- prometheus.MustNewConstMetric(
			httpsConnectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	if resp.TLS == nil {
		log.Errorln("The response from " + e.target + " is unencrypted")
		ch <- prometheus.MustNewConstMetric(
			httpsConnectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		httpsConnectSuccess, prometheus.GaugeValue, 1,
	)

	// Loop through returned certificates and create metrics
	for _, cert := range resp.TLS.PeerCertificates {

		subject_cn     := cert.Subject.CommonName
		issuer_cn      := cert.Issuer.CommonName
		subject_dnsn   := cert.DNSNames
		subject_emails := cert.EmailAddresses
		subject_ips    := cert.IPAddresses
		serial_no      := cert.SerialNumber.String()

		if !cert.NotAfter.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				notAfter, prometheus.GaugeValue, float64(cert.NotAfter.UnixNano()/1e9), serial_no, issuer_cn,
			)
		}

		if !cert.NotBefore.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				notBefore, prometheus.GaugeValue, float64(cert.NotBefore.UnixNano()/1e9), serial_no, issuer_cn,
			)
		}

		if subject_cn != "" {
			ch <- prometheus.MustNewConstMetric(
				commonName, prometheus.GaugeValue, 1, serial_no, issuer_cn, subject_cn,
			)
		}

		if len(subject_dnsn) > 0 {
			ch <- prometheus.MustNewConstMetric(
				subjectAlernativeDNSNames, prometheus.GaugeValue, 1, serial_no, issuer_cn, ","+strings.Join(subject_dnsn, ",")+",",
			)
		}

		if len(subject_emails) > 0 {
			ch <- prometheus.MustNewConstMetric(
				subjectAlernativeEmailAddresses, prometheus.GaugeValue, 1, serial_no, issuer_cn, ","+strings.Join(subject_emails, ",")+",",
			)
		}

		if len(subject_ips) > 0 {
			i := ","
			for _, ip := range subject_ips {
				i = i + ip.String() + ","
			}
			ch <- prometheus.MustNewConstMetric(
				subjectAlernativeIPs, prometheus.GaugeValue, 1, serial_no, issuer_cn, i,
			)
		}
	}
}

func probeHandler(w http.ResponseWriter, r *http.Request, insecure bool) {

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
		target:   target,
		timeout:  timeout,
		insecure: insecure,
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)

	// Serve
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func init() {
	prometheus.MustRegister(version.NewCollector(namespace + "_exporter"))
}

func main() {
	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9219").String()
		metricsPath   = kingpin.Flag("web.metrics-path", "Path under which to expose metrics").Default("/metrics").String()
		probePath     = kingpin.Flag("web.probe-path", "Path under which to expose the probe endpoint").Default("/probe").String()
		insecure      = kingpin.Flag("tls.insecure", "Skip certificate verification").Default("false").Bool()
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print(namespace + "_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infoln("Starting " + namespace + "_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc(*probePath, func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, *insecure)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
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