package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/ribbybibby/ssl_exporter/config"
	"github.com/ribbybibby/ssl_exporter/prober"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	namespace = "ssl"
)

func probeHandler(w http.ResponseWriter, r *http.Request, conf *config.Config, defaultMod *string, targetCli *string) {
	moduleName := r.URL.Query().Get("module")

	if moduleName == "" {
		moduleName = defaultMod
	}

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

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	target := r.URL.Query().Get("target")

	if target == "" {
		target = targetCli
	}

	if target == "" {
		http.Error(w, "Target parameter is missing", http.StatusBadRequest)
		return
	}

	probeFunc, ok := prober.Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}

	var (
		probeSuccess = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "probe_success"),
				Help: "If the probe was a success",
			},
		)
		proberType = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "prober"),
				Help: "The prober used by the exporter to connect to the target",
			},
			[]string{"prober"},
		)
	)

	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccess, proberType)
	proberType.WithLabelValues(module.Prober).Set(1)

	err := probeFunc(ctx, target, module, registry)
	if err != nil {
		log.Errorf("error=%s target=%s prober=%s timeout=%s", err, target, module.Prober, timeout)
		probeSuccess.Set(0)
	} else {
		probeSuccess.Set(1)
	}

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
		defaultMod    = kingpin.Flag("web.probe-path", "Path under which to expose the probe endpoint").Default("").String()
		target        = kingpin.Flag("web.probe-path", "Path under which to expose the probe endpoint").Default("").String()
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
		probeHandler(w, r, conf, *defaultMod, *target)
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
