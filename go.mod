module github.com/ribbybibby/ssl_exporter

require (
	github.com/bmatcuk/doublestar/v2 v2.0.3
	github.com/go-kit/log v0.1.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.29.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.0.0-00010101000000-000000000000
)

replace (
	k8s.io/api => k8s.io/api v0.19.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.3
	k8s.io/client-go => k8s.io/client-go v0.19.3
)

go 1.15
