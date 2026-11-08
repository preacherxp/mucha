package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	scopeStrict      = "strict"
	scopeNamespace   = "namespace-wide"
	scopeCluster     = "cluster-wide"
	annNamespaceWide = "sealedsecrets.bitnami.com/namespace-wide"
	annClusterWide   = "sealedsecrets.bitnami.com/cluster-wide"
	maxSecretBytes   = 1 << 20
)

var (
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	secretKey    = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
	requiredKeys = map[string][]string{
		"kubernetes.io/tls":              {"tls.crt", "tls.key"},
		"kubernetes.io/dockerconfigjson": {".dockerconfigjson"},
		"kubernetes.io/ssh-auth":         {"ssh-privatekey"},
	}
)

type meta struct {
	Name        string            `yaml:"name,omitempty" json:"name"`
	Namespace   string            `yaml:"namespace,omitempty" json:"namespace"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

type template struct {
	Metadata meta   `yaml:"metadata"`
	Type     string `yaml:"type,omitempty"`
}

type sealedSecret struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   meta   `yaml:"metadata"`
	Spec       struct {
		EncryptedData map[string]string `yaml:"encryptedData"`
		Template      template          `yaml:"template"`
	} `yaml:"spec"`
}

// form is the secret as edited in the UI. Data holds base64 plaintext; Sealed holds
// ciphertext kept from an imported SealedSecret (kubeseal --merge-into).
type form struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Scope       string            `json:"scope"`
	Type        string            `json:"type"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Data        map[string]string `json:"data"`
	Sealed      map[string]string `json:"sealed"`
}

type certInfo struct {
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
}

func parseCert(certPEM string) (*rsa.PublicKey, certInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, certInfo{}, errors.New("not a PEM certificate: expected a block starting with -----BEGIN CERTIFICATE-----")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, certInfo{}, fmt.Errorf("unreadable certificate: %w", err)
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, certInfo{}, errors.New("certificate does not hold an RSA key, which sealed-secrets requires")
	}
	sum := sha256.Sum256(block.Bytes)
	return pub, certInfo{Subject: c.Subject.String(), NotAfter: c.NotAfter, Fingerprint: hex.EncodeToString(sum[:])}, nil
}

// encryptionLabel binds ciphertext to its scope, exactly like sealed-secrets' EncryptionLabel.
func encryptionLabel(scope, namespace, name string) []byte {
	switch scope {
	case scopeCluster:
		return nil
	case scopeNamespace:
		return []byte(namespace)
	default:
		return []byte(namespace + "/" + name)
	}
}

// hybridEncrypt matches sealed-secrets' crypto.HybridEncrypt: RSA-OAEP(SHA-256) wraps a random
// AES-256 key, AES-GCM with a zero nonce (safe: the key is single use) seals the payload.
func hybridEncrypt(pub *rsa.PublicKey, plaintext, label []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, label)
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(wrapped)))
	out = append(out, wrapped...)
	return gcm.Seal(out, make([]byte, gcm.NonceSize()), plaintext, nil), nil
}

func validate(f form) []string {
	var errs []string
	if !slices.Contains([]string{scopeStrict, scopeNamespace, scopeCluster}, f.Scope) {
		errs = append(errs, "scope must be strict, namespace-wide or cluster-wide")
	}
	if f.Name == "" {
		errs = append(errs, "name is required")
	} else if len(f.Name) > 253 || !dnsSubdomain.MatchString(f.Name) {
		errs = append(errs, "name may only use lowercase letters, digits, '-' and '.', and must start and end with a letter or digit")
	}
	if f.Namespace == "" {
		if f.Scope != scopeCluster {
			errs = append(errs, "namespace is required unless the scope is cluster-wide")
		}
	} else if len(f.Namespace) > 63 || !dnsLabel.MatchString(f.Namespace) {
		errs = append(errs, "namespace may only use lowercase letters, digits and '-', at most 63 characters")
	}
	if len(f.Data)+len(f.Sealed) == 0 {
		errs = append(errs, "add at least one key")
	}
	size := 0
	for _, k := range slices.Sorted(maps.Keys(f.Data)) {
		plain, err := base64.StdEncoding.DecodeString(f.Data[k])
		if err != nil {
			errs = append(errs, fmt.Sprintf("value of %q is not valid base64", k))
		} else if len(plain) == 0 {
			errs = append(errs, fmt.Sprintf("value of %q is empty", k))
		}
		size += len(plain)
		if k == ".dockerconfigjson" && !json.Valid(plain) {
			errs = append(errs, "value of .dockerconfigjson is not valid JSON")
		}
	}
	if size > maxSecretBytes {
		errs = append(errs, "values add up to more than 1 MiB, the Kubernetes secret limit")
	}
	all := slices.Concat(slices.Collect(maps.Keys(f.Data)), slices.Collect(maps.Keys(f.Sealed)))
	slices.Sort(all)
	for _, k := range slices.Compact(all) {
		if len(k) > 253 || !secretKey.MatchString(k) {
			errs = append(errs, fmt.Sprintf("key %q may only use letters, digits, '-', '_' and '.'", k))
		}
	}
	for _, k := range requiredKeys[f.Type] {
		if !slices.Contains(all, k) {
			errs = append(errs, fmt.Sprintf("type %s needs a %q key", f.Type, k))
		}
	}
	return errs
}

func scopeAnnotations(base map[string]string, scope string) map[string]string {
	out := maps.Clone(base)
	if out == nil {
		out = map[string]string{}
	}
	delete(out, annNamespaceWide)
	delete(out, annClusterWide)
	switch scope {
	case scopeNamespace:
		out[annNamespaceWide] = "true"
	case scopeCluster:
		out[annClusterWide] = "true"
	}
	return out
}

func seal(certPEM string, f form) ([]byte, error) {
	if errs := validate(f); len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	pub, info, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	if time.Now().After(info.NotAfter) {
		return nil, fmt.Errorf("certificate expired on %s; fetch the current one from the cluster", info.NotAfter.Format("2 January 2006"))
	}
	var ss sealedSecret
	ss.APIVersion, ss.Kind = "bitnami.com/v1alpha1", "SealedSecret"
	ss.Metadata = meta{Name: f.Name, Namespace: f.Namespace, Annotations: scopeAnnotations(nil, f.Scope)}
	ss.Spec.Template = template{
		Metadata: meta{Name: f.Name, Namespace: f.Namespace, Labels: f.Labels, Annotations: scopeAnnotations(f.Annotations, f.Scope)},
		Type:     f.Type,
	}
	ss.Spec.EncryptedData = maps.Clone(f.Sealed)
	if ss.Spec.EncryptedData == nil {
		ss.Spec.EncryptedData = map[string]string{}
	}
	label := encryptionLabel(f.Scope, f.Namespace, f.Name)
	for k, v := range f.Data {
		plain, _ := base64.StdEncoding.DecodeString(v) // validated above
		ct, err := hybridEncrypt(pub, plain, label)
		if err != nil {
			return nil, err
		}
		ss.Spec.EncryptedData[k] = base64.StdEncoding.EncodeToString(ct)
	}
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(ss); err != nil {
		return nil, err
	}
	return []byte(b.String()), enc.Close()
}

func scopeOf(annotations ...map[string]string) string {
	for _, a := range annotations {
		if a[annClusterWide] == "true" {
			return scopeCluster
		}
		if a[annNamespaceWide] == "true" {
			return scopeNamespace
		}
	}
	return scopeStrict
}

// maskedOriginal returns imported YAML that is safe to show by default. In a Secret every value
// outside the identifying fields is masked, including last-applied (it embeds the data) and comments
// (they can quote values). A SealedSecret only holds ciphertext, so it stays as it is.
func maskedOriginal(text, kind string) (string, error) {
	if kind != "Secret" {
		return text, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return "", err
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "apiVersion", "kind", "type":
		case "metadata":
			maskLastApplied(root.Content[i+1])
		default:
			maskValues(root.Content[i+1])
		}
	}
	stripComments(&doc)
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", err
	}
	return b.String(), enc.Close()
}

func maskValues(n *yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			maskValues(n.Content[i])
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			maskValues(c)
		}
	default: // fixed length, so the mask does not reveal how long a value is
		*n = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "••••••••"}
	}
}

func maskLastApplied(metadata *yaml.Node) {
	for i := 0; i+1 < len(metadata.Content); i += 2 {
		if metadata.Content[i].Value != "annotations" {
			continue
		}
		a := metadata.Content[i+1]
		for j := 0; j+1 < len(a.Content); j += 2 {
			if a.Content[j].Value == "kubectl.kubernetes.io/last-applied-configuration" {
				maskValues(a.Content[j+1])
			}
		}
	}
}

func stripComments(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		stripComments(c)
	}
}

// countDocs ignores empty documents, so a stray trailing "---" is not mistaken for a second one.
func countDocs(text string) (int, error) {
	dec := yaml.NewDecoder(strings.NewReader(text))
	count := 0
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return count, nil
		} else if err != nil {
			return 0, err
		}
		if len(doc.Content) > 0 && doc.Content[0].Tag != "!!null" {
			count++
		}
	}
}

// importDoc reads a Secret (to seal it) or a SealedSecret (to add or replace keys in it).
func importDoc(text string) (form, string, error) {
	n, err := countDocs(text)
	if err != nil {
		return form{}, "", fmt.Errorf("not valid YAML or JSON: %w", err)
	}
	if n > 1 {
		return form{}, "", fmt.Errorf("this file holds %d YAML documents; import one Secret or SealedSecret at a time", n)
	}
	var d struct {
		Kind       string            `yaml:"kind"`
		Metadata   meta              `yaml:"metadata"`
		Type       string            `yaml:"type"`
		Data       map[string]string `yaml:"data"`
		StringData map[string]string `yaml:"stringData"`
		Spec       struct {
			EncryptedData map[string]string `yaml:"encryptedData"`
			Template      template          `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(text), &d); err != nil {
		return form{}, "", fmt.Errorf("not valid YAML or JSON: %w", err)
	}
	switch d.Kind {
	case "Secret":
		f := form{Name: d.Metadata.Name, Namespace: d.Metadata.Namespace, Type: d.Type, Labels: d.Metadata.Labels,
			Scope: scopeOf(d.Metadata.Annotations), Data: map[string]string{}, Sealed: map[string]string{}}
		f.Annotations = scopeAnnotations(d.Metadata.Annotations, scopeStrict)
		delete(f.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
		for k, v := range d.Data {
			if _, err := base64.StdEncoding.DecodeString(v); err != nil {
				return form{}, "", fmt.Errorf("data.%s is not valid base64; put plain text under stringData instead", k)
			}
			f.Data[k] = v
		}
		for k, v := range d.StringData { // stringData wins, as in the API server
			f.Data[k] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		if f.Type == "" {
			f.Type = "Opaque"
		}
		return f, d.Kind, nil
	case "SealedSecret":
		t := d.Spec.Template
		f := form{Name: d.Metadata.Name, Namespace: d.Metadata.Namespace, Type: t.Type, Labels: t.Metadata.Labels,
			Scope: scopeOf(d.Metadata.Annotations, t.Metadata.Annotations), Data: map[string]string{}, Sealed: d.Spec.EncryptedData}
		f.Annotations = scopeAnnotations(t.Metadata.Annotations, scopeStrict)
		if f.Name == "" {
			f.Name, f.Namespace = t.Metadata.Name, t.Metadata.Namespace
		}
		if f.Sealed == nil {
			f.Sealed = map[string]string{}
		}
		return f, d.Kind, nil
	default:
		return form{}, "", fmt.Errorf("expected a Secret or SealedSecret, got kind %q", d.Kind)
	}
}
