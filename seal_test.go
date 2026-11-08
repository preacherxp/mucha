package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sealed-secret"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestSealRoundTripWithKubeseal(t *testing.T) {
	if _, err := exec.LookPath("kubeseal"); err != nil {
		t.Skip("kubeseal not installed")
	}
	key, cert := testCert(t)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)

	for _, scope := range []string{scopeStrict, scopeNamespace, scopeCluster} {
		f := form{Name: "db", Namespace: "prod", Scope: scope, Type: "Opaque",
			Data: map[string]string{"password": b64("hunter2\n")}}
		out, err := seal(cert, f)
		if err != nil {
			t.Fatal(scope, err)
		}
		cmd := exec.Command("kubeseal", "--recovery-unseal", "--recovery-private-key", keyFile, "-o", "yaml")
		cmd.Stdin = bytes.NewReader(out)
		plain, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: kubeseal could not unseal: %v\n%s\n%s", scope, err, plain, out)
		}
		if !strings.Contains(string(plain), "password: "+b64("hunter2\n")) {
			t.Fatalf("%s: unsealed secret lost the value:\n%s", scope, plain)
		}
	}
}

func TestScopeBindsName(t *testing.T) {
	// A strict value moved to another name must stop decrypting: the label is part of OAEP.
	key, cert := testCert(t)
	pub, _, _ := parseCert(cert)
	ct, _ := hybridEncrypt(pub, []byte("x"), encryptionLabel(scopeStrict, "prod", "db"))
	n := int(ct[0])<<8 | int(ct[1])
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, key, ct[2:2+n], []byte("prod/other")); err == nil {
		t.Fatal("strict ciphertext decrypted under another name")
	}
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, key, ct[2:2+n], []byte("prod/db")); err != nil {
		t.Fatal(err)
	}
}

func TestImportMergeKeepsSealedValues(t *testing.T) {
	_, cert := testCert(t)
	out, err := seal(cert, form{Name: "db", Namespace: "prod", Scope: scopeNamespace, Type: "Opaque",
		Labels: map[string]string{"app": "db"}, Data: map[string]string{"a": b64("1")}})
	if err != nil {
		t.Fatal(err)
	}
	f, kind, err := importDoc(string(out))
	if err != nil || kind != "SealedSecret" || f.Scope != scopeNamespace || f.Labels["app"] != "db" || len(f.Annotations) != 0 {
		t.Fatalf("bad import: %+v %s %v", f, kind, err)
	}
	f.Data = map[string]string{"b": b64("2")}
	merged, err := seal(cert, f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), f.Sealed["a"]) || !strings.Contains(string(merged), "\n    b: ") {
		t.Fatalf("merge lost a key:\n%s", merged)
	}
}

func TestImportSecret(t *testing.T) {
	f, _, err := importDoc("apiVersion: v1\nkind: Secret\nmetadata: {name: api, namespace: web}\ndata: {token: " + b64("t") + "}\nstringData: {user: bob}\n")
	if err != nil || f.Data["token"] != b64("t") || f.Data["user"] != b64("bob") || f.Type != "Opaque" || f.Scope != scopeStrict {
		t.Fatalf("%+v %v", f, err)
	}
	if _, _, err := importDoc("kind: Secret\ndata: {token: not base64!}\n"); err == nil {
		t.Fatal("accepted invalid base64")
	}
}

func TestImportDocumentCount(t *testing.T) {
	one := "kind: Secret\nmetadata: {name: a, namespace: b}\ndata: {k: " + b64("v") + "}\n"
	for name, doc := range map[string]string{
		"plain":            one,
		"leading marker":   "---\n" + one,
		"trailing marker":  one + "---\n",
		"trailing comment": one + "---\n# end of file\n",
	} {
		if _, _, err := importDoc(doc); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"two secrets":          one + "---\n" + one,
		"secret and configmap": one + "---\nkind: ConfigMap\n",
		"broken second doc":    one + "---\nkey: [unclosed\n",
	} {
		if _, _, err := importDoc(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMaskedOriginalHidesValues(t *testing.T) {
	docs := map[string]string{
		"yaml": `# old password was comment-leak
apiVersion: v1
kind: Secret
metadata:
  name: api
  namespace: web
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"data":{"token":"annotation-leak"}}'
type: Opaque
data:
  token: leakleak # inline-leak
stringData:
  note: |
    multi-line-leak
extra:
  field: unknown-field-leak
  list: [flow-leak]
`,
		"json": `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"api"},"data":{"token":"leakleak"}}`,
	}
	for name, doc := range docs {
		_, kind, err := importDoc(doc)
		if err != nil {
			t.Fatal(name, err)
		}
		out, err := maskedOriginal(doc, kind)
		if err != nil {
			t.Fatal(name, err)
		}
		if strings.Contains(out, "leak") {
			t.Errorf("%s: a value survived masking:\n%s", name, out)
		}
		for _, want := range []string{"api", "token", "••••••••"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: masking lost %q:\n%s", name, want, out)
			}
		}
	}
	sealed := "kind: SealedSecret\nspec: {encryptedData: {a: ciphertext}}\n"
	if out, _ := maskedOriginal(sealed, "SealedSecret"); out != sealed {
		t.Errorf("SealedSecret was altered: %s", out)
	}
}

func TestValidate(t *testing.T) {
	ok := form{Name: "db", Namespace: "prod", Scope: scopeStrict, Type: "Opaque", Data: map[string]string{"k": b64("v")}}
	if errs := validate(ok); len(errs) != 0 {
		t.Fatal(errs)
	}
	bad := map[string]func(*form){
		"uppercase name":  func(f *form) { f.Name = "DB" },
		"no namespace":    func(f *form) { f.Namespace = "" },
		"bad key":         func(f *form) { f.Data = map[string]string{"a key": b64("v")} },
		"no keys":         func(f *form) { f.Data = nil },
		"empty value":     func(f *form) { f.Data = map[string]string{"k": ""} },
		"tls missing key": func(f *form) { f.Type = "kubernetes.io/tls"; f.Data = map[string]string{"tls.crt": b64("c")} },
		"bad docker json": func(f *form) {
			f.Type = "kubernetes.io/dockerconfigjson"
			f.Data = map[string]string{".dockerconfigjson": b64("{")}
		},
		"bad scope": func(f *form) { f.Scope = "global" },
	}
	for name, mutate := range bad {
		f := ok
		mutate(&f)
		if len(validate(f)) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	cluster := ok
	cluster.Scope, cluster.Namespace = scopeCluster, ""
	if errs := validate(cluster); len(errs) != 0 {
		t.Fatal("cluster-wide without namespace rejected:", errs)
	}
}
