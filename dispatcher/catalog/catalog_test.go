package catalog

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	digest1 = "1111111111111111111111111111111111111111111111111111111111111111"
	digest2 = "2222222222222222222222222222222222222222222222222222222222222222"

	dockerImage = "registry.example.com/docker-runner:1@sha256:" + digest1
	lightImage  = "registry.example.com/light-runner:1@sha256:" + digest1
	publicImage = "registry.example.com/public-runner:1@sha256:" + digest1
	extraImage  = "registry.example.com/extra-runner:1@sha256:" + digest1
	repoImage   = "registry.example.com/repo-runner:1@sha256:" + digest1
	imgImage    = "registry.example.com/img-runner:1@sha256:" + digest2
)

// validCatalog construit un catalogue valide minimal, puis modifié cas par cas.
func validCatalog() string {
	return fmt.Sprintf(`
github:
  owner: example-owner
  auth:
    type: pat
    secretRef: {name: github-pat-runners, key: github_token}
discovery: {enabled: false}
runtime:
  namespace: ci-runners
  claimURL: http://claim.example.com
  forbiddenPublicNodes: []
caches:
  language:
    type: language
    hostPath: /var/lib/runner-cache
  proxies-public:
    type: proxies
profiles:
  docker:
    template: docker
    image: %s
    dind:
      image: registry.example.com/dind:v1.0.0
    nodes: [node-a, node-b]
  light:
    template: light
    image: %s
    nodes: [node-a]
  public:
    template: light
    image: %s
    nodes: [node-a]
    trust: public
    caches: [proxies-public]
  extra:
    template: light
    image: %s
    nodes: [node-a]
defaults:
  profiles: [docker]
  maxRunners: 6
repos:
  demo:
    profiles: [docker, light]
    image: %s
    nodes: [repo-node-a]
  case-repo:
    fileNames:
      docker: CustomName
  add-nodes:
    profiles: [docker]
    nodes: ["+node-c"]
  replace-nodes:
    profiles: [docker]
    nodes: [node-z]
  public-repo:
    profiles: [docker]
  plain:
    profiles: [docker, extra]
  res:
    profiles: [docker]
    resources:
      limits:
        memory: 8Gi
  img:
    profiles: [docker]
    image: %s
fileNames:
  docker: runner-{repo}
  light: runner-{repo}-light
  "*": runner-{repo}-{profile}
capacity:
  enforce: false
  nodes:
    node-a: 4
`, dockerImage, lightImage, publicImage, extraImage, repoImage, imgImage)
}

func mustParse(t *testing.T, src string) *Catalog {
	t.Helper()
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse a échoué : %v", err)
	}
	return c
}

func replaceOnce(t *testing.T, src, old, new string) string {
	t.Helper()
	if strings.Count(src, old) != 1 {
		t.Fatalf("motif à remplacer non unique ou absent : %q", old)
	}
	return strings.Replace(src, old, new, 1)
}

func queueByName(t *testing.T, queues []Queue, name string) Queue {
	t.Helper()
	for _, q := range queues {
		if q.Name == name {
			return q
		}
	}
	t.Fatalf("file %q introuvable", name)
	return Queue{}
}

func TestParseValide(t *testing.T) {
	mustParse(t, validCatalog())
}

func TestParseRefus(t *testing.T) {
	tests := []struct {
		nom      string
		modifier func(t *testing.T, src string) string
	}{
		{
			nom: "image de profil non épinglée",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "image: "+dockerImage, "image: registry.example.com/runner:1")
			},
		},
		{
			nom: "image de surcharge de dépôt non épinglée",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "image: "+repoImage, "image: registry.example.com/runner:1")
			},
		},
		{
			nom: "nom de dépôt invalide avec slash",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "  demo:", "  bad/name:")
			},
		},
		{
			nom: "nom de dépôt invalide avec espace",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "  demo:", "  \"bad name\":")
			},
		},
		{
			nom: "profil inconnu dans repos.profiles",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "    profiles: [docker, light]", "    profiles: [docker, unknown]")
			},
		},
		{
			nom: "profil inconnu dans defaults.profiles",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "defaults:\n  profiles: [docker]", "defaults:\n  profiles: [unknown]")
			},
		},
		{
			nom: "clé inconnue dans un profil",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "  light:\n    template: light", "  light:\n    foo: 1\n    template: light")
			},
		},
		{
			nom: "profil public avec cache language",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "    caches: [proxies-public]", "    caches: [language]")
			},
		},
		{
			nom: "profil public sur nœud interdit",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "  forbiddenPublicNodes: []", "  forbiddenPublicNodes: [node-a]")
			},
		},
		{
			nom: "profil public avec dockerConfigSecret",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "    trust: public", "    trust: public\n    dockerConfigSecret: registry-creds")
			},
		},
		{
			nom: "surcharge nodes mélangeant +node et node",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "    nodes: [repo-node-a]", "    nodes: [\"+node-c\", node-z]")
			},
		},
		{
			nom: "nom de file dupliqué",
			modifier: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "  case-repo:\n    fileNames:\n      docker: CustomName", "  case-repo:\n    fileNames:\n      docker: CustomName\n  dup-repo:\n    fileNames:\n      docker: CustomName")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.nom, func(t *testing.T) {
			src := tt.modifier(t, validCatalog())
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatalf("Parse aurait dû refuser le catalogue")
			}
		})
	}
}

func TestResolveNomsDeFile(t *testing.T) {
	c := mustParse(t, validCatalog())
	queues, err := c.Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve a échoué : %v", err)
	}

	t.Run("motif par profil", func(t *testing.T) {
		q := queueByName(t, queues, "runner-demo")
		if q.Repo != "demo" {
			t.Errorf("Repo = %q, attendu demo", q.Repo)
		}
		if q.RequestedProfile != "docker" {
			t.Errorf("RequestedProfile = %q, attendu docker", q.RequestedProfile)
		}
	})

	t.Run("motif light", func(t *testing.T) {
		q := queueByName(t, queues, "runner-demo-light")
		if q.RequestedProfile != "light" {
			t.Errorf("RequestedProfile = %q, attendu light", q.RequestedProfile)
		}
	})

	t.Run("motif étoile", func(t *testing.T) {
		q := queueByName(t, queues, "runner-plain-extra")
		if q.RequestedProfile != "extra" {
			t.Errorf("RequestedProfile = %q, attendu extra", q.RequestedProfile)
		}
	})

	t.Run("surcharge fileNames exacte", func(t *testing.T) {
		q := queueByName(t, queues, "CustomName")
		if q.Repo != "case-repo" {
			t.Errorf("Repo = %q, attendu case-repo", q.Repo)
		}
		if q.RequestedProfile != "docker" {
			t.Errorf("RequestedProfile = %q, attendu docker", q.RequestedProfile)
		}
	})
}

func TestResolveSurchargeNodes(t *testing.T) {
	c := mustParse(t, validCatalog())
	queues, err := c.Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve a échoué : %v", err)
	}

	t.Run("ajout de nœud", func(t *testing.T) {
		q := queueByName(t, queues, "runner-add-nodes")
		for _, n := range []string{"node-a", "node-b", "node-c"} {
			if !slices.Contains(q.Spec.Nodes, n) {
				t.Errorf("Spec.Nodes = %v, devrait contenir %q", q.Spec.Nodes, n)
			}
		}
	})

	t.Run("remplacement de nœuds", func(t *testing.T) {
		q := queueByName(t, queues, "runner-replace-nodes")
		if !reflect.DeepEqual(q.Spec.Nodes, []string{"node-z"}) {
			t.Errorf("Spec.Nodes = %v, attendu [node-z]", q.Spec.Nodes)
		}
	})
}

func TestResolveDépôtPublic(t *testing.T) {
	t.Run("GitHub prime sur une visibilité privée périmée", func(t *testing.T) {
		src := replaceOnce(t, validCatalog(), "  public-repo:\n    profiles: [docker]", "  public-repo:\n    profiles: [docker]\n    visibility: private")
		c := mustParse(t, src)
		queues, err := c.Resolve(func(repo string) (bool, error) { return repo == "public-repo", nil })
		if err != nil {
			t.Fatal(err)
		}
		if q := queueByName(t, queues, "runner-public-repo"); q.Trust != TrustPublic {
			t.Fatalf("public repository received trust %q", q.Trust)
		}
	})
	t.Run("via fonction Visibility", func(t *testing.T) {
		c := mustParse(t, validCatalog())
		visibility := func(repo string) (bool, error) {
			return repo == "public-repo", nil
		}
		queues, err := c.Resolve(visibility)
		if err != nil {
			t.Fatalf("Resolve a échoué : %v", err)
		}
		q := queueByName(t, queues, "runner-public-repo")
		if q.Name != "runner-public-repo" {
			t.Errorf("Name = %q, attendu runner-public-repo", q.Name)
		}
		if q.RequestedProfile != "docker" {
			t.Errorf("RequestedProfile = %q, attendu docker", q.RequestedProfile)
		}
		if q.Profile != "public" {
			t.Errorf("Profile = %q, attendu public", q.Profile)
		}
		if q.Trust != TrustPublic {
			t.Errorf("Trust = %q, attendu public", q.Trust)
		}
	})

	t.Run("via visibility dans le catalogue", func(t *testing.T) {
		src := replaceOnce(t, validCatalog(), "  public-repo:\n    profiles: [docker]", "  public-repo:\n    profiles: [docker]\n    visibility: public")
		c := mustParse(t, src)
		queues, err := c.Resolve(nil)
		if err != nil {
			t.Fatalf("Resolve a échoué : %v", err)
		}
		q := queueByName(t, queues, "runner-public-repo")
		if q.Profile != "public" {
			t.Errorf("Profile = %q, attendu public", q.Profile)
		}
		if q.Trust != TrustPublic {
			t.Errorf("Trust = %q, attendu public", q.Trust)
		}
	})
}

func TestResolvePublicSansProfilPublic(t *testing.T) {
	src := replaceOnce(t, validCatalog(), "defaults:\n  profiles: [docker]\n  maxRunners: 6", "defaults:\n  profiles: [docker]\n  maxRunners: 6\n  publicProfile: absent")
	c := mustParse(t, src)
	visibility := func(repo string) (bool, error) {
		return repo == "public-repo", nil
	}
	if _, err := c.Resolve(visibility); err == nil {
		t.Fatalf("Resolve aurait dû refuser un dépôt public sans profil public")
	}
}

func TestResolveErreurVisibility(t *testing.T) {
	c := mustParse(t, validCatalog())
	visibility := func(repo string) (bool, error) {
		if repo == "public-repo" {
			return false, errors.New("erreur visibility")
		}
		return false, nil
	}
	if _, err := c.Resolve(visibility); err == nil {
		t.Fatalf("Resolve aurait dû propager l'erreur de Visibility")
	}
}

func TestWarmCompatible(t *testing.T) {
	c := mustParse(t, validCatalog())
	queues, err := c.Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve a échoué : %v", err)
	}

	t.Run("sans surcharge", func(t *testing.T) {
		q := queueByName(t, queues, "runner-plain")
		if !c.WarmCompatible(q) {
			t.Errorf("WarmCompatible = false, attendu true")
		}
	})

	t.Run("surcharge nodes ignorée", func(t *testing.T) {
		q := queueByName(t, queues, "runner-add-nodes")
		if !c.WarmCompatible(q) {
			t.Errorf("WarmCompatible = false, attendu true")
		}
	})

	t.Run("surcharge resources", func(t *testing.T) {
		q := queueByName(t, queues, "runner-res")
		if c.WarmCompatible(q) {
			t.Errorf("WarmCompatible = true, attendu false")
		}
	})

	t.Run("surcharge image", func(t *testing.T) {
		q := queueByName(t, queues, "runner-img")
		if c.WarmCompatible(q) {
			t.Errorf("WarmCompatible = true, attendu false")
		}
	})
}
