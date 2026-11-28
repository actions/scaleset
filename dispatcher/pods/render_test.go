package pods

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/actions/scaleset/dispatcher/catalog"
)

var agentImage = "registry.example.com/ci-dispatcher@sha256:" + strings.Repeat("3", 64)

func loadCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()

	cat, err := catalog.Load("testdata/catalog.yaml")
	if err != nil {
		t.Fatalf("chargement du catalogue : %v", err)
	}
	return cat
}

func resolveQueues(t *testing.T, cat *catalog.Catalog) []catalog.Queue {
	t.Helper()

	queues, err := cat.Resolve(nil)
	if err != nil {
		t.Fatalf("résolution du catalogue : %v", err)
	}
	return queues
}

func newRenderer(t *testing.T, cat *catalog.Catalog) *Renderer {
	t.Helper()

	r, err := NewRenderer(cat.Templates)
	if err != nil {
		t.Fatalf("création du renderer : %v", err)
	}
	return r
}

func requestForQueue(cat *catalog.Catalog, q catalog.Queue) Request {
	return Request{
		Name:       "ci-" + q.Profile + "-xxxxx",
		Namespace:  cat.Runtime.Namespace,
		Queue:      &q,
		Profile:    q.Profile,
		Spec:       q.Spec,
		ScaleSetID: 1,
		ClaimURL:   cat.Runtime.ClaimURL,
		AgentImage: agentImage,
		Labels:     Labels{Prefix: cat.Runtime.LabelPrefix},
	}
}

func warmRequestForProfile(cat *catalog.Catalog, profile string) Request {
	return Request{
		Name:       "ci-" + profile + "-warm-xxxxx",
		Namespace:  cat.Runtime.Namespace,
		Queue:      nil,
		Profile:    profile,
		Spec:       cat.ProfileSpec(profile),
		ScaleSetID: 1,
		ClaimURL:   cat.Runtime.ClaimURL,
		AgentImage: agentImage,
		Labels:     Labels{Prefix: cat.Runtime.LabelPrefix},
	}
}

func findQueue(t *testing.T, queues []catalog.Queue, name string) catalog.Queue {
	t.Helper()

	for _, q := range queues {
		if q.Name == name {
			return q
		}
	}
	t.Fatalf("file %q absente du catalogue résolu", name)
	return catalog.Queue{}
}

func compareGolden(t *testing.T, got []byte, path string) {
	t.Helper()

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture du golden %s : %v", path, err)
	}
	if bytes.Equal(got, want) {
		return
	}

	gotLines := bytes.Split(got, []byte("\n"))
	wantLines := bytes.Split(want, []byte("\n"))

	for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
		if !bytes.Equal(gotLines[i], wantLines[i]) {
			t.Fatalf(
				"golden %s : première ligne différente à la ligne %d\nobtenu : %q\nattendu : %q",
				path,
				i+1,
				gotLines[i],
				wantLines[i],
			)
		}
	}

	if len(gotLines) != len(wantLines) {
		t.Fatalf(
			"golden %s : nombre de lignes différent (obtenu %d, attendu %d)",
			path,
			len(gotLines),
			len(wantLines),
		)
	}

	t.Fatalf("golden %s : contenu différent sans première ligne identifiable", path)
}

func containerByName(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	return nil
}

func initContainerByName(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return &pod.Spec.InitContainers[i]
		}
	}
	return nil
}

func volumeByName(pod *corev1.Pod, name string) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			return &pod.Spec.Volumes[i]
		}
	}
	return nil
}

func tokenVolume(pod *corev1.Pod) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Projected == nil {
			continue
		}
		for _, s := range v.Projected.Sources {
			if s.ServiceAccountToken != nil && s.ServiceAccountToken.Audience == ClaimAudience {
				return v
			}
		}
	}
	return nil
}

func volumeMountByName(c *corev1.Container, name string) *corev1.VolumeMount {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == name {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}

func volumeMountByPath(c *corev1.Container, path string) *corev1.VolumeMount {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].MountPath == path {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}

func envValue(c *corev1.Container, name string) (string, bool) {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value, true
		}
	}
	return "", false
}

func containsString(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}

func requiredAffinityValues(t *testing.T, pod *corev1.Pod) []string {
	t.Helper()

	if pod.Spec.Affinity == nil ||
		pod.Spec.Affinity.NodeAffinity == nil ||
		pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		t.Fatalf("affinité requise absente")
	}

	var values []string
	terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	for _, term := range terms {
		for _, expr := range term.MatchExpressions {
			values = append(values, expr.Values...)
		}
	}
	return values
}

func TestRenduGolden(t *testing.T) {
	cat := loadCatalog(t)
	queues := resolveQueues(t, cat)
	r := newRenderer(t, cat)

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("lecture du répertoire testdata : %v", err)
	}

	trouves := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".golden.yaml") {
			continue
		}

		queueName := strings.TrimSuffix(fileName, ".golden.yaml")
		trouves++

		t.Run(queueName, func(t *testing.T) {
			q := findQueue(t, queues, queueName)
			req := requestForQueue(cat, q)

			got, err := r.RenderYAML(req)
			if err != nil {
				t.Fatalf("rendu YAML de la file %s : %v", q.Name, err)
			}
			compareGolden(t, got, "testdata/"+fileName)
		})
	}

	if trouves == 0 {
		t.Fatalf("aucun fichier golden trouvé dans testdata")
	}
}

func TestInvariantsDeBase(t *testing.T) {
	cat := loadCatalog(t)
	queues := resolveQueues(t, cat)
	q := findQueue(t, queues, "runner-demo")
	req := requestForQueue(cat, q)

	pod, err := newRenderer(t, cat).Render(req)
	if err != nil {
		t.Fatalf("rendu de la file %s : %v", q.Name, err)
	}

	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("restartPolicy = %q, attendu %q", pod.Spec.RestartPolicy, corev1.RestartPolicyNever)
	}
	if pod.Spec.AutomountServiceAccountToken == nil {
		t.Fatalf("automountServiceAccountToken est nil, attendu un pointeur vers false")
	}
	if *pod.Spec.AutomountServiceAccountToken != false {
		t.Fatalf("automountServiceAccountToken = %v, attendu false", *pod.Spec.AutomountServiceAccountToken)
	}

	if len(pod.Spec.InitContainers) == 0 {
		t.Fatalf("aucun init container")
	}
	firstInit := pod.Spec.InitContainers[0]
	if firstInit.Name != AgentInitContainer {
		t.Fatalf("premier init container = %q, attendu %q", firstInit.Name, AgentInitContainer)
	}
	if firstInit.Image != req.AgentImage {
		t.Fatalf("image du premier init container = %q, attendu %q", firstInit.Image, req.AgentImage)
	}

	tv := tokenVolume(pod)
	if tv == nil {
		t.Fatalf("aucun volume projeté portant un jeton d'audience %q", ClaimAudience)
	}
	if len(tv.Projected.Sources) == 0 {
		t.Fatalf("le volume projeté %q n'a aucune source", tv.Name)
	}
	token := tv.Projected.Sources[0].ServiceAccountToken
	if token == nil {
		t.Fatalf("le volume projeté %q ne contient pas de jeton de compte de service", tv.Name)
	}
	if token.Audience != ClaimAudience {
		t.Fatalf("audience du jeton = %q, attendu %q", token.Audience, ClaimAudience)
	}

	runner := containerByName(pod, RunnerContainer)
	if runner == nil {
		t.Fatalf("conteneur %q absent", RunnerContainer)
	}
	mount := volumeMountByName(runner, tv.Name)
	if mount == nil {
		t.Fatalf("le conteneur %q ne monte pas le volume %q", RunnerContainer, tv.Name)
	}
	if mount.MountPath != AudienceMountDir {
		t.Fatalf("montage du jeton = %q, attendu %q", mount.MountPath, AudienceMountDir)
	}
	if !mount.ReadOnly {
		t.Fatalf("montage du jeton n'est pas en lecture seule")
	}
	if len(runner.Command) == 0 || runner.Command[0] != AgentBinary {
		t.Fatalf("commande du conteneur %q = %v, attendu %q en premier", RunnerContainer, runner.Command, AgentBinary)
	}
}

func TestLabels(t *testing.T) {
	cat := loadCatalog(t)
	queues := resolveQueues(t, cat)
	q := findQueue(t, queues, "runner-demo")
	req := requestForQueue(cat, q)

	pod, err := newRenderer(t, cat).Render(req)
	if err != nil {
		t.Fatalf("rendu de la file %s : %v", q.Name, err)
	}

	labels := req.Labels
	if got := pod.Labels[LabelManagedBy]; got != ManagedByValue {
		t.Fatalf("label %s = %q, attendu %q", LabelManagedBy, got, ManagedByValue)
	}
	if got := pod.Labels[LabelComponent]; got != ComponentRunner {
		t.Fatalf("label %s = %q, attendu %q", LabelComponent, got, ComponentRunner)
	}
	if got := pod.Labels[LabelARCRepository]; got != q.Repo {
		t.Fatalf("label %s = %q, attendu %q", LabelARCRepository, got, q.Repo)
	}
	if got := pod.Labels[labels.Repo()]; got != q.Repo {
		t.Fatalf("label %s = %q, attendu %q", labels.Repo(), got, q.Repo)
	}
	if got := pod.Labels[labels.State()]; got != StateAssigned {
		t.Fatalf("label %s = %q, attendu %q", labels.State(), got, StateAssigned)
	}

	warmReq := warmRequestForProfile(cat, q.Profile)
	warmPod, err := newRenderer(t, cat).Render(warmReq)
	if err != nil {
		t.Fatalf("rendu du pod de réserve du profil %s : %v", q.Profile, err)
	}
	if got := warmPod.Labels[warmReq.Labels.State()]; got != StateWarm {
		t.Fatalf("label %s du pod de réserve = %q, attendu %q", warmReq.Labels.State(), got, StateWarm)
	}
	if _, ok := warmPod.Labels[warmReq.Labels.Repo()]; ok {
		t.Fatalf("le pod de réserve porte un label de dépôt %q", warmReq.Labels.Repo())
	}
	if _, ok := warmPod.Labels[LabelARCRepository]; ok {
		t.Fatalf("le pod de réserve porte un label de dépôt %q", LabelARCRepository)
	}
}

func TestPodDeReserveDocker(t *testing.T) {
	cat := loadCatalog(t)
	req := warmRequestForProfile(cat, "docker")

	pod, err := newRenderer(t, cat).Render(req)
	if err != nil {
		t.Fatalf("rendu du pod de réserve docker : %v", err)
	}

	if initContainerByName(pod, "prepare-nfs-language-caches") != nil {
		t.Fatalf("le pod de réserve docker contient un init container prepare-nfs-language-caches")
	}

	runner := containerByName(pod, RunnerContainer)
	if runner == nil {
		t.Fatalf("conteneur %q absent", RunnerContainer)
	}
	if mount := volumeMountByPath(runner, "/mnt/language-cache"); mount == nil {
		t.Fatalf("le conteneur %q ne monte pas le cache sur %q", RunnerContainer, "/mnt/language-cache")
	}
}

func TestSurchargeNodes(t *testing.T) {
	cat := loadCatalog(t)
	queues := resolveQueues(t, cat)
	q := findQueue(t, queues, "runner-demo")
	req := requestForQueue(cat, q)
	req.Nodes = []string{"node-b"}

	pod, err := newRenderer(t, cat).Render(req)
	if err != nil {
		t.Fatalf("rendu de la file %s avec Nodes : %v", q.Name, err)
	}

	values := requiredAffinityValues(t, pod)
	if !reflect.DeepEqual(values, []string{"node-b"}) {
		t.Fatalf("affinité requise = %v, attendu %v", values, []string{"node-b"})
	}
}

func TestCacheProfileLocal(t *testing.T) {
	cat := loadCatalog(t)

	repo, ok := cat.Repos["demo"]
	if !ok {
		t.Fatalf("dépôt demo absent du catalogue")
	}
	repo.CacheProfile = catalog.CacheProfileLocal

	queues := resolveQueues(t, cat)
	q := findQueue(t, queues, "runner-demo")
	req := requestForQueue(cat, q)

	pod, err := newRenderer(t, cat).Render(req)
	if err != nil {
		t.Fatalf("rendu de la file %s avec cacheProfile local : %v", q.Name, err)
	}

	runner := containerByName(pod, RunnerContainer)
	if runner == nil {
		t.Fatalf("conteneur %q absent", RunnerContainer)
	}
	value, ok := envValue(runner, "GOCACHE")
	if !ok {
		t.Fatalf("variable GOCACHE absente du conteneur %q", RunnerContainer)
	}
	if value != "/local-cache/go-build" {
		t.Fatalf("GOCACHE = %q, attendu %q", value, "/local-cache/go-build")
	}
}

func TestPodPublic(t *testing.T) {
	cat := loadCatalog(t)
	queues := resolveQueues(t, cat)
	q := findQueue(t, queues, "runner-OpenTool")
	req := requestForQueue(cat, q)

	pod, err := newRenderer(t, cat).Render(req)
	if err != nil {
		t.Fatalf("rendu du pod public %s : %v", q.Name, err)
	}

	if volumeByName(pod, "docker-config-secret") != nil {
		t.Fatalf("le pod public contient un volume docker-config-secret")
	}
	if volumeByName(pod, "language-cache") != nil {
		t.Fatalf("le pod public contient un volume language-cache")
	}

	values := requiredAffinityValues(t, pod)
	if containsString(values, "node-cp") {
		t.Fatalf("l'affinité requise du pod public contient node-cp : %v", values)
	}
}

func TestGabaritsPersonnalisesInvalides(t *testing.T) {
	cat := loadCatalog(t)

	deuxConteneurs := `apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: test
spec:
  containers:
  - name: runner
    image: busybox
  - name: sidecar
    image: busybox
`

	r, err := NewRenderer(map[string]string{"deux-conteneurs": deuxConteneurs})
	if err != nil {
		t.Fatalf("création du renderer personnalisé : %v", err)
	}

	req := Request{
		Name:       "ci-custom-xxxxx",
		Namespace:  cat.Runtime.Namespace,
		Profile:    "custom",
		Spec:       catalog.PodSpec{Template: "deux-conteneurs"},
		ScaleSetID: 1,
		ClaimURL:   cat.Runtime.ClaimURL,
		AgentImage: agentImage,
		Labels:     Labels{Prefix: cat.Runtime.LabelPrefix},
	}

	if _, err := r.Render(req); err == nil {
		t.Fatalf("un gabarit avec deux conteneurs doit faire échouer Render")
	}

	hostNetwork := `apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: test
spec:
  hostNetwork: true
  containers:
  - name: runner
    image: busybox
`

	r, err = NewRenderer(map[string]string{"host-network": hostNetwork})
	if err != nil {
		t.Fatalf("création du renderer personnalisé hostNetwork : %v", err)
	}

	req.Spec.Template = "host-network"
	if _, err := r.Render(req); err == nil {
		t.Fatalf("un gabarit avec hostNetwork: true doit faire échouer Render")
	}
}
