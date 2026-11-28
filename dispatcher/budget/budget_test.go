package budget

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/actions/scaleset/dispatcher/catalog"
)

func TestPlanPlafondParNœud(t *testing.T) {
	capacity := catalog.Capacity{
		Enforce: true,
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Places: 2},
		},
	}
	usage := Usage{"node-a": 1}
	demands := []Demand{
		{
			Queue:    "queue-a",
			Repo:     "repo-a",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  3,
		},
	}

	res := (&Planner{}).Plan(demands, usage, capacity)

	if len(res.Grants) != 1 {
		t.Fatalf("len(Grants) = %d, attendu 1", len(res.Grants))
	}
	if res.Grants[0].Queue != "queue-a" {
		t.Errorf("Grants[0].Queue = %q, attendu queue-a", res.Grants[0].Queue)
	}
	if res.Grants[0].Node != "node-a" {
		t.Errorf("Grants[0].Node = %q, attendu node-a", res.Grants[0].Node)
	}
	if res.Blocked["docker"] != 2 {
		t.Errorf("Blocked[docker] = %d, attendu 2", res.Blocked["docker"])
	}
}

func TestPlanNœudAutoOuAbsent(t *testing.T) {
	capacity := catalog.Capacity{
		Enforce: true,
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Auto: true},
		},
	}
	demands := []Demand{
		{
			Queue:    "queue-a",
			Repo:     "repo-a",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  3,
		},
		{
			Queue:    "queue-b",
			Repo:     "repo-b",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-absent"},
			Missing:  3,
		},
	}

	res := (&Planner{}).Plan(demands, Usage{}, capacity)

	if len(res.Grants) != 6 {
		t.Fatalf("len(Grants) = %d, attendu 6", len(res.Grants))
	}
	if len(res.Blocked) != 0 {
		t.Errorf("Blocked = %v, attendu vide", res.Blocked)
	}
}

func TestPlanÉquité(t *testing.T) {
	capacity := catalog.Capacity{
		Enforce: true,
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Places: 4},
		},
	}
	demands := []Demand{
		{
			Queue:    "queue-a",
			Repo:     "repo-a",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  4,
		},
		{
			Queue:    "queue-b",
			Repo:     "repo-b",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  4,
		},
	}

	res := (&Planner{}).Plan(demands, Usage{}, capacity)

	counts := map[string]int{}
	for _, g := range res.Grants {
		counts[g.Queue]++
	}
	if counts["queue-a"] != 2 {
		t.Errorf("attributions queue-a = %d, attendu 2", counts["queue-a"])
	}
	if counts["queue-b"] != 2 {
		t.Errorf("attributions queue-b = %d, attendu 2", counts["queue-b"])
	}
}

func TestPlanPriorité(t *testing.T) {
	capacity := catalog.Capacity{
		Enforce: true,
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Places: 1},
		},
	}
	demands := []Demand{
		{
			Queue:    "queue-normal",
			Repo:     "repo-a",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  1,
		},
		{
			Queue:    "queue-high",
			Repo:     "repo-b",
			Profile:  "docker",
			Priority: "high",
			Nodes:    []string{"node-a"},
			Missing:  1,
		},
	}

	res := (&Planner{}).Plan(demands, Usage{}, capacity)

	if len(res.Grants) != 1 {
		t.Fatalf("len(Grants) = %d, attendu 1", len(res.Grants))
	}
	if res.Grants[0].Queue != "queue-high" {
		t.Errorf("Grants[0].Queue = %q, attendu queue-high", res.Grants[0].Queue)
	}
	if res.Blocked["docker"] != 1 {
		t.Errorf("Blocked[docker] = %d, attendu 1", res.Blocked["docker"])
	}
}

func TestPlanRotationEntrePlans(t *testing.T) {
	capacity := catalog.Capacity{
		Enforce: true,
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Places: 1},
		},
	}
	demands := []Demand{
		{
			Queue:    "queue-a",
			Repo:     "repo-a",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  1,
		},
		{
			Queue:    "queue-b",
			Repo:     "repo-b",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  1,
		},
	}

	p := &Planner{}
	res1 := p.Plan(demands, Usage{}, capacity)
	res2 := p.Plan(demands, Usage{}, capacity)

	counts := map[string]int{}
	for _, g := range append(res1.Grants, res2.Grants...) {
		counts[g.Queue]++
	}
	if counts["queue-a"] != 1 || counts["queue-b"] != 1 {
		t.Errorf("rotation incorrecte, comptes = %v", counts)
	}
}

func TestPlanSansEnforce(t *testing.T) {
	capacity := catalog.Capacity{
		Enforce: false,
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Places: 1},
		},
	}
	demands := []Demand{
		{
			Queue:    "queue-a",
			Repo:     "repo-a",
			Profile:  "docker",
			Priority: "normal",
			Nodes:    []string{"node-a"},
			Missing:  3,
		},
	}

	res := (&Planner{}).Plan(demands, Usage{}, capacity)

	if len(res.Grants) != 3 {
		t.Fatalf("len(Grants) = %d, attendu 3", len(res.Grants))
	}
	for _, g := range res.Grants {
		if g.Node != "" {
			t.Errorf("Grant.Node = %q, attendu vide sans enforce", g.Node)
		}
	}
	if res.Blocked["docker"] != 2 {
		t.Errorf("Blocked[docker] = %d, attendu 2", res.Blocked["docker"])
	}
}

func TestUsageFromPods(t *testing.T) {
	tests := []struct {
		nom     string
		pods    []*corev1.Pod
		attendu Usage
	}{
		{
			nom: "pod Running avec NodeName",
			pods: []*corev1.Pod{
				{
					Spec:   corev1.PodSpec{NodeName: "node-a"},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			attendu: Usage{"node-a": 1},
		},
		{
			nom: "pod Succeeded ignoré",
			pods: []*corev1.Pod{
				{
					Spec:   corev1.PodSpec{NodeName: "node-a"},
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
				},
			},
			attendu: Usage{},
		},
		{
			nom: "pod Failed ignoré",
			pods: []*corev1.Pod{
				{
					Spec:   corev1.PodSpec{NodeName: "node-a"},
					Status: corev1.PodStatus{Phase: corev1.PodFailed},
				},
			},
			attendu: Usage{},
		},
		{
			nom: "pod Pending avec affinité hostname unique",
			pods: []*corev1.Pod{
				{
					Spec: corev1.PodSpec{
						Affinity: &corev1.Affinity{
							NodeAffinity: &corev1.NodeAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
									NodeSelectorTerms: []corev1.NodeSelectorTerm{
										{
											MatchExpressions: []corev1.NodeSelectorRequirement{
												{
													Key:      "kubernetes.io/hostname",
													Operator: corev1.NodeSelectorOpIn,
													Values:   []string{"node-b"},
												},
											},
										},
									},
								},
							},
						},
					},
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				},
			},
			attendu: Usage{"node-b": 1},
		},
		{
			nom: "pod Pending avec deux nœuds possibles dans un terme",
			pods: []*corev1.Pod{
				{
					Spec: corev1.PodSpec{
						Affinity: &corev1.Affinity{
							NodeAffinity: &corev1.NodeAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
									NodeSelectorTerms: []corev1.NodeSelectorTerm{
										{
											MatchExpressions: []corev1.NodeSelectorRequirement{
												{
													Key:      "kubernetes.io/hostname",
													Operator: corev1.NodeSelectorOpIn,
													Values:   []string{"node-b", "node-c"},
												},
											},
										},
									},
								},
							},
						},
					},
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				},
			},
			attendu: Usage{},
		},
		{
			nom: "pod Pending avec deux termes d'affinité",
			pods: []*corev1.Pod{
				{
					Spec: corev1.PodSpec{
						Affinity: &corev1.Affinity{
							NodeAffinity: &corev1.NodeAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
									NodeSelectorTerms: []corev1.NodeSelectorTerm{
										{
											MatchExpressions: []corev1.NodeSelectorRequirement{
												{
													Key:      "kubernetes.io/hostname",
													Operator: corev1.NodeSelectorOpIn,
													Values:   []string{"node-b"},
												},
											},
										},
										{
											MatchExpressions: []corev1.NodeSelectorRequirement{
												{
													Key:      "kubernetes.io/hostname",
													Operator: corev1.NodeSelectorOpIn,
													Values:   []string{"node-c"},
												},
											},
										},
									},
								},
							},
						},
					},
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				},
			},
			attendu: Usage{},
		},
		{
			nom: "pod Pending sans nœud ni affinité",
			pods: []*corev1.Pod{
				{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				},
			},
			attendu: Usage{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.nom, func(t *testing.T) {
			got := UsageFromPods(tt.pods)
			if !reflect.DeepEqual(got, tt.attendu) {
				t.Errorf("UsageFromPods = %v, attendu %v", got, tt.attendu)
			}
		})
	}
}

func TestFree(t *testing.T) {
	capacity := catalog.Capacity{
		Nodes: map[string]catalog.NodeCapacity{
			"node-a": {Places: 4},
			"node-b": {Auto: true},
			"node-c": {Places: 2},
		},
	}
	usage := Usage{
		"node-a": 1,
		"node-c": 2,
	}

	got := Free(usage, capacity)
	want := map[string]int{
		"node-a": 3,
		"node-c": 0,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Free = %v, attendu %v", got, want)
	}
}
