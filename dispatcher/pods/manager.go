package pods

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// Manager creates, patches and deletes runner pods and keeps a cache of
// every runner pod of the namespace, ARC ones included (the budget counts
// them during the cohabitation).
type Manager struct {
	client     kubernetes.Interface
	namespace  string
	labels     Labels
	factory    informers.SharedInformerFactory
	nodes      informers.SharedInformerFactory
	podLister  corelisters.PodLister
	nodeLister corelisters.NodeLister
	podInf     cache.SharedIndexInformer
}

// NewManager builds a Manager for one namespace.
func NewManager(client kubernetes.Interface, namespace string, l Labels) *Manager {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 10*time.Minute,
		informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.LabelSelector = LabelComponent + "=" + ComponentRunner
		}))
	nodes := informers.NewSharedInformerFactory(client, 30*time.Minute)
	m := &Manager{client: client, namespace: namespace, labels: l, factory: factory, nodes: nodes}
	m.podInf = factory.Core().V1().Pods().Informer()
	m.podLister = factory.Core().V1().Pods().Lister()
	m.nodeLister = nodes.Core().V1().Nodes().Lister()
	return m
}

// OnPod registers a callback for every pod add, update or delete. It must be
// called before Start.
func (m *Manager) OnPod(fn func(pod *corev1.Pod, deleted bool)) {
	_, _ = m.podInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if p, ok := obj.(*corev1.Pod); ok {
				fn(p, false)
			}
		},
		UpdateFunc: func(_, obj any) {
			if p, ok := obj.(*corev1.Pod); ok {
				fn(p, false)
			}
		},
		DeleteFunc: func(obj any) {
			if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = t.Obj
			}
			if p, ok := obj.(*corev1.Pod); ok {
				fn(p, true)
			}
		},
	})
}

// Start runs the informers and waits for their first sync.
func (m *Manager) Start(ctx context.Context) error {
	m.factory.Start(ctx.Done())
	m.nodes.Start(ctx.Done())
	for t, ok := range m.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("pod cache %v did not sync", t)
		}
	}
	for t, ok := range m.nodes.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("node cache %v did not sync", t)
		}
	}
	return nil
}

// RunnerPods returns every runner pod of the namespace (ARC ones included).
func (m *Manager) RunnerPods() []*corev1.Pod {
	pods, _ := m.podLister.Pods(m.namespace).List(labels.Everything())
	return pods
}

// Managed returns the pods this dispatcher owns.
func (m *Manager) Managed() []*corev1.Pod {
	sel := labels.SelectorFromSet(labels.Set{LabelManagedBy: ManagedByValue})
	pods, _ := m.podLister.Pods(m.namespace).List(sel)
	return pods
}

// Get returns a cached pod.
func (m *Manager) Get(name string) (*corev1.Pod, bool) {
	p, err := m.podLister.Pods(m.namespace).Get(name)
	if err != nil {
		return nil, false
	}
	return p, true
}

// Nodes returns the cached nodes.
func (m *Manager) Nodes() []*corev1.Node {
	nodes, _ := m.nodeLister.List(labels.Everything())
	return nodes
}

// Create creates a pod.
func (m *Manager) Create(ctx context.Context, pod *corev1.Pod) (*corev1.Pod, error) {
	return m.client.CoreV1().Pods(m.namespace).Create(ctx, pod, metav1.CreateOptions{})
}

// Delete deletes a pod, only if it still has that UID. A pod already gone
// is not an error.
func (m *Manager) Delete(ctx context.Context, name string, uid types.UID) error {
	opts := metav1.DeleteOptions{}
	if uid != "" {
		opts.Preconditions = &metav1.Preconditions{UID: &uid}
	}
	err := m.client.CoreV1().Pods(m.namespace).Delete(ctx, name, opts)
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return err
}

// Patch merges labels and annotations into a pod, only if it still has that
// UID (the merge patch carries it as a precondition).
func (m *Manager) Patch(ctx context.Context, name string, uid types.UID, lbls, annotations map[string]string) error {
	meta := map[string]any{}
	if uid != "" {
		meta["uid"] = string(uid)
	}
	if len(lbls) > 0 {
		meta["labels"] = lbls
	}
	if len(annotations) > 0 {
		meta["annotations"] = annotations
	}
	body, err := json.Marshal(map[string]any{"metadata": meta})
	if err != nil {
		return err
	}
	_, err = m.client.CoreV1().Pods(m.namespace).Patch(ctx, name, types.MergePatchType, body, metav1.PatchOptions{})
	return err
}

// IsGone reports a pod that no longer exists.
func IsGone(err error) bool {
	return apierrors.IsNotFound(err) || apierrors.IsConflict(err) || errors.Is(err, context.Canceled)
}

// Terminated reports a pod whose runner has exited.
func Terminated(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed || p.DeletionTimestamp != nil
}

// Labels returns the label set of the manager.
func (m *Manager) Labels() Labels { return m.labels }

// Namespace returns the managed namespace.
func (m *Manager) Namespace() string { return m.namespace }
