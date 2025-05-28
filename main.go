package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/chainguard-dev/clog"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
)

type copts struct {
	refs                []string
	repos               []string
	serviceaccounts     []string
	name                string
	patchAllSAs         bool
	patchAllNamespaces  bool

	flags *genericclioptions.ConfigFlags
	genericiooptions.IOStreams
}

func NewCmdCrane(streams genericiooptions.IOStreams) *cobra.Command {
	o := copts{
		flags:     genericclioptions.NewConfigFlags(true),
		IOStreams: streams,
	}

	cmd := &cobra.Command{
		Use:   "crane [repository]",
		Short: "Create a secret with registry credentials",
		Example: `
Create a secret appropriate for pulling "cgr.dev/chainguard/chainguard-base:latest"

	kubectl crane --ref cgr.dev/chainguard/chainguard-base:latest

Create a secret appropriate for pulling all images from "cgr.dev" and "gcr.io"

	kubectl crane --repo cgr.dev --ref gcr.io/foo/bar

Create a secret in the "foo" namespace that all the default service accounts in the "foo" namespace can pull images from "cgr.dev"

	kubectl crane --repo cgr.dev --sa default --namespace foo

Create a secret in the "foo" namespace and patch it to all service accounts in that namespace

	kubectl crane --repo cgr.dev --namespace foo --patch-all-sa
	
Create a secret and patch it to all service accounts across all namespaces

	kubectl crane --repo cgr.dev --patch-all-namespaces --patch-all-sa
	
Create a secret and patch it to specific service accounts across all namespaces

	kubectl crane --repo cgr.dev --patch-all-namespaces --sa default`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd)
		},
	}

	o.flags.AddFlags(cmd.Flags())
	cmd.Flags().StringVar(&o.name, "name", "kc", "The name of the registry credentials secret to create/update.")
	cmd.Flags().StringSliceVar(&o.refs, "ref", []string{}, "The image reference to create the secret for. The repository will be inferred.")
	cmd.Flags().StringSliceVarP(&o.repos, "repo", "r", []string{}, "The repository to create the secret for")
	cmd.Flags().StringSliceVar(&o.serviceaccounts, "sa", []string{}, "The service account to patch.")
	cmd.Flags().BoolVar(&o.patchAllSAs, "patch-all-sa", false, "Patch all service accounts in the namespace with the image pull secret.")
	cmd.Flags().BoolVar(&o.patchAllNamespaces, "patch-all-namespaces", false, "Patch service accounts across all namespaces with the image pull secret.")

	return cmd
}

func (o *copts) Run(cmd *cobra.Command) error {
	ctx := cmd.Context()
	log := clog.FromContext(ctx)

	// Validate flags
	if err := o.validateFlags(); err != nil {
		return err
	}

	// Build registry configurations
	repos, err := o.buildRegistryConfigs(*log)
	if err != nil {
		return err
	}

	// Create docker config
	dcfg, err := o.createDockerConfig(repos)
	if err != nil {
		return err
	}

	// Create secret object
	secret, err := o.secret(dcfg)
	if err != nil {
		return fmt.Errorf("creating secret: %w", err)
	}

	// Get Kubernetes client
	kcli, err := o.getKubernetesClient()
	if err != nil {
		return err
	}

	// Create or update the main secret
	sobj, err := o.createOrUpdateSecret(ctx, kcli, secret, *log)
	if err != nil {
		return err
	}

	// Patch service accounts based on flags
	return o.patchServiceAccounts(ctx, kcli, sobj, *log)
}

// validateFlags validates the command line flags
func (o *copts) validateFlags() error {
	if len(o.refs) == 0 && len(o.repos) == 0 {
		return fmt.Errorf("at least one --ref or --repo must be specified")
	}

	if o.patchAllNamespaces && *o.flags.Namespace != "" && *o.flags.Namespace != "default" {
		return fmt.Errorf("--patch-all-namespaces cannot be used with a specific --namespace")
	}

	return nil
}

// buildRegistryConfigs builds registry configurations from refs and repos
func (o *copts) buildRegistryConfigs(log clog.Logger) (map[string]name.Registry, error) {
	repos := make(map[string]name.Registry)

	for _, repo := range o.repos {
		r, err := name.NewRegistry(repo)
		if err != nil {
			return nil, fmt.Errorf("parsing repository: %w", err)
		}
		log.Infof("registering repo %s", r.RegistryStr())
		repos[r.RegistryStr()] = r
	}

	for _, ref := range o.refs {
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, fmt.Errorf("parsing repository: %w", err)
		}
		log.Infof("registering repo %s inferred from reference %s", r.Context().RegistryStr(), r.String())
		repos[r.Context().RegistryStr()] = r.Context().Registry
	}

	return repos, nil
}

// createDockerConfig creates docker configuration from registry configs
func (o *copts) createDockerConfig(repos map[string]name.Registry) (configfile.ConfigFile, error) {
	dcfg := configfile.ConfigFile{
		AuthConfigs: map[string]types.AuthConfig{},
	}

	for name, repo := range repos {
		a, err := authn.DefaultKeychain.Resolve(repo)
		if err != nil {
			return dcfg, fmt.Errorf("resolving auth for %s: %w", name, err)
		}

		cfg, err := a.Authorization()
		if err != nil {
			return dcfg, fmt.Errorf("getting authorization for %s: %w", name, err)
		}

		dcfg.AuthConfigs[name] = types.AuthConfig{
			Username: cfg.Username,
			Password: cfg.Password,
			Auth:     cfg.Auth,
		}
	}

	return dcfg, nil
}

// getKubernetesClient creates a kubernetes client
func (o *copts) getKubernetesClient() (*kubernetes.Clientset, error) {
	rcfg, err := o.flags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("getting REST config: %w", err)
	}

	kcli, err := kubernetes.NewForConfig(rcfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	return kcli, nil
}

// createOrUpdateSecret creates or updates the main secret
func (o *copts) createOrUpdateSecret(ctx context.Context, kcli *kubernetes.Clientset, secret *corev1.Secret, log clog.Logger) (*corev1.Secret, error) {
	log.Infof("managing secret '%s/%s'", secret.Namespace, secret.Name)

	sobj, err := kcli.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, v1.GetOptions{})
	if err == nil {
		// Update existing secret
		sobj, err = kcli.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, v1.UpdateOptions{})
		if err != nil {
			return nil, fmt.Errorf("updating secret: %w", err)
		}
		log.Infof("updated secret '%s/%s'", secret.Namespace, secret.Name)
	} else if errors.IsNotFound(err) {
		// Create new secret
		sobj, err = kcli.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, v1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating secret: %w", err)
		}
		log.Infof("created secret '%s/%s'", secret.Namespace, secret.Name)
	} else {
		return nil, fmt.Errorf("checking for existing secret: %w", err)
	}

	return sobj, nil
}

// patchServiceAccounts patches service accounts based on flags
func (o *copts) patchServiceAccounts(ctx context.Context, kcli *kubernetes.Clientset, secret *corev1.Secret, log clog.Logger) error {
	if o.patchAllNamespaces {
		return o.patchAllNamespacesFunc(ctx, kcli, secret, log)
	} else if o.patchAllSAs {
		return o.patchAllServiceAccountsInNamespace(ctx, kcli, secret.Namespace, secret.Name, log)
	} else if len(o.serviceaccounts) > 0 {
		return o.patchSpecificServiceAccounts(ctx, kcli, secret.Namespace, secret.Name, o.serviceaccounts, log)
	}

	return nil
}

// patchAllNamespacesFunc patches service accounts across all namespaces
func (o *copts) patchAllNamespacesFunc(ctx context.Context, kcli *kubernetes.Clientset, secret *corev1.Secret, log clog.Logger) error {
	// List all namespaces
	nsList, err := kcli.CoreV1().Namespaces().List(ctx, v1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing namespaces: %w", err)
	}

	log.Infof("patching service accounts across all namespaces with imagePullSecret '%s'", secret.Name)

	for _, ns := range nsList.Items {
		// Skip system namespaces
		if isSystemNamespace(ns.Name) {
			log.Infof("skipping system namespace '%s'", ns.Name)
			continue
		}

		// Create/update secret in namespace
		if err := o.ensureSecretInNamespace(ctx, kcli, ns.Name, secret, log); err != nil {
			log.Infof("failed to ensure secret in namespace '%s': %v", ns.Name, err)
			continue
		}

		// Patch service accounts in namespace
		if o.patchAllSAs {
			if err := o.patchAllServiceAccountsInNamespace(ctx, kcli, ns.Name, secret.Name, log); err != nil {
				log.Infof("failed to patch all service accounts in namespace '%s': %v", ns.Name, err)
			}
		} else if len(o.serviceaccounts) > 0 {
			if err := o.patchSpecificServiceAccounts(ctx, kcli, ns.Name, secret.Name, o.serviceaccounts, log); err != nil {
				log.Infof("failed to patch specific service accounts in namespace '%s': %v", ns.Name, err)
			}
		}
	}

	log.Infof("finished patching service accounts across all namespaces")
	return nil
}

// ensureSecretInNamespace ensures a secret exists in a namespace
func (o *copts) ensureSecretInNamespace(ctx context.Context, kcli *kubernetes.Clientset, namespace string, secret *corev1.Secret, log clog.Logger) error {
	nsSecret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      secret.Name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: secret.Data,
	}

	_, err := kcli.CoreV1().Secrets(namespace).Get(ctx, secret.Name, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// Create the secret
			_, err = kcli.CoreV1().Secrets(namespace).Create(ctx, nsSecret, v1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating secret: %w", err)
			}
			log.Infof("created secret '%s' in namespace '%s'", secret.Name, namespace)
		} else {
			return fmt.Errorf("checking for secret: %w", err)
		}
	} else {
		// Update the secret
		_, err = kcli.CoreV1().Secrets(namespace).Update(ctx, nsSecret, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating secret: %w", err)
		}
		log.Infof("updated secret '%s' in namespace '%s'", secret.Name, namespace)
	}

	return nil
}

// patchAllServiceAccountsInNamespace patches all service accounts in a namespace
func (o *copts) patchAllServiceAccountsInNamespace(ctx context.Context, kcli *kubernetes.Clientset, namespace, secretName string, log clog.Logger) error {
	saList, err := kcli.CoreV1().ServiceAccounts(namespace).List(ctx, v1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing service accounts: %w", err)
	}

	for _, sa := range saList.Items {
		if err := o.patchServiceAccount(ctx, kcli, namespace, sa.Name, secretName, log); err != nil {
			log.Infof("failed to patch service account '%s' in namespace '%s': %v", sa.Name, namespace, err)
		}
	}

	log.Infof("patched all service accounts in namespace '%s' with imagePullSecret '%s'", namespace, secretName)
	return nil
}

// patchSpecificServiceAccounts patches specific service accounts
func (o *copts) patchSpecificServiceAccounts(ctx context.Context, kcli *kubernetes.Clientset, namespace, secretName string, serviceAccounts []string, log clog.Logger) error {
	for _, saName := range serviceAccounts {
		if err := o.ensureServiceAccountWithSecret(ctx, kcli, namespace, saName, secretName, log); err != nil {
			return err
		}
	}

	return nil
}

// ensureServiceAccountWithSecret ensures a service account exists and has the secret
func (o *copts) ensureServiceAccountWithSecret(ctx context.Context, kcli *kubernetes.Clientset, namespace, saName, secretName string, log clog.Logger) error {
	_, err := kcli.CoreV1().ServiceAccounts(namespace).Get(ctx, saName, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// Create the service account
			newSA := &corev1.ServiceAccount{
				ObjectMeta: v1.ObjectMeta{
					Name:      saName,
					Namespace: namespace,
				},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: secretName}},
			}
			_, err = kcli.CoreV1().ServiceAccounts(namespace).Create(ctx, newSA, v1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating service account '%s': %w", saName, err)
			}
			log.Infof("created service account '%s' in namespace '%s'", saName, namespace)
			return nil
		}
		return fmt.Errorf("getting service account '%s': %w", saName, err)
	}

	return o.patchServiceAccount(ctx, kcli, namespace, saName, secretName, log)
}

// patchServiceAccount patches a single service account with the secret
func (o *copts) patchServiceAccount(ctx context.Context, kcli *kubernetes.Clientset, namespace, saName, secretName string, log clog.Logger) error {
	serviceAccount, err := kcli.CoreV1().ServiceAccounts(namespace).Get(ctx, saName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting service account: %w", err)
	}

	// Check if the imagePullSecret is already present
	for _, ips := range serviceAccount.ImagePullSecrets {
		if ips.Name == secretName {
			// Already has the secret
			return nil
		}
	}

	// Add the secret
	serviceAccount.ImagePullSecrets = append(serviceAccount.ImagePullSecrets, corev1.LocalObjectReference{Name: secretName})
	_, err = kcli.CoreV1().ServiceAccounts(namespace).Update(ctx, serviceAccount, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating service account: %w", err)
	}

	log.Infof("patched service account '%s' in namespace '%s' with imagePullSecret '%s'", saName, namespace, secretName)
	return nil
}

// isSystemNamespace checks if a namespace is a system namespace
func isSystemNamespace(namespace string) bool {
	systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, ns := range systemNamespaces {
		if namespace == ns {
			return true
		}
	}
	return false
}

func main() {
	flags := pflag.NewFlagSet("kubectl-crane", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := NewCmdCrane(genericiooptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	})

	ctx := context.Background()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})))

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func (o *copts) secret(dockerconfig configfile.ConfigFile) (*corev1.Secret, error) {
	dockerConfigJSON, err := json.Marshal(dockerconfig)
	if err != nil {
		return nil, fmt.Errorf("marshaling docker config: %w", err)
	}

	ns := "default"
	if *o.flags.Namespace != "" {
		ns = *o.flags.Namespace
	}

	return &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      o.name,
			Namespace: ns,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": dockerConfigJSON,
		},
	}, nil
}
