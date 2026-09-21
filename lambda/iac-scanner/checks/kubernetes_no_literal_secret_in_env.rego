# METADATA
# title: Container environment variable holds a literal credential
# description: |
#   Neither scanner reports a password typed straight into a manifest, and
#   the direction of what they do report is backwards: the *correct* form,
#   `valueFrom.secretKeyRef`, raises CKV_K8S_35, while a literal under
#   `value:` raises nothing at all.
#
#   The cause is structural, and it is specific to Kubernetes. checkov's
#   secret detection is EntropyKeywordCombinator -- a keyword has to sit
#   beside a high-entropy value. In a Secret's `stringData` it does
#   (`password: "<value>"` is one YAML pair) and CKV_SECRET_6 fires. In a
#   container's `env` list the keyword is under `name:` and the secret is
#   under `value:`, two separate keys, so the combinator never pairs them.
#   Measured 2026-09-20 with the identical value in both positions; the two
#   eval cases k8s-literal-secret-in-env and
#   k8s-literal-secret-in-secret-object isolate it. Shape-matched
#   credentials are unaffected -- an AKIA... key in the same position fires
#   CKV_SECRET_2, because AWSKeyDetector needs no keyword -- so the blind
#   spot is exactly those credentials only recognisable from the name
#   beside them, which is most of them.
#
#   This check is that pairing, done structurally rather than by entropy:
#   an `env` entry whose name contains a credential keyword and whose value
#   is a literal. Entropy is deliberately not scored. A weak password is
#   still a hardcoded credential, and "changeme" in a manifest is a finding,
#   not a false positive.
#
#   Like IACP-0001, this admits cases a human may judge acceptable -- a
#   throwaway value in a local-development overlay looks exactly like this.
#   Whether it matters is a reviewer's call recorded in the dashboard, not
#   something the scanner decides (spec §8.1). What is excluded is only what
#   is not a credential by construction: an empty value, a `$(VAR)`
#   reference to another variable, and names that point *at* a secret rather
#   than hold one (`..._NAME`, `..._FILE`, `..._PATH`).
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: IACP-0002
#   avd_id: IACP-0002
#   provider: kubernetes
#   service: general
#   severity: HIGH
#   short_code: no-literal-secret-in-env
#   recommended_action: Move the value into a Secret and mount it as a file; a secretKeyRef is better than a literal but still exposes the value to child processes, crash dumps and anything that logs the environment (CIS Kubernetes 5.4.1).
#   input:
#     selector:
#       - type: kubernetes
package user.kubernetes.iacp0002

import rego.v1

# Substrings that make an environment variable name a credential. Matched
# case-insensitively against the whole name, so POSTGRES_PASSWORD,
# db-password and OAUTH_TOKEN all qualify.
credential_keywords := {
	"password", "passwd", "pwd", "secret", "token",
	"apikey", "api_key", "accesskey", "access_key",
	"privatekey", "private_key", "credential", "passphrase",
}

# Names that reference a credential rather than contain one.
reference_suffixes := {"_name", "_file", "_path", "-name", "-file", "-path"}

# Where a pod spec lives, by kind. Listed rather than discovered, so the
# check never walks into an unrelated `spec.template`.
pod_specs contains spec if {
	input.kind == "Pod"
	spec := input.spec
}

pod_specs contains spec if {
	input.kind in {"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "Job"}
	spec := input.spec.template.spec
}

pod_specs contains spec if {
	input.kind == "CronJob"
	spec := input.spec.jobTemplate.spec.template.spec
}

# initContainers hold credentials as often as containers do -- a schema
# migration job is the usual case.
containers contains container if {
	some spec in pod_specs
	some container in spec.containers
}

containers contains container if {
	some spec in pod_specs
	some container in spec.initContainers
}

names_a_credential(name) if {
	lower_name := lower(name)
	some keyword in credential_keywords
	contains(lower_name, keyword)
	not points_at_a_credential(lower_name)
}

points_at_a_credential(lower_name) if {
	some suffix in reference_suffixes
	endswith(lower_name, suffix)
}

# A literal: `value` is present and is not a reference to another variable.
# Kubernetes expands $(OTHER_VAR) at runtime, so that is a pointer, not a
# secret -- PugetScope's DATABASE_URL is built that way.
literal_value(env) if {
	is_string(env.value)
	count(trim_space(env.value)) > 0
	not contains(env.value, "$(")
}

deny contains res if {
	some container in containers
	some env in container.env
	names_a_credential(env.name)
	literal_value(env)
	res := result.new(
		sprintf(
			"Container '%s' sets environment variable '%s' to a literal value; a credential in a manifest is readable by anyone who can read the manifest.",
			[container.name, env.name],
		),
		env,
	)
}
