# METADATA
# title: Security group rule allows unrestricted ingress from any IP address on a port other than SSH or RDP
# description: |
#   Trivy's built-in AWS-0107 (tfsec's aws-ec2-no-public-ingress-sgr) is
#   scoped upstream to the remote-administration ports, 22 and 3389. tfsec's
#   version fired on any port, and the difference cost this project two
#   findings it had been built around -- port 80 and the Kubernetes NodePort
#   range open to the world (spec §8.4 item 2; corpus/eval/README.md, "Public
#   ingress on non-admin ports"). This check is the other half: an ingress
#   rule open to every IP on any TCP/UDP port range that AWS-0107 does not
#   already cover. A rule AWS-0107 does cover (22 or 3389 in range, or all
#   protocols) is left to it, so the two never report the same rule twice.
#
#   A public web tier looks exactly like this finding, on purpose. The check
#   still admits it: whether port 80 open to the world is intended is a
#   reviewer's call, recorded in the dashboard, not something a scanner or a
#   model decides (spec §8.1). Mapped to OWASP CNAS-6, "network access
#   controls should default to deny", alongside the egress twin AWS-0104.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: IACP-0001
#   avd_id: IACP-0001
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: no-public-ingress-any-port
#   recommended_action: Restrict the source to the CIDR ranges that need to reach this port, or expose the service through a load balancer whose security group is the only permitted source.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
package user.aws.ec2.iacp0001

import rego.v1

# The same constants lib.net keeps, inlined so this check stands alone.
all_ips := {"0.0.0.0/0", "0000:0000:0000:0000:0000:0000:0000:0000/0", "::/0", "*"}

all_protocols := {"-1", "all"}

tcp_or_udp := {"tcp", "6", "udp", "17"}

protocol(v) := lower(v) if is_string(v)

protocol(v) := lower(format_int(v, 10)) if is_number(v)

port_in_range(from, to, port) if {
	from <= port
	port <= to
}

# What AWS-0107 already reports: all protocols, or a range that includes
# SSH or RDP. Excluded here so a rule is never counted under both ids.
covered_by_aws0107(rule) if protocol(rule.protocol.value) in all_protocols

covered_by_aws0107(rule) if port_in_range(rule.fromport.value, rule.toport.value, 22)

covered_by_aws0107(rule) if port_in_range(rule.fromport.value, rule.toport.value, 3389)

deny contains res if {
	some group in input.aws.ec2.securitygroups
	some rule in group.ingressrules
	protocol(rule.protocol.value) in tcp_or_udp
	not covered_by_aws0107(rule)
	some block in rule.cidrs
	block.value in all_ips
	res := result.new(
		sprintf("Security group rule allows unrestricted ingress from any IP address on ports %d-%d.", [rule.fromport.value, rule.toport.value]),
		block,
	)
}
