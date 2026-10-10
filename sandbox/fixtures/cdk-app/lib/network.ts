import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";

export class Network extends Construct {
  constructor(scope: Construct, id: string) {
    super(scope, id);
    const vpc = new ec2.Vpc(this, "Vpc", { maxAzs: 1, natGateways: 0 });
    const sg = new ec2.SecurityGroup(this, "Ssh", { vpc });
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), "ssh from anywhere");
  }
}
