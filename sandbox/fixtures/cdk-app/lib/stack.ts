import { Stack, StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";
import { addStorage } from "./storage";
import { Network } from "./network";
import * as iam from "aws-cdk-lib/aws-iam";

export class ProbeStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
    addStorage(this);
    new Network(this, "Net");
    new iam.ManagedPolicy(this, "AdminPolicy", {
      statements: [new iam.PolicyStatement({ actions: ["*"], resources: ["*"] })],
    });
  }
}
