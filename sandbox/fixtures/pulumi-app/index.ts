import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const config = new pulumi.Config();
export const bucket = new aws.s3.Bucket("logs", {
  tags: { Environment: config.get("environment") || "sandbox" },
});
export const securityGroup = new aws.ec2.SecurityGroup("ssh", {
  ingress: [{ protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["0.0.0.0/0"] }],
});
export const bucketId = bucket.id;
