import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
const hard = new pulumi.Config().getBoolean("hardened") || false;
export const logs = new aws.s3.Bucket("logs", {});
export const access = new aws.s3.BucketPublicAccessBlock("access", {
  bucket: logs.id, blockPublicAcls: hard, blockPublicPolicy: hard,
  ignorePublicAcls: hard, restrictPublicBuckets: hard,
});
export const version = new aws.s3.BucketVersioning("version", {
  bucket: logs.id, versioningConfiguration: { status: hard ? "Enabled" : "Suspended" },
});
export const key = new aws.kms.Key("key", { enableKeyRotation: hard });
export const encryption = new aws.s3.BucketServerSideEncryptionConfiguration("encryption", {
  bucket: logs.id, rules: [{ applyServerSideEncryptionByDefault: {
    sseAlgorithm: hard ? "aws:kms" : "AES256", ...(hard ? { kmsMasterKeyId: key.id } : {}),
  } }],
});
export const logging = new aws.s3.BucketLogging("logging", { bucket: logs.id, targetBucket: "external-audit", targetPrefix: "logs/" });
export const server = new aws.ec2.Instance("server", {
  ami: "ami-12345678", instanceType: "t3.small",
  metadataOptions: { httpTokens: hard ? "required" : "optional" }, rootBlockDevice: { encrypted: hard },
});
export const web = new aws.ec2.SecurityGroup("web", {
  ingress: [{ protocol: "tcp", fromPort: hard ? 443 : 22, toPort: hard ? 443 : 22,
    cidrBlocks: [hard ? "10.0.0.0/8" : "0.0.0.0/0"] }],
});
export const trail = new aws.cloudtrail.Trail("trail", {
  s3BucketName: logs.id, enableLogFileValidation: hard, isMultiRegionTrail: hard,
  ...(hard ? { kmsKeyId: key.id } : {}),
});
