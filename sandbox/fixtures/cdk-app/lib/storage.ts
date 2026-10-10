import { Construct } from "constructs";
import * as s3 from "aws-cdk-lib/aws-s3";

export function addStorage(scope: Construct) {
  // defaults: no versioning, no access logging
  return new s3.Bucket(scope, "Data");
}
