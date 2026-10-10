import { App } from "aws-cdk-lib";
import { ProbeStack } from "../lib/stack";
const app = new App();
new ProbeStack(app, "ProbeStack");
