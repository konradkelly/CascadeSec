# The sandbox's Node 22 image (docs/sandbox-spec.md §6). One image per
# runtime, pinned by digest -- here the base, and in terraform/sandbox the
# image itself. Harnesses arrive with the kinds that run them (spec §9);
# for now the runner carries only the containment's own tests.
#
# node:22-slim, 22.23.3 at the time of pinning (2026-10-09).
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392

COPY runner.mjs /opt/sandbox/runner.mjs

# The task's only writable places. Declared as volumes, owned by the
# unprivileged user, so the task definition's empty volumes mounted here
# start writable by it; the rest of the filesystem is read-only at run time
# (readonlyRootFilesystem in terraform/sandbox/ecs.tf).
RUN mkdir -p /work && chown node:node /work && chmod 0755 /work \
 && chmod 1777 /tmp
VOLUME ["/work", "/tmp"]

# uid 1000, matching the task definition's `user`. The task definition is
# what enforces it; this is so the image is unprivileged run anywhere else.
USER node
WORKDIR /work

ENTRYPOINT ["node", "/opt/sandbox/runner.mjs"]
