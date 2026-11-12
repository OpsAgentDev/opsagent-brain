#!/usr/bin/env bash
# Rolls one ECS service to a new image, per the deploy contract in opsagent-infra's README:
# take the latest task definition revision, replace only `image`, register it, update the service.
#   roll.sh <service> <image> [--migrate]   (--migrate: run `db migrate` on the new revision first)
set -euo pipefail
service="${1:?usage: roll.sh <service> <image> [--migrate]}" image="${2:?image}" migrate="${3:-}"
cluster="opsagent" family="opsagent-$service"

# Only the fields RegisterTaskDefinition accepts; the rest of the description is read-only.
aws ecs describe-task-definition --task-definition "$family" --query taskDefinition |
  jq --arg image "$image" '{family, taskRoleArn, executionRoleArn, networkMode, containerDefinitions,
    requiresCompatibilities, cpu, memory, runtimePlatform} | .containerDefinitions[0].image = $image' >taskdef.json
arn="$(aws ecs register-task-definition --cli-input-json file://taskdef.json \
  --query taskDefinition.taskDefinitionArn --output text)"
echo "registered $arn"

if [[ $migrate == --migrate ]]; then
  net="$(aws ecs describe-services --cluster "$cluster" --services "$service" \
    --query 'services[0].networkConfiguration' --output json)"
  overrides="$(jq -nc --arg n "$service" '{containerOverrides: [{name: $n, command: ["opsagent-brain", "db", "migrate"]}]}')"
  task="$(aws ecs run-task --cluster "$cluster" --task-definition "$arn" --launch-type FARGATE \
    --network-configuration "$net" --overrides "$overrides" --query 'tasks[0].taskArn' --output text)"
  echo "migrating in $task"
  aws ecs wait tasks-stopped --cluster "$cluster" --tasks "$task"
  code="$(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" --query 'tasks[0].containers[0].exitCode' --output text)"
  # A failed migration stops the deploy before any service rolls.
  [[ $code == 0 ]] || { echo "db migrate exited $code; see log group /opsagent/prod/api" >&2; exit 1; }
fi

aws ecs update-service --cluster "$cluster" --service "$service" --task-definition "$arn" \
  --query 'service.deployments[0].rolloutState' --output text
