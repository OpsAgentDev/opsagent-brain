#!/usr/bin/env bash
# Runs the AWS connector against a local AWS Emulator: deploys the real read-role template,
# verifies it, reads a seeded bucket, deletes the stack (lost access), deploys it again (reconnect).
# Needs docker, the AWS CLI v2 and cargo. No AWS account, nothing is billed.
#   scripts/aws-emulator-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${OPSAGENT_EMULATOR_PORT:-9297}"
IMAGE=opsagent-aws-emulator
NAME="opsagent-aws-emulator-$PORT"
WORK="${TMPDIR:-/tmp}/opsagent-aws-emulator"
BASE=https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest
# AWS's publishing key, from the emulator user guide (Getting started on Linux).
FINGERPRINT=98BCF336A3BE53B734E967C52E5BF49BD940F624

case "$(uname -m)" in arm64 | aarch64) ARCH=aarch64 ;; *) ARCH=x86_64 ;; esac
mkdir -p "$WORK/img" "$WORK/home/.aws/emulator"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  rpm="aws-emulator-$ARCH.rpm"
  curl -fsSLo "$WORK/img/$rpm" "$BASE/$rpm"
  if command -v gpg >/dev/null; then
    curl -fsSLo "$WORK/img/$rpm.sig" "$BASE/$rpm.sig"
    curl -fsSLo "$WORK/key.asc" https://downloads.aws.com/keys/gpg/current.asc
    export GNUPGHOME="$WORK/gnupg"
    mkdir -p -m 700 "$GNUPGHOME"
    gpg --quiet --import "$WORK/key.asc"
    gpg --status-fd 1 --verify "$WORK/img/$rpm.sig" "$WORK/img/$rpm" 2>/dev/null | grep -q "VALIDSIG $FINGERPRINT" ||
      { echo "emulator package signature does not match AWS's key; not installing" >&2; exit 1; }
    rm "$WORK/img/$rpm.sig"
  else
    echo "gpg not found: emulator package signature not checked" >&2
  fi
  cat >"$WORK/img/Dockerfile" <<DOCKER
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
COPY $rpm /tmp/aws-emulator.rpm
RUN rpm -i /tmp/aws-emulator.rpm && rm /tmp/aws-emulator.rpm && mkdir -p /home/emulator && chown 1000 /home/emulator
USER 1000
ENV HOME=/home/emulator
ENTRYPOINT ["aws-emulator", "-b", "0.0.0.0"]
DOCKER
  docker build -q -t "$IMAGE" "$WORK/img" >/dev/null
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
E="$WORK/home/.aws/emulator"
rm -rf "$E/$PORT"
# Published on loopback only; state is in memory and goes with the container.
docker run -d --name "$NAME" --memory=2g --memory-swap=2g -p "127.0.0.1:$PORT:$PORT" \
  -e HOME="$WORK/home" -v "$E:$E" "$IMAGE" -p "$PORT" --telemetry off >/dev/null
for _ in $(seq 1 30); do [ -f "$E/$PORT/ca.pem" ] && break; sleep 1; done
[ -f "$E/$PORT/ca.pem" ] || { docker logs "$NAME" >&2; echo "emulator did not start" >&2; exit 1; }

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
export AWS_ENDPOINT_URL="https://127.0.0.1:$PORT"
export AWS_SHARED_CREDENTIALS_FILE="$E/$PORT/emulator_credentials" AWS_CONFIG_FILE="$E/$PORT/config"
export AWS_CA_BUNDLE="$E/$PORT/ca.pem" SSL_CERT_FILE="$E/$PORT/ca.pem"
export AWS_EC2_METADATA_DISABLED=true AWS_DISABLE_HOST_PREFIX_INJECTION=true
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""

SHORT=emu00001
STACK="OpsAgent-Read-$SHORT"
export OPSAGENT_EMULATOR_EXTERNAL_ID=11111111-2222-4333-8444-555555555555
export OPSAGENT_EMULATOR_BUCKET=opsagent-emulator-open
for _ in $(seq 1 30); do PRINCIPAL=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null) && break; sleep 1; done

deploy() {
  aws cloudformation create-stack --stack-name "$STACK" --capabilities CAPABILITY_NAMED_IAM \
    --template-body file://templates/aws/opsagent-read-role-v1.yaml --parameters \
    "ParameterKey=ExternalId,ParameterValue=$OPSAGENT_EMULATOR_EXTERNAL_ID" \
    "ParameterKey=OpsAgentPrincipal,ParameterValue=$PRINCIPAL" \
    "ParameterKey=OrgShortId,ParameterValue=$SHORT" >/dev/null
  aws cloudformation wait stack-create-complete --stack-name "$STACK"
  OPSAGENT_EMULATOR_ROLE_ARN=$(aws cloudformation describe-stacks --stack-name "$STACK" \
    --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' --output text)
  export OPSAGENT_EMULATOR_ROLE_ARN
}
run() { cargo test -p opsagent-connectors --test aws_emulator -- --ignored --exact "$1"; }

deploy
aws s3api create-bucket --bucket "$OPSAGENT_EMULATOR_BUCKET" >/dev/null
# New buckets block public access by default; the seeded one has it switched off, the state check 3 reports.
aws s3api put-public-access-block --bucket "$OPSAGENT_EMULATOR_BUCKET" --public-access-block-configuration \
  BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
run emulator_verify_and_inventory
aws cloudformation delete-stack --stack-name "$STACK"
aws cloudformation wait stack-delete-complete --stack-name "$STACK"
run emulator_deleted_stack_is_lost_access
deploy
run emulator_verify_and_inventory
echo "aws emulator tests passed"
