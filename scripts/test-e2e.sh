#!/usr/bin/env bash
# Runs the live STS smoke test. GetCallerIdentity creates no AWS resources
# (AWS documents it as requiring no IAM permission and no persistent state),
# so unlike s3-eio/dynamodb-eio there is no provision/teardown step here —
# just a short-lived credential mint and the test itself.
#
#   TEST_USER_PROFILE - profile holding sts-smoke-test-user's own static keys;
#                        used only to mint a short-lived session token
#                        (default: sts-smoke-test-user)
set -euo pipefail
cd "$(dirname "$0")/.."

REGION="${REGION:-us-east-1}"
TEST_USER_PROFILE="${TEST_USER_PROFILE:-sts-smoke-test-user}"

echo "==> Minting short-lived session token for ${TEST_USER_PROFILE}..."
creds="$(aws sts get-session-token --profile "$TEST_USER_PROFILE" --duration-seconds 900 \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<<"$creds"

export AWS_EIO_LIVE=1
export AWS_REGION="$REGION"

echo "==> Running live STS smoke test..."
dune runtest test/
