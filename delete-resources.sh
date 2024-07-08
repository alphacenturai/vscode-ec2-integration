#!/bin/bash

# Check if the required arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <instance-name> <aws-profile> <aws-region>"
    exit 1
fi

# Get the arguments
INSTANCE_NAME="$1"
AWS_PROFILE="$2"
AWS_REGION="$3"

STACK_ID=$(aws cloudformation describe-stacks \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --stack-name "$INSTANCE_NAME-Stack" \
    --query 'Stacks[0].StackId' \
    --output text)

if [ -n "$STACK_ID" ]; then
    aws cloudformation delete-stack \
        --stack-name "$STACK_ID" \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION"
else
    # Get instance ID
    INSTANCE_ID=$(aws ec2 describe-instances \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --filters "Name=tag:Name,Values=$INSTANCE_NAME" "Name=instance-state-name,Values=running,stopped" \
        --query 'Reservations[*].Instances[*].InstanceId' \
        --output text)

    # Terminate the instance (if it exists)
    if [ -n "$INSTANCE_ID" ]; then
        echo "Terminating instance: $INSTANCE_ID"
        aws ec2 terminate-instances \
            --profile "$AWS_PROFILE" \
            --region "$AWS_REGION" \
            --instance-ids "$INSTANCE_ID"
    else
        echo "Instance not found. Skipping instance termination."
    fi

    # Get security group ID
    SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --filters "Name=group-name,Values=$INSTANCE_NAME-SG" \
        --query 'SecurityGroups[*].GroupId' \
        --output text)

    # Delete the security group (if it exists)
    if [ -n "$SECURITY_GROUP_ID" ]; then
        echo "Deleting security group: $SECURITY_GROUP_ID"
        aws ec2 delete-security-group \
            --profile "$AWS_PROFILE" \
            --region "$AWS_REGION" \
            --group-id "$SECURITY_GROUP_ID"
    else
        echo "Security group not found. Skipping security group deletion."
    fi

    # Get IAM role name
    ROLE_NAME="$INSTANCE_NAME-Role"

    # Detach managed policy from the role (if attached)
    MANAGED_POLICY_ARN=$(aws iam list-attached-role-policies \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --role-name "$ROLE_NAME" \
        --query 'AttachedPolicies[*].PolicyArn' \
        --output text)

    if [ -n "$MANAGED_POLICY_ARN" ]; then
        echo "Detaching managed policy: $MANAGED_POLICY_ARN"
        aws iam detach-role-policy \
            --profile "$AWS_PROFILE" \
            --region "$AWS_REGION" \
            --role-name "$ROLE_NAME" \
            --policy-arn "$MANAGED_POLICY_ARN"
    else
        echo "No managed policy attached to the role. Skipping policy detachment."
    fi

    # Delete the IAM role (if it exists)
    echo "#######################################"
    echo "Deleting IAM role: $ROLE_NAME"
    aws iam delete-role \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --role-name "$ROLE_NAME" || echo "IAM role not found. Skipping role deletion."

    # Delete the IAM instance profile (if it exists)
    echo "#######################################"
    echo "Deleting IAM instance profile: $ROLE_NAME"
    aws iam delete-instance-profile \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --instance-profile-name "$ROLE_NAME" || echo "IAM instance profile not found. Skipping instance profile deletion."
fi

echo "Cleanup completed."