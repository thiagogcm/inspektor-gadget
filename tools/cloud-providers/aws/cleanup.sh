#! /bin/bash

set -eo pipefail

# This script deletes cloudformation stacks and VPCs that were created by the CI pipeline.
# It skips stacks and VPCs that were created in the last 3 hours, by checking the ig-ci-timestamp tag

REGION=$1

if [ -z "$REGION" ]; then
  echo "Usage: $0 <region>" >&2
  exit 1
fi

# Delete Cloudformation stacks
echo "Checking Cloudformation stacks..."

CF_STACKS_JSON=$(aws --region ${REGION} cloudformation describe-stacks --query 'Stacks[?Tags[?Key == `ig-ci-timestamp`]]')
CF_STACKS_WITH_TIMESTAMP=$(echo ${CF_STACKS_JSON} | jq -c '.[] | {StackId: .StackId, Timestamp: (.Tags[]? | select(.Key == "ig-ci-timestamp").Value)}')

deleted_stacks=""
for cf_stack_with_timestamp in $CF_STACKS_WITH_TIMESTAMP; do
    cf_stack_id=$(echo ${cf_stack_with_timestamp} | jq -r '.StackId')
    timestamp=$(echo ${cf_stack_with_timestamp} | jq -r '.Timestamp')
    timestamp=$(date -d ${timestamp} +%s)

    # Skip stacks created in the last 3 hours
    if [ $timestamp -gt $(date -d "3 hours ago" +%s) ]; then
        echo "Skipping Cloudformation Stack $cf_stack_id"
        continue
    fi

    echo "Deleting Cloudformation Stack $cf_stack_id"
    aws --region ${REGION} cloudformation delete-stack --stack-name ${cf_stack_id}
    deleted_stacks=$(echo -e "$deleted_stacks\n$cf_stack_id")
done

# Wait until all stacks were actually deleted
if [ -n "$deleted_stacks" ]; then
    echo "Waiting for stacks to be deleted..."

    num_deleted_stacks=$(echo -n "$deleted_stacks" | wc -l)
    tries=1
    while [ $tries -lt 5 ]; do
        current_deleted_stacks=$deleted_stacks
        for cf_stack_id in $current_deleted_stacks; do
            CF_STACKS_JSON=$(aws --region ${REGION} cloudformation describe-stacks --query "Stacks[?StackId == \`${cf_stack_id}\`]")
            if [ "${CF_STACKS_JSON}" == "[]" ]; then
                echo "Stack $cf_stack_id was deleted"
                deleted_stacks=$(echo "$deleted_stacks" | sed '/${cf_stack_id}\n/d')
            fi
        done
        if [ -z "$deleted_stacks" ]; then
            break
        fi
        tries=$((tries+1))
        echo -n "."
        sleep 60
    done
    echo ""
fi

# Delete VPCs and their dependencies
echo "Checking VPCs..."
VPCS_JSON=$(aws ec2 --region ${REGION} describe-vpcs --query 'Vpcs[?Tags[?Key == `ig-ci-timestamp`]]')
VPCS_WITH_TIMESTAMP=$(echo $VPCS_JSON | jq -c '.[] | {VpcId: .VpcId, Timestamp: (.Tags[]? | select(.Key == "ig-ci-timestamp").Value)}')

for vpc_with_timestamp in $VPCS_WITH_TIMESTAMP; do
    vpc=$(echo $vpc_with_timestamp |  | jq -r '.VpcId')
    timestamp=$(echo $vpc_with_timestamp |  | jq -r '.Timestamp')
    timestamp=$(date -d $timestamp +%s)

    # Skip VPCs created in the last 3 hours
    if [ $timestamp -gt $(date -d "3 hours ago" +%s) ]; then
        echo "Skipping VPC $vpc"
        continue
    fi

    # detach and delete gateways
    igw=$(aws ec2 --region ${REGION} describe-internet-gateways --filters Name=attachment.vpc-id,Values=${vpc} | jq -r .InternetGateways[].InternetGatewayId)
    if [ "${igw}" != "null" ]; then
        for gw in ${igw}; do
            echo "Detaching internet gateway ${gw}"
            aws ec2 --region ${REGION} detach-internet-gateway --internet-gateway-id ${gw} --vpc-id ${vpc}
            echo "Deleting internet gateway ${gw}"
            aws ec2 --region ${REGION} delete-internet-gateway --internet-gateway-id ${gw}
        done
    fi

    # delete network interfaces
    subnets=$(aws ec2 --region ${REGION} describe-subnets --filters Name=vpc-id,Values=${vpc} | jq -r .Subnets[].SubnetId)
    if [ "${subnets}" != "null" ]; then
        for subnet in ${subnets}; do
            echo "Deleting network interfgaces in subnet ${subnet}"

            # get network interfaces
            network_interfaces=$(aws ec2 --region ${REGION} describe-network-interfaces --filters Name=subnet-id,Values=${subnet} | jq -r .NetworkInterfaces[].NetworkInterfaceId)
            if [ "${network_interfaces}" != "null" ]; then
                for ni in ${network_interfaces}; do
                    echo "Deleting network interface ${ni}"
                    aws ec2 --region ${REGION} delete-network-interface --network-interface-id ${ni}
                done
            fi
        done
    fi

    # delete security groups
    security_groups=$(aws ec2 --region ${REGION} \
        describe-security-groups --filters Name=vpc-id,Values=${vpc} | jq -r .SecurityGroups[].GroupId)
    if [ "${security_groups}" != "null" ]; then
        for sg in ${security_groups}; do
            # get security group name
            sg_name=$(aws ec2 --region ${REGION} describe-security-groups --group-ids ${sg} | jq -r .SecurityGroups[].GroupName)
            if [ "${sg_name}" == "default" ]; then
                continue
            fi
            echo "Deleting security group ${sg}"
            aws ec2 --region ${REGION} delete-security-group --group-id ${sg}
        done
    fi

    # delete subnets
    subnets=$(aws ec2 --region ${REGION} describe-subnets --filters Name=vpc-id,Values=${vpc} | jq -r .Subnets[].SubnetId)
    if [ "${subnets}" != "null" ]; then
        for subnet in ${subnets}; do
        echo "Deleting subnet ${subnet}"
        aws ec2 --region ${REGION} delete-subnet --subnet-id ${subnet}
        done
    fi

    echo "Deleting VPC ${vpc}"
    aws ec2 --region ${REGION} delete-vpc --vpc-id $vpc
done
