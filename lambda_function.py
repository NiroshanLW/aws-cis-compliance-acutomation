
import boto3
import os
import datetime

def lambda_handler(event, context):

    # Function to create a log metric filter
    def create_log_metric_filter(log_group_name, filter_name, filter_pattern, metric_namespace, metric_name):
        client = boto3.client('logs')
        
        response = client.put_metric_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern=filter_pattern,
            metricTransformations=[
                {
                    'metricNamespace': metric_namespace,
                    'metricName': metric_name,
                    'metricValue': '1'
                }
            ]
        )
        
        print(f"Log metric filter '{filter_name}' created successfully.")

   # Function to create a CloudWatch metric alarm
    def create_metric_alarm(alarm_name, metric_namespace, metric_name, comparison_operator, threshold, sns_topic_arn, alarm_description):
        client = boto3.client('cloudwatch')
        
        response = client.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_description,
            ComparisonOperator=comparison_operator,
            EvaluationPeriods=1,
            MetricName=metric_name,
            Namespace=metric_namespace,
            Period=60,
            Statistic='Sum',
            Threshold=threshold,
            ActionsEnabled=True,
            AlarmActions=[sns_topic_arn],
        )
        
        print(f"Alarm '{alarm_name}' created successfully.")

    # Function to create an SNS topic
    def create_sns_topic(topic_name):
        client = boto3.client('sns')
        
        response = client.create_topic(
            Name=topic_name
        )
        
        topic_arn = response['TopicArn']
        print(f"SNS topic '{topic_name}' created successfully.")
        
        return topic_arn

    # Function to subscribe an email address to a topic
    def subscribe_email_to_topic(topic_arn, email_address):
        client = boto3.client('sns')
        
        response = client.subscribe(
            TopicArn=topic_arn,
            Protocol='email',
            Endpoint=email_address
        )
        
        print(f"Email address '{email_address}' subscribed to the topic.")

    log_group_name = 'aws-cloudtrail-logs-630XXXXXXX434-108b2ae0' 

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.1	A log metric filter and alarm should exist for usage of the "root" user

    root_filter_name = 'RootUserUsageFilter'
    root_filter_pattern = '{$.userIdentity.type = "Root"}'
    root_metric_namespace = 'Custom/RootUser'
    root_metric_name = 'RootUserUsage'
    root_alarm_name = 'RootUserUsageAlarm'
    root_comparison_operator = 'GreaterThanThreshold'
    root_threshold = 0
    root_sns_topic_name = 'RootUserUsageTopic'
    root_email_address = 'your-email@example.com'  
    root_alarm_description = 'Usage of root user detected'

    # 1 Creating SNS topic   
    # 2 Subscribing email address to the topic
    # 3 Creating log metric filter    
    # 4 Creating metric alarm    
                        
    root_topic_arn = create_sns_topic(root_sns_topic_name)
    subscribe_email_to_topic(root_topic_arn, root_email_address)
    create_log_metric_filter(log_group_name, root_filter_name, root_filter_pattern, root_metric_namespace, root_metric_name)
    create_metric_alarm(root_alarm_name, root_metric_namespace, root_metric_name, root_comparison_operator, root_threshold, root_topic_arn, root_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.2	Ensure a log metric filter and alarm exist for unauthorized API calls

    unauthorized_filter_name = 'UnauthorizedAPICallsFilter'
    unauthorized_filter_pattern = '{$.errorCode = "AccessDenied"}'
    unauthorized_metric_namespace = 'Custom/UnauthorizedAPI'
    unauthorized_metric_name = 'UnauthorizedAPICalls'
    unauthorized_alarm_name = 'UnauthorizedAPICallsAlarm'
    unauthorized_comparison_operator = 'GreaterThanThreshold'
    unauthorized_threshold = 0
    unauthorized_sns_topic_name = 'UnauthorizedAPICallsTopic'
    unauthorized_email_address = 'your-email@example.com' 
    unauthorized_alarm_description = 'Unauthorized API calls detected'

    unauthorized_topic_arn = create_sns_topic(unauthorized_sns_topic_name)
    subscribe_email_to_topic(unauthorized_topic_arn, unauthorized_email_address)
    create_log_metric_filter(log_group_name, unauthorized_filter_name, unauthorized_filter_pattern, unauthorized_metric_namespace, unauthorized_metric_name)
    create_metric_alarm(unauthorized_alarm_name, unauthorized_metric_namespace, unauthorized_metric_name, unauthorized_comparison_operator, unauthorized_threshold, unauthorized_topic_arn, unauthorized_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.3	Ensure a log metric filter and alarm exist for Management Console sign-in without MFA

    signin_without_mfa_filter_name = 'SignInWithoutMFAFilter'
    signin_without_mfa_filter_pattern = '{$.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "No"}'
    signin_without_mfa_metric_namespace = 'Custom/SignInWithoutMFA'
    signin_without_mfa_metric_name = 'SignInWithoutMFA'
    signin_without_mfa_alarm_name = 'SignInWithoutMFAAlarm'
    signin_without_mfa_comparison_operator = 'GreaterThanThreshold'
    signin_without_mfa_threshold = 0
    signin_without_mfa_sns_topic_name = 'SignInWithoutMFATopic'
    signin_without_mfa_email_address = 'your-email@example.com' 
    signin_without_mfa_alarm_description = 'Management console sign-in without MFA detected'

    signin_without_mfa_topic_arn = create_sns_topic(signin_without_mfa_sns_topic_name)
    subscribe_email_to_topic(signin_without_mfa_topic_arn, signin_without_mfa_email_address)
    create_log_metric_filter(log_group_name, signin_without_mfa_filter_name, signin_without_mfa_filter_pattern, signin_without_mfa_metric_namespace, signin_without_mfa_metric_name)
    create_metric_alarm(signin_without_mfa_alarm_name, signin_without_mfa_metric_namespace, signin_without_mfa_metric_name, signin_without_mfa_comparison_operator, signin_without_mfa_threshold, signin_without_mfa_topic_arn, signin_without_mfa_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.4	Ensure a log metric filter and alarm exist for IAM policy changes

    iam_policy_changes_filter_name = 'IAMPolicyChangesFilter'
    iam_policy_changes_filter_pattern = '{$.eventName = "PutGroupPolicy" || $.eventName = "PutRolePolicy" || $.eventName = "PutUserPolicy" || $.eventName = "CreatePolicy" || $.eventName = "DeletePolicy" || $.eventName = "AttachGroupPolicy" || $.eventName = "DetachGroupPolicy" || $.eventName = "AttachRolePolicy" || $.eventName = "DetachRolePolicy" || $.eventName = "AttachUserPolicy" || $.eventName = "DetachUserPolicy"}'
    iam_policy_changes_metric_namespace = 'Custom/IAMPolicyChanges'
    iam_policy_changes_metric_name = 'IAMPolicyChanges'
    iam_policy_changes_alarm_name = 'IAMPolicyChangesAlarm'
    iam_policy_changes_comparison_operator = 'GreaterThanThreshold'
    iam_policy_changes_threshold = 0
    iam_policy_changes_sns_topic_name = 'IAMPolicyChangesTopic'
    iam_policy_changes_email_address = 'your-email@example.com'  
    iam_policy_changes_alarm_description = 'IAM policy changes detected'

    iam_policy_changes_topic_arn = create_sns_topic(iam_policy_changes_sns_topic_name)
    subscribe_email_to_topic(iam_policy_changes_topic_arn, iam_policy_changes_email_address)
    create_log_metric_filter(log_group_name, iam_policy_changes_filter_name, iam_policy_changes_filter_pattern, iam_policy_changes_metric_namespace, iam_policy_changes_metric_name)
    create_metric_alarm(iam_policy_changes_alarm_name, iam_policy_changes_metric_namespace, iam_policy_changes_metric_name, iam_policy_changes_comparison_operator, iam_policy_changes_threshold, iam_policy_changes_topic_arn, iam_policy_changes_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.5	Ensure a log metric filter and alarm exist for CloudTrail configuration changes

    cloudtrail_config_changes_filter_name = 'CloudTrailConfigChangesFilter'
    cloudtrail_config_changes_filter_pattern = '{$.eventName = "CreateTrail" || $.eventName = "UpdateTrail" || $.eventName = "DeleteTrail" || $.eventName = "StartLogging" || $.eventName = "StopLogging" || $.eventName = "PutEventSelectors" || $.eventName = "DeleteEventSelectors" || $.eventName = "CreateTrail" || $.eventName = "UpdateTrail" || $.eventName = "DeleteTrail"}'
    cloudtrail_config_changes_metric_namespace = 'Custom/CloudTrailConfigChanges'
    cloudtrail_config_changes_metric_name = 'CloudTrailConfigChanges'
    cloudtrail_config_changes_alarm_name = 'CloudTrailConfigChangesAlarm'
    cloudtrail_config_changes_comparison_operator = 'GreaterThanThreshold'
    cloudtrail_config_changes_threshold = 0
    cloudtrail_config_changes_sns_topic_name = 'CloudTrailConfigChangesTopic'
    cloudtrail_config_changes_email_address = 'your-email@example.com'  
    cloudtrail_config_changes_alarm_description = 'CloudTrail configuration changes detected'

    cloudtrail_config_changes_topic_arn = create_sns_topic(cloudtrail_config_changes_sns_topic_name)
    subscribe_email_to_topic(cloudtrail_config_changes_topic_arn, cloudtrail_config_changes_email_address)
    create_log_metric_filter(log_group_name, cloudtrail_config_changes_filter_name, cloudtrail_config_changes_filter_pattern, cloudtrail_config_changes_metric_namespace, cloudtrail_config_changes_metric_name)
    create_metric_alarm(cloudtrail_config_changes_alarm_name, cloudtrail_config_changes_metric_namespace, cloudtrail_config_changes_metric_name, cloudtrail_config_changes_comparison_operator, cloudtrail_config_changes_threshold, cloudtrail_config_changes_topic_arn,  cloudtrail_config_changes_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.6	Ensure a log metric filter and alarm exist for AWS Management Console authentication failures

    auth_failures_filter_name = 'AuthFailuresFilter'
    auth_failures_filter_pattern = '{$.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication"}'
    auth_failures_metric_namespace = 'Custom/AuthFailures'
    auth_failures_metric_name = 'AuthFailures'
    auth_failures_alarm_name = 'AuthFailuresAlarm'
    auth_failures_comparison_operator = 'GreaterThanThreshold'
    auth_failures_threshold = 0
    auth_failures_sns_topic_name = 'AuthFailuresTopic'
    auth_failures_email_address = 'your-email@example.com'  
    auth_failures_alarm_description = 'AWS Management Console authentication failures detected'

    auth_failures_topic_arn = create_sns_topic(auth_failures_sns_topic_name)
    subscribe_email_to_topic(auth_failures_topic_arn, auth_failures_email_address)
    create_log_metric_filter(log_group_name, auth_failures_filter_name, auth_failures_filter_pattern, auth_failures_metric_namespace, auth_failures_metric_name)
    create_metric_alarm(auth_failures_alarm_name, auth_failures_metric_namespace, auth_failures_metric_name, auth_failures_comparison_operator, auth_failures_threshold, auth_failures_topic_arn, auth_failures_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.7	Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs

    cmk_changes_filter_name = 'CMKChangesFilter'
    cmk_changes_filter_pattern = '{$.eventName = "DisableKey" || $.eventName = "ScheduleKeyDeletion"}'
    cmk_changes_metric_namespace = 'Custom/CMKChanges'
    cmk_changes_metric_name = 'CMKChanges'
    cmk_changes_alarm_name = 'CMKChangesAlarm'
    cmk_changes_comparison_operator = 'GreaterThanThreshold'
    cmk_changes_threshold = 0
    cmk_changes_sns_topic_name = 'CMKChangesTopic'
    cmk_changes_email_address = 'your-email@example.com'  
    cmk_changes_alarm_description = 'Disabling or scheduled deletion of customer created CMKs detected'

    cmk_changes_topic_arn = create_sns_topic(cmk_changes_sns_topic_name)
    subscribe_email_to_topic(cmk_changes_topic_arn, cmk_changes_email_address)
    create_log_metric_filter(log_group_name, cmk_changes_filter_name, cmk_changes_filter_pattern, cmk_changes_metric_namespace, cmk_changes_metric_name)
    create_metric_alarm(cmk_changes_alarm_name, cmk_changes_metric_namespace, cmk_changes_metric_name, cmk_changes_comparison_operator, cmk_changes_threshold, cmk_changes_topic_arn, cmk_changes_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.8	Ensure a log metric filter and alarm exist for S3 bucket policy changes

    s3_policy_changes_filter_name = 'S3PolicyChangesFilter'
    s3_policy_changes_filter_pattern = '{$.eventName = "PutBucketPolicy" || $.eventName = "DeleteBucketPolicy" || $.eventName = "PutBucketAcl" || $.eventName = "PutBucketCors" || $.eventName = "PutBucketLifecycle" || $.eventName = "PutBucketLogging" || $.eventName = "PutBucketNotification" || $.eventName = "PutBucketTagging" || $.eventName = "PutBucketReplication" || $.eventName = "DeleteBucketTagging" || $.eventName = "DeleteBucketReplication" || $.eventName = "DeleteBucketCors" || $.eventName = "DeleteBucketLifecycle" || $.eventName = "DeleteBucketWebsite"}'
    s3_policy_changes_metric_namespace = 'Custom/S3PolicyChanges'
    s3_policy_changes_metric_name = 'S3PolicyChanges'
    s3_policy_changes_alarm_name = 'S3PolicyChangesAlarm'
    s3_policy_changes_comparison_operator = 'GreaterThanThreshold'
    s3_policy_changes_threshold = 0
    s3_policy_changes_sns_topic_name = 'S3PolicyChangesTopic'
    s3_policy_changes_email_address = 'your-email@example.com'  
    s3_policy_changes_alarm_description = 'S3 bucket policy changes detected'

    s3_policy_changes_topic_arn = create_sns_topic(s3_policy_changes_sns_topic_name)
    subscribe_email_to_topic(s3_policy_changes_topic_arn, s3_policy_changes_email_address)
    create_log_metric_filter(log_group_name, s3_policy_changes_filter_name, s3_policy_changes_filter_pattern, s3_policy_changes_metric_namespace, s3_policy_changes_metric_name)
    create_metric_alarm(s3_policy_changes_alarm_name, s3_policy_changes_metric_namespace, s3_policy_changes_metric_name, s3_policy_changes_comparison_operator, s3_policy_changes_threshold, s3_policy_changes_topic_arn, s3_policy_changes_alarm_description)

    s3_policy_changes_filter_name2 = 'S3PolicyChangesFilter2'
    s3_policy_changes_filter_pattern2 = '{$.eventName = "DeleteBucketAnalyticsConfiguration" || $.eventName = "DeleteBucketMetricsConfiguration" || $.eventName = "DeleteBucketInventoryConfiguration" || $.eventName = "DeleteBucketIntelligentTieringConfiguration" || $.eventName = "DeleteBucketOwnershipControls" || $.eventName = "DeleteBucketPolicy" || $.eventName = "PutBucketWebsite" || $.eventName = "PutBucketAnalyticsConfiguration" || $.eventName = "PutBucketMetricsConfiguration" || $.eventName = "PutBucketInventoryConfiguration" || $.eventName = "PutBucketIntelligentTieringConfiguration" || $.eventName = "PutBucketOwnershipControls"}'
    s3_policy_changes_metric_namespace2 = 'Custom/S3PolicyChanges2'
    s3_policy_changes_metric_name2 = 'S3PolicyChanges2'
    s3_policy_changes_alarm_name2 = 'S3PolicyChangesAlarm2'
    s3_policy_changes_comparison_operator = 'GreaterThanThreshold'
    s3_policy_changes_threshold = 0
    s3_policy_changes_sns_topic_name2 = 'S3PolicyChangesTopic2'
    s3_policy_changes_email_address = 'your-email@example.com'  
    s3_policy_changes_alarm_description2 = 'S3 bucket policy changes detected'

    s3_policy_changes_topic_arn2 = create_sns_topic(s3_policy_changes_sns_topic_name2)
    subscribe_email_to_topic(s3_policy_changes_topic_arn2, s3_policy_changes_email_address)
    create_log_metric_filter(log_group_name, s3_policy_changes_filter_name2, s3_policy_changes_filter_pattern2, s3_policy_changes_metric_namespace2, s3_policy_changes_metric_name2)
    create_metric_alarm(s3_policy_changes_alarm_name2, s3_policy_changes_metric_namespace2, s3_policy_changes_metric_name2, s3_policy_changes_comparison_operator, s3_policy_changes_threshold, s3_policy_changes_topic_arn2, s3_policy_changes_alarm_description2)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.9	Ensure a log metric filter and alarm exist for AWS Config configuration changes

    config_changes_filter_name = 'ConfigChangesFilter'
    config_changes_filter_pattern = '{$.eventName = "PutConfigRule" || $.eventName = "DeleteConfigRule" || $.eventName = "PutConfigurationAggregator" || $.eventName = "DeleteConfigurationAggregator" || $.eventName = "PutRemediationConfigurations" || $.eventName = "DeleteRemediationConfiguration" || $.eventName = "PutRetentionConfiguration" || $.eventName = "DeleteRetentionConfiguration" || $.eventName = "PutOrganizationConfigRule" || $.eventName = "DeleteOrganizationConfigRule" || $.eventName = "PutOrganizationConformancePack" || $.eventName = "DeleteOrganizationConformancePack"|| $.eventName = "PutAggregateEvaluationResult" }'
    config_changes_metric_namespace = 'Custom/ConfigChanges'
    config_changes_metric_name = 'ConfigChanges'
    config_changes_alarm_name = 'ConfigChangesAlarm'
    config_changes_comparison_operator = 'GreaterThanThreshold'
    config_changes_threshold = 0
    config_changes_sns_topic_name = 'ConfigChangesTopic'
    config_changes_email_address = 'your-email@example.com'  
    config_changes_alarm_description = 'AWS Config configuration changes detected'

    config_changes_topic_arn = create_sns_topic(config_changes_sns_topic_name)
    subscribe_email_to_topic(config_changes_topic_arn, config_changes_email_address)
    create_log_metric_filter(log_group_name, config_changes_filter_name, config_changes_filter_pattern, config_changes_metric_namespace, config_changes_metric_name)
    create_metric_alarm(config_changes_alarm_name, config_changes_metric_namespace, config_changes_metric_name, config_changes_comparison_operator, config_changes_threshold, config_changes_topic_arn, config_changes_alarm_description)

    config_changes_filter_name2 = 'ConfigChangesFilter2'
    config_changes_filter_pattern2 = '{ $.eventName = "PutAggregateEvaluationResult" || $.eventName = "PutOrganizationConformancePack" || $.eventName = "DeleteOrganizationConformancePack" || $.eventName = "PutConfigRule" || $.eventName = "DeleteConfigRule" || $.eventName = "PutConfigurationAggregator" || $.eventName = "DeleteConfigurationAggregator" || $.eventName = "PutRemediationConfigurations" || $.eventName = "DeleteRemediationConfiguration" || $.eventName = "PutRetentionConfiguration" || $.eventName = "DeleteRetentionConfiguration" || $.eventName = "PutOrganizationConfigRule" || $.eventName = "DeleteOrganizationConfigRule" }'
    config_changes_metric_namespace2 = 'Custom/ConfigChanges2'
    config_changes_metric_name2 = 'ConfigChanges2'
    config_changes_alarm_name2 = 'ConfigChangesAlarm2'
    config_changes_comparison_operator = 'GreaterThanThreshold'
    config_changes_threshold = 0
    config_changes_sns_topic_name2 = 'ConfigChangesTopic2'
    config_changes_email_address = 'your-email@example.com'  
    config_changes_alarm_description2 = 'AWS Config configuration changes detected'

    config_changes_topic_arn2 = create_sns_topic(config_changes_sns_topic_name2)
    subscribe_email_to_topic(config_changes_topic_arn2, config_changes_email_address)
    create_log_metric_filter(log_group_name, config_changes_filter_name2, config_changes_filter_pattern2, config_changes_metric_namespace2, config_changes_metric_name2)
    create_metric_alarm(config_changes_alarm_name2, config_changes_metric_namespace2, config_changes_metric_name2, config_changes_comparison_operator, config_changes_threshold, config_changes_topic_arn2, config_changes_alarm_description2)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.10	Ensure a log metric filter and alarm exist for security group changes

    sg_filter_name = 'SecurityGroupChangeFilter'
    sg_filter_pattern = '{$.eventName = "AuthorizeSecurityGroupIngress" || $.eventName = "AuthorizeSecurityGroupEgress" || $.eventName = "RevokeSecurityGroupIngress" || $.eventName = "RevokeSecurityGroupEgress"}'
    sg_metric_namespace = 'Custom/SecurityGroup'
    sg_metric_name = 'SecurityGroupChanges'
    sg_alarm_name = 'SecurityGroupChangeAlarm'
    sg_comparison_operator = 'GreaterThanThreshold'
    sg_threshold = 0
    sg_sns_topic_name = 'SecurityGroupChangesTopic'
    sg_email_address = 'your-email@example.com' 
    sg_alarm_description = 'Security group changes detected'

    sg_topic_arn = create_sns_topic(sg_sns_topic_name)
    subscribe_email_to_topic(sg_topic_arn, sg_email_address)
    create_log_metric_filter(log_group_name, sg_filter_name, sg_filter_pattern, sg_metric_namespace, sg_metric_name)
    create_metric_alarm(sg_alarm_name, sg_metric_namespace, sg_metric_name, sg_comparison_operator, sg_threshold, sg_topic_arn, sg_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.11	Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)

    nacl_changes_filter_name = 'NACLChangesFilter'
    nacl_changes_filter_pattern = '{$.eventName = "CreateNetworkAcl" || $.eventName = "CreateNetworkAclEntry" || $.eventName = "DeleteNetworkAcl" || $.eventName = "DeleteNetworkAclEntry" || $.eventName = "ReplaceNetworkAclEntry" || $.eventName = "ReplaceNetworkAclAssociation"}'
    nacl_changes_metric_namespace = 'Custom/NACLChanges'
    nacl_changes_metric_name = 'NACLChanges'
    nacl_changes_alarm_name = 'NACLChangesAlarm'
    nacl_changes_comparison_operator = 'GreaterThanThreshold'
    nacl_changes_threshold = 0
    nacl_changes_sns_topic_name = 'NACLChangesTopic'
    nacl_changes_email_address = 'your-email@example.com'  
    nacl_changes_alarm_description = 'Changes to Network Access Control Lists (NACL) detected'

    nacl_changes_topic_arn = create_sns_topic(nacl_changes_sns_topic_name)
    subscribe_email_to_topic(nacl_changes_topic_arn, nacl_changes_email_address)
    create_log_metric_filter(log_group_name, nacl_changes_filter_name, nacl_changes_filter_pattern, nacl_changes_metric_namespace, nacl_changes_metric_name)
    create_metric_alarm(nacl_changes_alarm_name, nacl_changes_metric_namespace, nacl_changes_metric_name, nacl_changes_comparison_operator, nacl_changes_threshold, nacl_changes_topic_arn, nacl_changes_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.12	Ensure a log metric filter and alarm exist for changes to network gateways

    network_gateway_changes_filter_name = 'NetworkGatewayChangesFilter'
    network_gateway_changes_filter_pattern = '{$.eventName = "CreateCustomerGateway" || $.eventName = "DeleteCustomerGateway" || $.eventName = "AttachInternetGateway" || $.eventName = "CreateInternetGateway" || $.eventName = "DeleteInternetGateway" || $.eventName = "DetachInternetGateway" || $.eventName = "AttachVpnGateway" || $.eventName = "CreateVpnGateway" || $.eventName = "DeleteVpnGateway" || $.eventName = "DetachVpnGateway" || $.eventName = "CreateVpnConnection" || $.eventName = "DeleteVpnConnection" || $.eventName = "ModifyVpnConnection"}'
    network_gateway_changes_metric_namespace = 'Custom/NetworkGatewayChanges'
    network_gateway_changes_metric_name = 'NetworkGatewayChanges'
    network_gateway_changes_alarm_name = 'NetworkGatewayChangesAlarm'
    network_gateway_changes_comparison_operator = 'GreaterThanThreshold'
    network_gateway_changes_threshold = 0
    network_gateway_changes_sns_topic_name = 'NetworkGatewayChangesTopic'
    network_gateway_changes_email_address = 'your-email@example.com'  
    network_gateway_changes_alarm_description = 'Changes to network gateways detected'

    network_gateway_changes_topic_arn = create_sns_topic(network_gateway_changes_sns_topic_name)
    subscribe_email_to_topic(network_gateway_changes_topic_arn, network_gateway_changes_email_address)
    create_log_metric_filter(log_group_name, network_gateway_changes_filter_name, network_gateway_changes_filter_pattern, network_gateway_changes_metric_namespace, network_gateway_changes_metric_name)
    create_metric_alarm(network_gateway_changes_alarm_name, network_gateway_changes_metric_namespace, network_gateway_changes_metric_name, network_gateway_changes_comparison_operator, network_gateway_changes_threshold, network_gateway_changes_topic_arn, network_gateway_changes_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CIS CloudWatch.13	Ensure a log metric filter and alarm exist for route table changes

    route_table_changes_filter_name = 'RouteTableChangesFilter'
    route_table_changes_filter_pattern = '{$.eventName = "CreateRouteTable" || $.eventName = "DeleteRouteTable" || $.eventName = "ReplaceRoute" || $.eventName = "CreateRoute" || $.eventName = "DeleteRoute" || $.eventName = "AssociateRouteTable" || $.eventName = "DisassociateRouteTable"}'
    route_table_changes_metric_namespace = 'Custom/RouteTableChanges'
    route_table_changes_metric_name = 'RouteTableChanges'
    route_table_changes_alarm_name = 'RouteTableChangesAlarm'
    route_table_changes_comparison_operator = 'GreaterThanThreshold'
    route_table_changes_threshold = 0
    route_table_changes_sns_topic_name = 'RouteTableChangesTopic'
    route_table_changes_email_address = 'your-email@example.com'  
    route_table_changes_alarm_description = 'Route table changes detected'

    route_table_changes_topic_arn = create_sns_topic(route_table_changes_sns_topic_name)
    subscribe_email_to_topic(route_table_changes_topic_arn, route_table_changes_email_address)
    create_log_metric_filter(log_group_name, route_table_changes_filter_name, route_table_changes_filter_pattern, route_table_changes_metric_namespace, route_table_changes_metric_name)
    create_metric_alarm(route_table_changes_alarm_name, route_table_changes_metric_namespace, route_table_changes_metric_name, route_table_changes_comparison_operator, route_table_changes_threshold, route_table_changes_topic_arn, route_table_changes_alarm_description)

#CIS AWS Foundations Benchmark v1.2.0
#CloudWatch.14	Ensure a log metric filter and alarm exist for VPC changes

    vpc_changes_filter_name = 'VPCChangesFilter'
    vpc_changes_filter_pattern = '{$.eventName = "CreateVpc" || $.eventName = "DeleteVpc" || $.eventName = "ModifyVpcAttribute" || $.eventName = "AcceptVpcPeeringConnection" || $.eventName = "CreateVpcPeeringConnection" || $.eventName = "DeleteVpcPeeringConnection" || $.eventName = "RejectVpcPeeringConnection" || $.eventName = "AttachClassicLinkVpc" || $.eventName = "DetachClassicLinkVpc"}'
    vpc_changes_metric_namespace = 'Custom/VPCChanges'
    vpc_changes_metric_name = 'VPCChanges'
    vpc_changes_alarm_name = 'VPCChangesAlarm'
    vpc_changes_comparison_operator = 'GreaterThanThreshold'
    vpc_changes_threshold = 0
    vpc_changes_sns_topic_name = 'VPCChangesTopic'
    vpc_changes_email_address = 'your-email@example.com'  
    vpc_changes_alarm_description = 'VPC changes detected'

    vpc_changes_topic_arn = create_sns_topic(vpc_changes_sns_topic_name)
    subscribe_email_to_topic(vpc_changes_topic_arn, vpc_changes_email_address)
    create_log_metric_filter(log_group_name, vpc_changes_filter_name, vpc_changes_filter_pattern, vpc_changes_metric_namespace, vpc_changes_metric_name)
    create_metric_alarm(vpc_changes_alarm_name, vpc_changes_metric_namespace, vpc_changes_metric_name, vpc_changes_comparison_operator, vpc_changes_threshold, vpc_changes_topic_arn, vpc_changes_alarm_description)

#Calling main Lambda Function

if __name__ == '__main__':
    lambda_handler(None, None)



