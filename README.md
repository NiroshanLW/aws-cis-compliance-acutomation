# Compliance as a Code with Cloud Custodian and Python

Cloud Custodian is an open-source tool and a Domain Specific Language used for managing public cloud environments. It can help your organization to maintain security and compliance by automating policy enforcement across multiple accounts and services. Cloud Custodian is designed to work with various cloud providers, including Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).


The tool is highly customizable, allowing users to create policies that define how resources should be managed. Policies can be written in simple YAML syntax and can range from simple actions like stopping unused instances to more complex actions like managing access control lists (ACLs) or cleaning up unused storage resources.

It helps organizations maintain security and compliance by automating policy enforcement across multiple cloud accounts and services.
It helps organizations save costs by automating resource management by identifying and taking action on unused resources.
It is highly customizable, allowing organizations to tailor policies to their specific needs.
It is an open-source tool, which means it can be used by organizations without incurring licensing costs.
You can install Cloud Custodian on Ubuntu Linux using the following commands:

Install Python and pip:
sudo apt-get update
sudo apt-get install python3-pip
2. Install Cloud Custodian using pip:

python3 -m venv custodian
source custodian/bin/activate
pip install c7n
3. Verify that Cloud Custodian is installed:

custodian version


(custodian) xxxanw@NXXXW-PC:/mnt/d//cloud-c$ custodian version
0.9.26
This should display the version number of Cloud Custodian if it is installed correctly.

Here is my first policy which is triggered when a new S3 bucket is created and it applies few best practice configurations to the bucket automatically. This eliminate configuration mismatches and mistakes done by developers. Also it helps to automatically satisfy the requirements of cloud compliances such as CIS.

    - name: s3-best-practice-config
      resource: s3
      description: |
        This policy is triggered when a new S3 bucket is created and it applies
        few best practice configurations to the bucket automatically. 
        This eliminate configuration missmatches and mistakes done by developers.
      mode:
        type: cloudtrail
        events:
          - CreateBucket
        role: arn:aws:iam::XXXXXXXX7434:role/XXXXXX-custodian-role
        timeout: 200
      actions:
       - type: set-public-block
         BlockPublicAcls: true
         BlockPublicPolicy: true
         IgnorePublicAcls: true
         RestrictPublicBuckets: true
       - type: auto-tag-user
         tag: CreatorName
       - type: set-bucket-encryption
       - type: toggle-versioning
         enabled: true
This policy, named s3-best-practice-config, is designed to ensure that best practice configurations are applied automatically to newly created S3 buckets in an AWS account. Here's a breakdown of the policy:

name: The name of the policy.
resource: The AWS resource that the policy applies to. In this case, it applies to S3 buckets.
description: A description of what the policy does. This policy automatically applies best practice configurations to new S3 buckets to eliminate configuration mismatches and mistakes.
mode: This specifies the event source that triggers the policy. In this case, the policy is triggered when a new S3 bucket is created via a CloudTrail event — in this case it is “CreateBucket” event. The role specifies the IAM role that Cloud Custodian uses to access the AWS APIs.
actions: This section lists the actions that the policy takes when it's triggered. There are three actions in this policy:
set-public-block: This action sets the best practice configurations for blocking public access to the S3 bucket by setting various properties:
auto-tag-user: This action automatically adds a tag to the S3 bucket with the name of the user who created the bucket. The tag key is CreatorName.
set-bucket-encryption: This action automatically enables server-side encryption for the S3 bucket.
toggle-versioning: This action automatically enables versioning for the S3 bucket.
Together, these actions it ensured that newly created S3 buckets in my AWS environment are configured with best practice settings for security, compliance, and governance. Then you can use below command to apply this policy into your AWS environment,

custodian run s3-best-practice-config.yaml -s out
