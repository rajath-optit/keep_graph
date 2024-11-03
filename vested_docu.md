AWS vested report  
-client: vested 
- Report Name: AWS vested report. 
-Report Date: Wednesday, 29 June 2024 
-Report Version: Version 1.0 

Overview: 

The AWS Compliance module offers a robust suite of benchmarks and controls designed to evaluate your AWS account against various compliance frameworks, including the CIS Amazon Web Services Foundations Benchmark. This report leverages these pre-built benchmarks to measure how well your cloud infrastructure aligns with standard frameworks such as CIS, GDPR, NIST, PCI, SOC 2, and others. Through rich visualizations like charts, graphs, and tables, this report provides an in-depth view of security compliance, offering valuable insights into your resources. 

This report includes filtered results and customized groupings organized by specific AWS services, addressing questions like: 

Resource Inventory: "How many of this resource type do I have?" 

Counts by Accounts and Regions: Provides a breakdown of resources across accounts and geographical regions. 

Configuration Percentages: Tracks the percentage of resources configured in specific ways (e.g., whether encryption is enabled). 

Resource Age: Reveals the age of each resource for lifecycle management. 

Additionally, resource detail reports are accessible via dashboard drilldowns or by manually selecting a resource name. These detailed views provide configurations and relational insights, enabling deeper questions such as: 

Resource Relationships: "What are the relationships between this resource and others?" 

Public Accessibility: Identifies if a resource is publicly accessible. 

Encryption Details: Shows whether encryption is enabled, along with the encryption keys used. 

Versioning Status: Checks if versioning is enabled. 

Networking Rules: Lists ingress and egress rules associated with the resource. 

For a detailed analysis of each service, please refer to the Excel sheet provided. It includes descriptions, recommendations, priorities, and steps to address each identified issue, guiding you through enhancing security within the Vested AWS account. 
 
LINK OF DETAILED REPORT: https://optit2022-my.sharepoint.com/:x:/r/personal/rajath_h_optit_in/Documents/Microsoft%20Teams%20Chat%20Files/vested_final_report.xlsx?d=w3861ae95fd7344538eab94d334b880b2&csf=1&web=1&e=l4Ab92&nav=MTVfe0QwMjdDRjIzLTNBNDEtNDRBRi05RjUyLTg1QjU2MUY5REMyM30. 
 

Key Components: 

S.No 

Pillar 

Control Number / Sheet Name 

1 

Security 

1.0 IAM 

 

 

1.1 Storage (S3, EBS, RDS) 

 

 

1.2 Compute (EC2) 

 

 

1.3 Network (VPC, ELB, AS, R53) 

 

 

Security Hub, Secrets Manager, WAFv2 

 

 

ACM, EKS, Lambda 

 

 

1.6 Safe (Other Remaining) 

Explanation of Key Components 

1.0 IAM: Includes all controls related to Identity and Access Management (IAM), ensuring secure and regulated access to AWS resources. 

1.1 Storage (S3, EBS, RDS): Addresses storage solutions, covering the security and compliance measures for S3 (Simple Storage Service), EBS (Elastic Block Store), and RDS (Relational Database Service). 

1.2 Compute (EC2): Focuses on compute resources, primarily EC2 (Elastic Compute Cloud), to assess the security and configuration of AWS compute instances. 

1.3 Network (VPC, ELB, AS, R53): Pertains to network configurations, ensuring security for components like VPC (Virtual Private Cloud), ELB (Elastic Load Balancing), AS (Auto Scaling), and R53 (Route 53). 

Security Hub, Secrets Manager, and WAFv2: These are critical services for enhancing overall security. Security Hub provides centralized security alerts, Secrets Manager manages sensitive information, and WAFv2 (Web Application Firewall) protects web applications from common threats. 

ACM, EKS, Lambda: Represents additional AWS services including ACM (AWS Certificate Manager), EKS (Elastic Kubernetes Service), and Lambda (serverless compute), all essential for securing workloads in diverse architectures. 

1.5 Unsafe (Other Remaining): Includes remaining resources that require further review after addressing the primary security controls. 

1.6 Safe (Other Remaining): Consists of items classified as safe, adhering to best practices and AWS Well-Architected Framework standards. 

This classification provides a structured approach to monitoring and securing AWS resources, guiding prioritization for security improvements across different service categories. 

ACM					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
1	ACM 	ACM certificates should not use wildcard certificates 	Ensures certificates do not use wildcards for enhanced security. 	3	Critical
					
Auto Scaling 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
2	Auto Scaling 	EC2 instances should require IMDSv2 	Configures EC2 instances to use IMDSv2  mitigating security risks. 	8	Critical
3	Auto Scaling 	No suspended processes in Auto Scaling groups 	All processes are active to maintain reliability and scaling functionality. 	44	Critical
4	Auto Scaling 	Health checks for load-balanced Auto Scaling groups 	Ensures load-balanced Auto Scaling groups have health checks for operational stability. 	30	Critical
5	Auto Scaling 	User data in launch configurations should not contain sensitive data 	Prevents sensitive data in user data scripts to avoid unintended exposure. 	1	Critical
6	Auto Scaling 	Auto Scaling groups should span multiple availability zones 	Ensures redundancy across zones to improve resilience. 	7	Critical
7	Auto Scaling 	Use EC2 launch templates in Auto Scaling groups 	Launch templates should be used for consistency and resource optimization. 	16	Critical
8	Auto Scaling 	Multiple instance types and availability zones 	Requires use of diverse instance types and zones for scalability and failover. 	44	Critical
					
EBS 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
9	EBS 	Delete on termination for attached volumes 	Configures volumes to delete on termination preventing orphaned storage costs. 	54	Medium
10	EBS 	Encryption enabled for attached volumes 	Ensures all EBS volumes attached to instances have encryption enabled for data protection. 	76	Critical
11	EBS 	Snapshot encryption 	Protects snapshot data by enforcing encryption at rest. 	19	Critical
12	EBS 	Encryption at rest for EBS volumes 	Secures data at rest in volumes through encryption. 	75	Critical
13	EBS 	Volume snapshots availability 	Confirms EBS volumes are backed up through snapshots to prevent data loss. 	152	Critical
14	EBS 	Volumes should be attached to EC2 instances 	Ensures volumes are correctly attached to prevent wasted resources. 	28	Critical
15	EBS 	Backup plan for EBS volumes 	Enforces that volumes are included in a backup plan for data retention. 	164	Critical
					
EC2 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
16	EC2 	Termination protection for instances 	Prevents accidental termination of EC2 instances by enabling termination protection. 	113	Critical
17	EC2 	Detailed monitoring enabled for EC2 instances 	Ensures that detailed monitoring is active for improved tracking of EC2 instance performance. 	113	Medium
18	EC2 	IAM role with restricted access for instances 	Prevents credentials exposure through strict IAM roles. 	81	Critical
19	EC2 	EBS optimization enabled for instances 	Ensures that instances have EBS optimization enabled for enhanced performance. 	87	Medium
20	EC2 	Instances located within a VPC 	Confirms all EC2 instances are running within a VPC for secure networking. 	2	Critical
21	EC2 	Backup plan coverage for instances 	Ensures all EC2 instances are included in a backup plan. 	113	Critical
22	EC2 	IAM profile attached to instances 	Validates that instances have an IAM profile attached for access management. 	32	Critical
23	EC2 	Instances avoid 'launch wizard' security groups 	Avoids using default security groups that may lack security customization. 	2	Critical
24	EC2 	Instances without public IPs 	Restricts public IP assignment to prevent direct internet access. 	11	Critical
25	EC2 	No key pairs in running state for instances 	Ensures no active key pairs in instances to avoid unauthorized access. 	100	Critical
26	EC2 	Single ENI usage for instances 	Limits instances to a single Elastic Network Interface (ENI) for simplified network configs. 	38	Medium
27	EC2 	IMDSv2 usage for instances 	Enforces use of Instance Metadata Service Version 2 for enhanced security. 	95	Critical
28	EC2 	Secrets excluded from user data 	Prevents secrets exposure in EC2 instance user data. 	69	Critical
29	EC2 	Removal of stopped instances after 30 days 	Ensures stopped instances are removed within 30 days to avoid unnecessary costs. 	2	Medium
30	EC2 	Attached EBS volumes delete on termination 	Configures attached EBS volumes to delete upon instance termination to prevent unused storage. 	14	Medium
31	EC2 	Images (AMIs) are recent (within 90 days) 	Ensures that AMIs in use are updated regularly  within 90 days. 	26	Medium
32	EC2 	Encrypted AMIs 	Protects AMIs through encryption to secure the data in images. 	10	Critical
33	EC2 	Removal of instances stopped for over 90 days 	Maintains instance lifecycle by removing inactive instances over 90 days. 	1	Medium
34	EC2 	Instances not older than 180 days 	Ensures all instances are periodically refreshed within 180 days for performance and security. 	28	Critical
35	EC2 	Public instances have IAM profile attached 	Confirms public instances are secure with appropriate IAM profile attached. 	6	Critical
					
EKS 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
36	EKS 	Kubernetes secrets encryption using KMS 	Ensures Kubernetes secrets in EKS clusters are encrypted using AWS KMS for added data security. 	2	Critical
37	EKS 	Control plane audit logging enabled 	Enables logging for control plane operations in EKS  assisting in audit and security tracking. 	2	High
					
ELB 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
38	ELB 	Connection draining enabled on Classic Load Balancers 	Ensures Classic Load Balancers drain connections properly before scaling in or out. 	1	Medium
39	ELB 	Logging enabled for application and classic load balancers 	Enables logging for monitoring ELB traffic  assisting in troubleshooting and auditing. 	17	High
40	ELB 	SSL/HTTPS listeners on load balancers only 	Configures load balancers to only use SSL or HTTPS for secure data transit. 	22	Critical
41	ELB 	Deletion protection enabled for application load balancers 	Protects application load balancers from accidental deletion. 	21	High
42	ELB 	Drop HTTP headers on application load balancers 	Configures load balancers to drop HTTP headers to enhance privacy and security. 	21	Medium
43	ELB 	Web Application Firewall (WAF) enabled for application load balancers 	Adds WAF protection to filter out malicious requests  enhancing security. 	21	Critical
44	ELB 	HTTP to HTTPS redirection on application load balancers 	Ensures HTTP requests are redirected to HTTPS to enforce secure connections. 	3	High
45	ELB 	Cross-zone load balancing on classic load balancers 	Balances traffic across multiple availability zones for improved resilience and performance. 	1	Medium
46	ELB 	SSL/HTTPS listeners for classic load balancers 	Ensures Classic Load Balancers use SSL or HTTPS for secure communication. 	1	High
47	ELB 	Secure SSL cipher usage on ELB listeners 	Configures ELB listeners to use secure SSL ciphers for safe data transmission. 	46	Critical
48	ELB 	Load balancers prohibit public access 	Prevents public access to ELB load balancers  restricting access to private networks. 	18	Critical
49	ELB 	TLS listener security policy on network load balancers 	Configures TLS security policy for network load balancers to maintain secure communication. 	1	High
					
IAM 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
50	IAM 	Support role created for AWS Support incident management 	Ensures a dedicated support role is created for handling AWS Support incidents efficiently. 	1	High
51	IAM 	Password policy prevents password reuse 	Prevents users from reusing previous passwords  strengthening password security. 	1	High
52	IAM 	Password policy requires at least one number 	Enforces inclusion of numeric characters in passwords for better security. 	1	Medium
53	IAM 	Password policy requires at least one symbol 	Enforces inclusion of special characters in passwords to enhance security. 	1	Medium
54	IAM 	Policies attached only to groups or roles 	Ensures policies are attached to IAM groups or roles only  not to individual users. 	17	High
55	IAM 	No full ":" administrative privileges in policies 	Prevents granting full access through IAM policies to minimize risks. 	1	Critical
56	IAM 	Policies should not grant full access to any service 	Limits permissions in policies to prevent unauthorized access. 	38	Critical
57	IAM 	Administrator access policy should not be attached to any role 	Avoids over-permissioning by preventing administrator access attachment to roles. 	2	High
58	IAM 	Inline policies should not allow blocked actions on KMS keys 	Prevents inline policies from allowing restricted actions on KMS keys. 	1	Critical
59	IAM 	Managed policies should not allow blocked actions on KMS keys 	Ensures managed policies do not grant unauthorized actions on KMS keys. 	5	High
60	IAM 	IAM Access Analyzer enabled in all regions 	Enables IAM Access Analyzer for comprehensive monitoring across all regions. 	16	Medium
61	IAM 	Only one active access key per IAM user 	Restricts IAM users to one active access key for security. 	4	Medium
62	IAM 	AWS managed policies attached to IAM roles 	Requires use of AWS managed policies on IAM roles for standardized permission management. 	1146	High
63	IAM 	IAM groups should have at least one user 	Ensures IAM groups are populated with users for accountability. 	2	Medium
64	IAM 	No inline policies on groups	" users  or roles Disallows inline policies for roles	 groups	 or users to maintain policy consistency. "	33	High
65	IAM 	Strong password configurations for IAM users 	Enforces strong password policies for IAM users to prevent unauthorized access. 	1	High
66	IAM 	IAM policy usage 	Ensures policies are in use and actively managed. 	1129	Medium
67	IAM 	IAM roles without assume role policies 	Avoids improper access control by limiting the usage of assume role policies. 	1	Medium
68	IAM 	Unused IAM roles removal 	Identifies and removes unused IAM roles for security and policy hygiene. 	123	Medium
69	IAM 	Hardware MFA enabled for root user 	Adds hardware MFA for root user to ensure strong authentication. 	1	Critical
70	IAM 	MFA enabled for root user 	Requires MFA for root user to enhance security. 	1	High
71	IAM 	Access key rotation every 90 days 	Enforces access key rotation for IAM users to maintain security. 	42	High
72	IAM 	No inline or attached policies for IAM users 	Prevents IAM users from having inline or attached policies for minimized risk. 	18	High
73	IAM 	Users must belong to at least one group 	Ensures IAM users are part of a group for better access management. 	9	Medium
74	IAM 	Hardware MFA for IAM users 	Adds hardware MFA for IAM users to secure account access. 	33	Critical
75	IAM 	Strong password policies for minimum length 	Ensures minimum password length of 8 characters for IAM users. 	1	Medium
					
Lambda 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
76	Lambda 	Cloudwatch Lambda insights enabled 	Enables Lambda insights for monitoring function performance and troubleshooting. 	21	High
77	Lambda 	Encryption in transit for environment variables 	Protects environment variables with encryption to secure sensitive data. 	21	High
78	Lambda 	CloudTrail logging enabled for Lambda functions 	Logs Lambda functions activities for enhanced auditing. 	21	High
79	Lambda 	Concurrent execution limit for Lambda functions 	Sets a limit on concurrent executions to avoid over-utilization. 	21	Medium
80	Lambda 	Lambda CORS configuration does not allow all origins 	Restricts CORS settings to prevent unauthorized cross-origin requests. 	20	High
81	Lambda 	Dead-letter queue configured for Lambda functions 	Provides a dead-letter queue for handling failed events in Lambda functions. 	21	High
82	Lambda 	Lambda functions in a VPC 	Configures Lambda functions within a VPC to restrict access to private resources. 	7	High
83	Lambda 	Multi-availability zone configuration for Lambda functions 	Ensures Lambda functions operate across multiple availability zones for redundancy. 	1	Medium
84	Lambda 	Lambda functions restrict public access 	Restricts public access to Lambda functions to prevent unauthorized use. 	1	High
85	Lambda 	Lambda functions restrict public URL access 	Prevents Lambda functions from being publicly accessible via URL. 	21	Critical
86	Lambda 	Lambda function tracing enabled 	Enables tracing for Lambda functions for better performance monitoring. 	21	Medium
87	Lambda 	No sensitive data in Lambda function variables 	Ensures Lambda variables do not contain sensitive data. 	13	High
					
RDS 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
88	RDS 	RDS event notifications subscription for critical cluster events 	Configures an RDS event notifications subscription to alert for critical cluster events. 	1	High
89	RDS 	RDS event notifications subscription for critical database instance events 	Ensures that an event notifications subscription is set for critical database instance events. 	1	High
90	RDS 	RDS event notifications subscription for critical database parameter group events 	Configures an event notifications subscription for critical database parameter group events. 	1	High
91	RDS 	RDS event notifications subscription for critical database security group events 	Ensures that an event notifications subscription is set for critical database security group events. 	1	High
92	RDS 	Aurora MySQL DB clusters publish audit logs to CloudWatch Logs 	Ensures that Aurora MySQL DB clusters publish audit logs to CloudWatch Logs for better monitoring. 	6	Medium
93	RDS 	Database logging should be enabled 	Ensures that database logging is enabled to maintain audit trails and access logs. 	13	Medium
94	RDS 	IAM authentication configured for RDS clusters 	Configures IAM authentication for enhanced security in RDS clusters. 	6	High
95	RDS 	RDS Aurora clusters protected by backup plan 	Ensures RDS Aurora clusters are protected by a backup plan to prevent data loss. 	6	High
96	RDS 	RDS Aurora clusters have backtracking enabled 	Enables backtracking for RDS Aurora clusters to restore to a previous state quickly. 	6	Medium
97	RDS 	RDS Aurora PostgreSQL clusters not exposed to local file read vulnerability 	Ensures RDS Aurora PostgreSQL clusters are not exposed to local file read vulnerabilities. 	5	High
98	RDS 	RDS clusters have deletion protection enabled 	Ensures deletion protection is enabled for RDS clusters to prevent accidental deletion. 	3	High
99	RDS 	RDS database clusters use a custom administrator username 	Configures RDS database clusters to use a custom administrator username for better security. 	1	High
100	RDS 	RDS database instances use a custom administrator username 	Configures RDS database instances to use a custom administrator username for better security. 	1	High
101	RDS 	RDS databases and clusters not use default database engine port 	Ensures that RDS databases and clusters do not use the default database engine port for security reasons. 	6	High
102	RDS 	RDS DB clusters configured for multiple Availability Zones 	Configures RDS DB clusters for high availability across multiple Availability Zones. 	4	High
103	RDS 	RDS DB clusters encrypted with CMK 	Ensures RDS DB clusters are encrypted with Customer Managed Keys (CMK) for added security. 	6	High
104	RDS 	RDS DB instance and cluster enhanced monitoring enabled 	Ensures that enhanced monitoring is enabled for RDS DB instances and clusters for better performance insights. 	15	Medium
105	RDS 	RDS DB instance multi-AZ should be enabled 	Ensures RDS DB instances are configured for multi-AZ deployment for high availability. 	13	High
106	RDS 	RDS DB instance protected by backup plan 	Ensures that RDS DB instances are protected by a backup plan to prevent data loss. 	13	High
107	RDS 	RDS DB instances connections encrypted 	Ensures that connections to RDS DB instances are encrypted for security. 	13	High
108	RDS 	RDS DB instances configured to copy tags to snapshots 	Ensures that RDS DB instances are configured to copy tags to their snapshots for better management. 	8	Medium
109	RDS 	RDS DB instances should be in a backup plan 	Ensures RDS DB instances are included in a backup plan for data safety. 	13	High
110	RDS 	RDS DB instances integrated with CloudWatch logs 	Ensures RDS DB instances are integrated with CloudWatch logs for monitoring and alerting. 	9	Medium
111	RDS 	RDS DB instances have deletion protection enabled 	Ensures that deletion protection is enabled for RDS DB instances to prevent accidental deletion. 	12	High
112	RDS 	RDS DB instances have IAM authentication enabled 	Ensures IAM authentication is enabled for RDS DB instances for enhanced security. 	13	High
113	RDS 	RDS DB instances should not use public subnet 	Ensures RDS DB instances are not deployed in a public subnet for security reasons. 	13	High
114	RDS 	RDS snapshots should be encrypted at rest 	Ensures that RDS snapshots are encrypted at rest for data protection. 	5	High
115	RDS 	RDS PostgreSQL DB instances not exposed to local file read vulnerability 	Ensures RDS PostgreSQL DB instances are not exposed to local file read vulnerabilities. 	11	High
					
S3 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
116	S3 	All data in AWS S3 discovered	" classified  and secured as required 	Ensures all S3 data is discovered classified and secured to meet compliance requirements. "	102	High
117	S3 	S3 buckets object logging enabled 	Ensures S3 buckets have object logging enabled for tracking access and changes. 	170	Medium
118	S3 	S3 buckets static website hosting disabled 	Ensures that static website hosting is disabled on S3 buckets to prevent unintended exposure. 	2	Medium
119	S3 	S3 public access blocked at account level 	Ensures that public access is blocked at the account level for enhanced security. 	2	High
					
Secrets Manager 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
120	Secrets Manager 	Secrets Manager secrets should be encrypted using CMK 	Ensures that all secrets are securely encrypted using Customer Master Keys (CMK). 	2	High
121	Secrets Manager 	Secrets Manager secrets should be rotated as per the rotation schedule 	Ensures that secrets are rotated regularly according to the defined schedule. 	2	High
122	Secrets Manager 	Secrets Manager secrets should be rotated within a specified number of days 	Ensures timely rotation of secrets to minimize exposure risk. 	2	High
123	Secrets Manager 	Secrets Manager secrets should be rotated within specific number of days 	Ensures that secrets are rotated within the specified timeframe. 	1	High
124	Secrets Manager 	Secrets Manager secrets should have automatic rotation enabled 	Ensures that secrets are automatically rotated without manual intervention. 	2	High
125	Secrets Manager 	Secrets Manager secrets that have not been used in 90 days should be removed 	Identifies and removes secrets that are no longer in use  enhancing security. 	1	High
126	Security Hub 	AWS Security Hub should be enabled for an AWS Account 	Ensures that Security Hub is active for centralized security management. 	2	High
					
VPC 					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
127	VPC 	Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports 	Prevents unauthorized access to critical server administration ports. 	2	High
128	VPC 	Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389 	Ensures that remote access ports are secured from unrestricted access. 	2	High
129	VPC 	Security groups should not allow unrestricted access to ports with high risk 	Reduces the risk of exploitation by restricting access to sensitive ports. 	2	High
130	VPC 	Unused EC2 security groups should be removed 	Helps to minimize security risk by cleaning up unused security groups. 	65	Medium
131	VPC 	VPC default security group should not allow inbound and outbound traffic 	Ensures the default security group is properly configured for security. 	2	High
132	VPC 	VPC endpoint services should have acceptance required enabled 	Ensures that only authorized services can connect to the endpoint. 	200	High
133	VPC 	VPC flow logs should be enabled 	Ensures that traffic logs are collected for auditing and monitoring. 	7	High
134	VPC 	VPC route table should restrict public access to IGW 	Prevents unauthorized access to the internet through the Internet Gateway. 	2	High
135	VPC 	VPC security groups should be associated with at least one ENI 	Ensures proper network interface assignment to security groups. 	65	Medium
136	VPC 	VPC Security groups should only allow unrestricted incoming traffic for authorized ports 	Limits exposure by allowing only specified ports to receive traffic. 	2	High
137	VPC 	VPC security groups should restrict ingress access on ports 20	2122,3306, 3389, 4333 from 0.0.0.0/0 Protects against unauthorized access to commonly exploited ports. 	2	High
138	VPC 	VPC security groups should restrict ingress SSH access from 0.0.0.0/0 	Secures SSH access by limiting source addresses. 	2	High
139	VPC 	VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0 	Ensures all ingress TCP and UDP traffic is properly controlled. 	54	High
140	VPC 	VPC security groups should restrict uses of 'launch-wizard' security groups 	Avoids reliance on default security groups that may not be appropriately configured. 	2	High
141	VPC 	VPC should be configured to use VPC endpoints 	Enhances security by ensuring all services utilize VPC endpoints. 	9	High
142	VPC 	VPC subnet auto assign public IP should be disabled 	Prevents instances from being assigned a public IP by default. 	33	Medium
143	VPC 	VPCs peering connection route tables should have least privilege 	Ensures that route tables are configured with the least privilege necessary for connectivity. 	16	Medium
144	VPC 	VPCs should exist in multiple regions 	Enhances resilience by distributing VPCs across multiple regions. 	1	High
145	VPC 	VPCs should have both public and private subnets configured 	Ensures proper segmentation and security of resources within VPCs. 	9	High
					
Account					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
1	Account	AWS account should be part of AWS Organizations	Ensures accounts are centrally managed, enhancing security and compliance.	1	Safe/Well Architected
					
CloudFormation					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
19	CloudFormation	CloudFormation stacks differ from the expected configuration	Indicates potential configuration drift that could lead to security vulnerabilities.	37	Critical
20	CloudFormation	CloudFormation stacks should have notifications enabled	Lack of notifications can delay response to configuration changes, increasing security risk.	37	Medium
21	CloudFormation	CloudFormation stacks termination protection should be enabled	Without termination protection, stacks could be accidentally deleted, causing service disruptions.	33	High
					
CloudFront					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
22	CloudFront	CloudFront distributions access logs should be enabled	Without access logs, tracking unauthorized access attempts becomes difficult, posing security risks.	15	Critical
23	CloudFront	CloudFront distributions should encrypt traffic to custom origins	Unencrypted traffic may expose sensitive data during transit, leading to potential data breaches.	12	Critical
24	CloudFront	CloudFront distributions should encrypt traffic to non-S3 origins	Non-encrypted traffic increases the risk of interception and data exposure.	12	Critical
25	CloudFront	CloudFront distributions should have a default root object configured	Without a default root object, users may face access issues, leading to degraded user experience.	15	Medium
26	CloudFront	CloudFront distributions should have AWS WAF enabled	Without AWS WAF, distributions are more vulnerable to attacks, increasing the risk of data breaches.	12	High
27	CloudFront	CloudFront distributions should have field-level encryption enabled	Without field-level encryption, sensitive data may be exposed, violating compliance regulations.	15	High
28	CloudFront	CloudFront distributions should have geo restriction enabled	Lack of geo restrictions can allow access from untrusted regions, increasing the risk of data breaches.	15	High
29	CloudFront	CloudFront distributions should have the latest TLS version	Using outdated TLS versions can expose traffic to vulnerabilities, increasing security risks.	15	Critical
30	CloudFront	CloudFront distributions should have origin access identity enabled	Without origin access identity, S3 origins may be exposed to the public, compromising data security.	26	High
31	CloudFront	CloudFront distributions should have origin failover configured	Failure to configure origin failover may lead to service disruptions during origin outages.	15	Medium
32	CloudFront	CloudFront distributions should not point to non-existent S3 origins	Pointing to non-existent origins can lead to unnecessary errors and service interruptions.	1	Medium
33	CloudFront	CloudFront distributions should require encryption in transit	Failing to enforce encryption can lead to data leaks and non-compliance with security standards.	5	Critical
34	CloudFront	CloudFront distributions should use custom SSL/TLS certificates	Not using custom certificates may lead to untrusted communications, jeopardizing data security.	3	High
35	CloudFront	CloudFront distributions should use secure SSL cipher	Using insecure ciphers can expose traffic to interception and potential exploitation.	15	High
36	CloudFront	CloudFront distributions should use SNI to serve HTTPS requests	Lack of SNI may result in improper SSL certificate validation, leading to security vulnerabilities.	3	Medium
					
CloudTrail					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
2	CloudTrail	All S3 buckets should log S3 data events in CloudTrail	Ensures auditing and monitoring of S3 data events, meeting compliance best practices.	102	Safe/Well Architected
37	CloudTrail	At least one CloudTrail trail should be enabled in the AWS account	Without CloudTrail, auditing and monitoring of account activity is severely limited, risking compliance.	1	Critical
38	CloudTrail	At least one multi-region AWS CloudTrail should be present in an account	Failing to enable multi-region trails may miss activities in unmonitored regions, increasing security risks.	1	Critical
39	CloudTrail	At least one trail should be enabled with security best practices	Without security best practices, trails may not capture all relevant events, hindering auditing capabilities.	2	High
					
CloudWatch					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
3	CloudWatch	CloudWatch should not allow cross-account sharing	Prevents unauthorized access to CloudWatch metrics, ensuring data integrity and compliance.	1	Safe/Well Architected
40	CloudWatch	CloudWatch alarm action should be enabled	Disabling alarm actions can delay incident responses, potentially increasing damage from security breaches.	1	High
41	CloudWatch	Ensure a log metric filter and alarm exist for AWS Config configuration changes	Lack of alerts for configuration changes can lead to unmonitored security issues.	1	High
42	CloudWatch	Ensure a log metric filter and alarm exist for AWS Management Console authentication failures	Without alerts for authentication failures, unauthorized access attempts may go unnoticed.	1	High
43	CloudWatch	Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA	Failing to alert on sign-ins without MFA increases vulnerability to unauthorized access.	1	High
44	CloudWatch	Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)	Lack of monitoring for NACL changes can expose the network to unauthorized access.	1	Medium
45	CloudWatch	Ensure a log metric filter and alarm exist for changes to network gateways	Unmonitored changes to network gateways can create vulnerabilities in network security.	1	Medium
46	CloudWatch	Ensure a log metric filter and alarm exist for CloudTrail configuration changes	Failing to monitor changes to CloudTrail can lead to gaps in auditing and compliance.	1	Medium
47	CloudWatch	Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys	Lack of alerts for key management changes can lead to unauthorized access to sensitive data.	1	High
48	CloudWatch	Ensure a log metric filter and alarm exist for IAM policy changes	Unmonitored changes to IAM policies can create security vulnerabilities by altering access permissions.	1	High
49	CloudWatch	Ensure a log metric filter and alarm exist for route table changes	Failing to monitor route table changes can lead to unintended network traffic routing, increasing risk.	1	Medium
50	CloudWatch	Ensure a log metric filter and alarm exist for S3 bucket policy changes	Lack of monitoring for bucket policy changes can lead to unauthorized data access.	1	High
51	CloudWatch	Ensure a log metric filter and alarm exist for security group changes	Unmonitored security group changes can expose resources to unwanted access, compromising security.	1	High
52	CloudWatch	Ensure a log metric filter and alarm exist for unauthorized API calls	Without alerts for unauthorized API calls, potential abuse or breaches may go unnoticed.	1	Critical
53	CloudWatch	Ensure a log metric filter and alarm exist for usage of 'root' account	Lack of monitoring for root account usage increases the risk of unauthorized access to sensitive resources.	1	Critical
54	CloudWatch	Ensure a log metric filter and alarm exist for VPC changes	Unmonitored VPC changes can expose the network to risks, compromising overall security.	1	Medium
55	CloudWatch	Ensure AWS Organizations changes are monitored	Lack of monitoring for AWS Organizations changes can lead to misconfigurations and increased risks.	1	Medium
56	CloudWatch	Log group encryption at rest should be enabled	Without encryption, logs may be exposed to unauthorized access, violating compliance requirements.	557	High
57	CloudWatch	Log group retention period should be at least 365 days	Short retention periods can lead to loss of crucial data needed for audits and investigations.	557	Medium
					
CodeBuild					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
4	CodeBuild	CodeBuild project plaintext environment variables should not contain sensitive AWS values	Ensures sensitive information is not exposed in environment variables, maintaining security compliance.	84	Safe/Well Architected
5	CodeBuild	CodeBuild projects should not be unused for 90 days or greater	Identifies and mitigates the risks associated with unused projects, promoting resource efficiency.	58	Safe/Well Architected
6	CodeBuild	CodeBuild projects should not use a user-controlled buildspec	Ensures that build processes are controlled and secure, preventing potential vulnerabilities.	84	Safe/Well Architected
58	CodeBuild	CodeBuild GitHub or Bitbucket source repository URLs should use OAuth	Using insecure methods for repository access can expose sensitive data, increasing security vulnerabilities.	79	High
59	CodeBuild	CodeBuild project artifact encryption should be enabled	Lack of artifact encryption can expose sensitive information during the build process.	10	Medium
60	CodeBuild	CodeBuild project environments should not have privileged mode enabled	Running projects in privileged mode increases the risk of exploitation through elevated permissions.	64	Critical
61	CodeBuild	CodeBuild projects should not be unused for 90 days or greater	Unused projects may pose security risks if not monitored or properly decommissioned.	26	Medium
					
Config					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
7	Config	Config configuration recorder should not fail to deliver logs	Ensures continuous monitoring and compliance by logging configuration changes.	1	Safe/Well Architected
62	Config	AWS Config should be enabled	Without AWS Config, tracking configuration changes becomes challenging, increasing the risk of misconfigurations.	30	Critical
					
DMS					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
8	DMS	DMS replication instances should not be publicly accessible	Protects sensitive data by ensuring that replication instances are not exposed to the public internet.	2	Safe/Well Architected
63	DMS	DMS endpoints should use SSL	Not using SSL for DMS endpoints can expose sensitive data during migration, increasing risks.	3	High
					
ECR					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
9	ECR	ECR repositories should have image scan on push enabled	Enhances security by scanning images for vulnerabilities upon being pushed to the repository.	34	Safe/Well Architected
10	ECR	ECR repositories should have lifecycle policies configured	Manages the lifecycle of images, reducing the risk of vulnerabilities from outdated images.	18	Safe/Well Architected
11	ECR	ECR repositories should prohibit public access	Ensures that ECR repositories are secure and not accessible to unauthorized users.	34	Safe/Well Architected
64	ECR	ECR private repositories should have tag immutability configured	Without tag immutability, unauthorized changes to image tags can lead to security vulnerabilities.	34	High
					
Elastic Beanstalk					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
65	Elastic Beanstalk	Elastic Beanstalk environment should have managed updates enabled	Without managed updates, environments may run outdated software, exposing vulnerabilities.	21	High
66	Elastic Beanstalk	Elastic Beanstalk should stream logs to CloudWatch	Failing to stream logs can hinder monitoring and troubleshooting, increasing security risks.	4	Medium
					
ElastiCache					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
67	ElastiCache	ElastiCache clusters should not use public_subnet	Using public subnets can expose ElastiCache clusters to unauthorized access, compromising data security.	12	Critical
68	ElastiCache	ElastiCache for Redis replication groups before version 6.0 should use Redis Auth	Not using Redis Auth can expose Redis data to unauthorized access, leading to data breaches.	9	High
69	ElastiCache	ElastiCache for Redis replication groups should be encrypted at rest	Without encryption at rest, sensitive data in Redis can be exposed to unauthorized access.	9	High
70	ElastiCache	ElastiCache for Redis replication groups should be encrypted in transit	Failing to encrypt data in transit can lead to interception and data breaches.	9	High
71	ElastiCache	ElastiCache for Redis replication groups should be encrypted with CMK	Not using Customer Managed Keys for encryption may lead to compliance violations.	9	High
72	ElastiCache	ElastiCache for Redis replication groups should have automatic failover enabled	Lack of automatic failover can lead to service disruptions during outages, increasing downtime.	6	Medium
73	ElastiCache	ElastiCache Redis cluster automatic backup should be enabled with retention period of 15 days or greater	Inadequate backup retention increases the risk of data loss in case of failures.	9	Medium
					
EMR					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
12	EMR	EMR public access should be blocked at account level	Ensures that EMR resources are not publicly accessible, enhancing security at the account level.	1	Safe/Well Architected
					
KMS					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
13	KMS	KMS key decryption should be restricted in IAM customer managed policy	Protects sensitive data by limiting access to KMS key decryption, ensuring compliance with security best practices.	355	Safe/Well Architected
14	KMS	KMS key decryption should be restricted in IAM inline policy	Ensures that inline policies do not allow unauthorized access to KMS key decryption, enhancing data security.	119	Safe/Well Architected
					
Redshift					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
15	Redshift	Redshift clusters should prohibit public access	Protects sensitive data by preventing public access to Redshift clusters.	1	Safe/Well Architected
74	Redshift	AWS Redshift audit logging should be enabled	Without audit logging, monitoring Redshift activity becomes challenging, increasing security risks.	1	Critical
75	Redshift	AWS Redshift enhanced VPC routing should be enabled	Lack of enhanced VPC routing can lead to exposure of data to untrusted networks.	1	High
76	Redshift	Redshift cluster audit logging and encryption should be enabled	Without both audit logging and encryption, Redshift data is vulnerable to unauthorized access.	1	Critical
77	Redshift	Redshift cluster encryption in transit should be enabled	Lack of encryption in transit exposes data to interception, increasing risk.	1	Critical
78	Redshift	Redshift clusters should be encrypted with CMK	Not using Customer Managed Keys for encryption can lead to compliance violations.	1	High
					
SNS					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
16	SNS	SNS topic policies should prohibit public access	Ensures that SNS topics are secure and not accessible to unauthorized users, maintaining data confidentiality.	2	Safe/Well Architected
79	SNS	SNS topic policies should prohibit public access	Public access policies can lead to unauthorized access to SNS topics, compromising security.	3	High
					
SQS					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
17	SQS	SQS queue policies should prohibit public access	Protects sensitive information by preventing unauthorized public access to SQS queues.	1	Safe/Well Architected
80	SQS	SQS queue policies should prohibit public access	Public access can expose SQS queues to unauthorized access, leading to data breaches.	1	High
					
SSM					
Sr No 	Service 	Control Title 	Description 	Open Issues 	Priority
18	SSM	EC2 instances should be managed by AWS Systems Manager	Ensures proper management and monitoring of EC2 instances, enhancing operational security and compliance.	39	Safe/Well Architected
81	SSM	EC2 instances should be managed by AWS Systems Manager	Unmanaged instances pose security risks due to lack of monitoring and management.	74	Critical
					
Top services severity. 

 

 
The Total Count of Titles is 2,604 for priority level 1, 3,100 for priority level 2, 183 for priority level 3, and 115 for blank entries, resulting in a Grand Total of 6,002. 

 

The Total Count of Control Titles is 2,604 for priority level 1, 3,100 for priority level 2, 183 for priority level 3, and 115 for blank entries, resulting in a Grand Total of 6,002. 
 
For complete detail of the report and recommendations, you can check the Excel sheet. [link given in sheet 3] 

 
Overall Synopsis: 

ACM (AWS Certificate Manager):  

ACM simplifies the process of managing SSL/TLS certificates for use with AWS services and your internal connected resources. It allows you to easily provision, manage, and deploy public and private SSL/TLS certificates, helping you secure your websites and applications. 

Auto Scaling:  

Auto Scaling helps you ensure that you have the right number of Amazon EC2 instances available to handle the load for your application. It automatically adjusts the number of EC2 instances in your application’s architecture in response to changing traffic patterns, ensuring optimal performance and cost-efficiency. 

EBS (Elastic Block Store):  

Amazon Elastic Block Store (EBS) provides block-level storage volumes for use with Amazon EC2 instances. EBS is designed for high availability and durability, offering features like snapshotting, encryption, and backup capabilities to protect your data and ensure continuous operations. 

EC2 Security Best Practices: 

AWS EC2 instances must have termination protection enabled to prevent accidental deletions, with detailed monitoring activated for performance insights. IAM roles should be configured to avoid credentials exposure, while EBS optimization enhances storage performance. All instances must reside in a Virtual Private Cloud (VPC) and be backed by a robust backup plan. Security measures include avoiding public IP assignments and multiple Elastic Network Interfaces (ENIs). EC2 instances should leverage Instance Metadata Service Version 2 (IMDSv2) to enhance security, and sensitive user data should be excluded from instance configurations. Regular maintenance protocols include removing stopped instances after 30 days and ensuring Amazon Machine Images (AMIs) are updated and encrypted. Instances older than 180 days should be decommissioned, and all public instances must have attached IAM profiles to enforce strict access controls. 

EKS:  

EKS clusters should be configured to encrypt Kubernetes secrets using AWS Key Management Service (KMS) to enhance security and compliance. Additionally, enabling control plane audit logging is essential for tracking access and changes within the cluster, helping maintain governance and audit trails. 

ELB:  

Classic Load Balancers should have connection draining enabled to ensure ongoing requests are completed before instances are deregistered, enhancing user experience. It’s critical to enable logging for ELB application and classic load balancers to monitor traffic and diagnose issues. Furthermore, all application and network load balancers must exclusively utilize SSL or HTTPS listeners to secure data in transit. Implementing deletion protection for application load balancers prevents accidental removal, while dropping unnecessary HTTP headers and enabling the Web Application Firewall (WAF) fortifies security against web vulnerabilities. Ensuring HTTP requests are redirected to HTTPS further enhances protection and enabling cross-zone to load balancing guarantees efficient traffic distribution. Classic load balancers must also restrict public access and utilize secure SSL ciphers, while network load balancers should have a configured TLS listener security policy for encryption. 

AWS EC2: 

AWS EC2 provides a robust infrastructure for running applications with multiple best practices to enhance security and performance, including enabling termination protection, monitoring, and ensuring instances are configured without public IPs or unnecessary credentials exposure. 

AWS EKS: 

AWS EKS allows for seamless Kubernetes management, emphasizing security by recommending the encryption of secrets using KMS and enabling control plane audit logging for comprehensive logging and monitoring. 

AWS ELB: 

AWS ELB offers reliable load balancing services while recommending essential configurations such as enabling connection draining, logging, and ensuring SSL usage for secure communication to enhance application availability and security. 

IAM (Identity and Access Management): 

AWS IAM plays a critical role in managing access to AWS resources, with best practices that include enforcing strong password policies, enabling MFA, and ensuring users and roles have appropriate permissions to prevent unauthorized access. 

AWS Lambda: 

AWS Lambda allows developers to run code in response to events while providing guidelines for ensuring security and reliability, such as enabling CloudWatch insights, configuring VPCs, and managing sensitive environment variables securely. 
 
RDS: 

Amazon RDS (Relational Database Service) automates many of the tedious tasks involved in database management. To ensure optimal security and reliability, it is essential to configure RDS clusters with backup plans, enable encryption at rest, and set up event notifications for critical events. Monitoring capabilities such as enhanced logging and IAM authentication should also be utilized to secure database access and data integrity, while features like multi-AZ deployments enhance availability. 

S3: 

Amazon S3 (Simple Storage Service) provides scalable object storage for data and applications. To safeguard data, it is crucial to implement discovery and classification processes, ensure that object logging is enabled, and block public access at the account level. Additionally, disabling static website hosting on S3 buckets can prevent unintended exposure of sensitive information. Proper management of these configurations enhances the overall security posture of data stored in S3. 
 
Secrets Manager:  

AWS Secrets Manager helps you protect access to your applications, services, and IT resources without the upfront investment and on-going maintenance costs of operating your own infrastructure. It enables you to rotate, manage, and retrieve database credentials, API keys, and other secrets throughout their lifecycle, all while maintaining stringent security controls. 

Security Hub:  

AWS Security Hub provides a comprehensive view of your security state in AWS and helps you check your compliance with security best practices. By aggregating, organizing, and prioritizing your security alerts and findings from multiple AWS services and third-party products, it enables effective incident response and risk management. 

VPC:  

Amazon Virtual Private Cloud (VPC) allows you to provision a logically isolated section of the AWS cloud where you can launch AWS resources in a virtual network that you define. You have complete control over your virtual networking environment, including resource placement, connectivity, and security, which helps enhance your cloud infrastructure's security posture. 

AWS WAFv2: 

AWS WAFv2 provides the capability to enable logging on both regional and global web access control lists (ACLs). This feature allows users to track and monitor web traffic to identify and respond to potential security threats. By enabling logging, you gain valuable insights into access patterns and can effectively manage the security posture of your applications deployed on AWS. 

 
AWS Compliance Control Summary: 

This table provides an overview of key AWS compliance controls, descriptions, open issues, and prioritization for improving the security posture of your AWS account. 

This table provides a comprehensive overview of critical compliance controls for ACM, Auto Scaling, EBS, EC2, ELB, S3, VPC AND MORE within your AWS environment. It includes essential information such as control titles, descriptions of each control, the number of open issues, and their respective priority levels. These controls are designed to enhance security and ensure operational efficiency. For further insights, including in-depth descriptions, recommended actions, and step-by-step guidance to address identified issues, please refer to the attached Excel sheet. 
