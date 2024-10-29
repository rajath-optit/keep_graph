| Sr No | Service       | Control Title                                                        | Description                                                                                       | Open Issues | Priority |
|-------|---------------|----------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-------------|----------|
| 1     | ACM           | ACM certificates should not use wildcard certificates               | Ensures certificates do not use wildcards for enhanced security.                                 | 3           | Critical |
| 2     | Auto Scaling  | EC2 instances should require IMDSv2                                 | Configures EC2 instances to use IMDSv2, mitigating security risks.                               | 8           | Critical |
| 3     | Auto Scaling  | No suspended processes in Auto Scaling groups                       | All processes are active to maintain reliability and scaling functionality.                      | 44          | Critical |
| 4     | Auto Scaling  | Health checks for load-balanced Auto Scaling groups                 | Ensures load-balanced Auto Scaling groups have health checks for operational stability.          | 30          | Critical |
| 5     | Auto Scaling  | User data in launch configurations should not contain sensitive data | Prevents sensitive data in user data scripts to avoid unintended exposure.                       | 1           | Critical |
| 6     | Auto Scaling  | Auto Scaling groups should span multiple availability zones         | Ensures redundancy across zones to improve resilience.                                           | 7           | Critical |
| 7     | Auto Scaling  | Use EC2 launch templates in Auto Scaling groups                     | Launch templates should be used for consistency and resource optimization.                       | 16          | Critical |
| 8     | Auto Scaling  | Multiple instance types and availability zones                      | Requires use of diverse instance types and zones for scalability and failover.                   | 44          | Critical |
| 9     | EBS           | Delete on termination for attached volumes                          | Configures volumes to delete on termination, preventing orphaned storage costs.                 | 54          | Medium   |
| 10    | EBS           | Encryption enabled for attached volumes                             | Ensures all EBS volumes attached to instances have encryption enabled for data protection.      | 76          | Critical |
| 11    | EBS           | Snapshot encryption                                                 | Protects snapshot data by enforcing encryption at rest.                                          | 19          | Critical |
| 12    | EBS           | Encryption at rest for EBS volumes                                  | Secures data at rest in volumes through encryption.                                              | 75          | Critical |
| 13    | EBS           | Volume snapshots availability                                       | Confirms EBS volumes are backed up through snapshots to prevent data loss.                       | 152         | Critical |
| 14    | EBS           | Volumes should be attached to EC2 instances                         | Ensures volumes are correctly attached to prevent wasted resources.                              | 28          | Critical |
| 15    | EBS           | Backup plan for EBS volumes                                         | Enforces that volumes are included in a backup plan for data retention.                          | 164         | Critical |
| 16    | EC2     | Termination protection for instances                                    | Prevents accidental termination of EC2 instances by enabling termination protection.          | 113         | Critical |
| 17    | EC2     | Detailed monitoring enabled for EC2 instances                           | Ensures that detailed monitoring is active for improved tracking of EC2 instance performance. | 113         | Medium   |
| 18    | EC2     | IAM role with restricted access for instances                           | Prevents credentials exposure through strict IAM roles.                                       | 81          | Critical |
| 19    | EC2     | EBS optimization enabled for instances                                  | Ensures that instances have EBS optimization enabled for enhanced performance.                | 87          | Medium   |
| 20    | EC2     | Instances located within a VPC                                          | Confirms all EC2 instances are running within a VPC for secure networking.                    | 2           | Critical |
| 21    | EC2     | Backup plan coverage for instances                                      | Ensures all EC2 instances are included in a backup plan.                                      | 113         | Critical |
| 22    | EC2     | IAM profile attached to instances                                       | Validates that instances have an IAM profile attached for access management.                  | 32          | Critical |
| 23    | EC2     | Instances avoid 'launch wizard' security groups                         | Avoids using default security groups that may lack security customization.                    | 2           | Critical |
| 24    | EC2     | Instances without public IPs                                            | Restricts public IP assignment to prevent direct internet access.                             | 11          | Critical |
| 25    | EC2     | No key pairs in running state for instances                             | Ensures no active key pairs in instances to avoid unauthorized access.                        | 100         | Critical |
| 26    | EC2     | Single ENI usage for instances                                          | Limits instances to a single Elastic Network Interface (ENI) for simplified network configs.  | 38          | Medium   |
| 27    | EC2     | IMDSv2 usage for instances                                              | Enforces use of Instance Metadata Service Version 2 for enhanced security.                    | 95          | Critical |
| 28    | EC2     | Secrets excluded from user data                                         | Prevents secrets exposure in EC2 instance user data.                                          | 69          | Critical |
| 29    | EC2     | Removal of stopped instances after 30 days                              | Ensures stopped instances are removed within 30 days to avoid unnecessary costs.              | 2           | Medium   |
| 30    | EC2     | Attached EBS volumes delete on termination                              | Configures attached EBS volumes to delete upon instance termination to prevent unused storage.| 14          | Medium   |
| 31    | EC2     | Images (AMIs) are recent (within 90 days)                               | Ensures that AMIs in use are updated regularly, within 90 days.                               | 26          | Medium   |
| 32    | EC2     | Encrypted AMIs                                                          | Protects AMIs through encryption to secure the data in images.                                | 10          | Critical |
| 33    | EC2     | Removal of instances stopped for over 90 days                           | Maintains instance lifecycle by removing inactive instances over 90 days.                     | 1           | Medium   |
| 34    | EC2     | Instances not older than 180 days                                       | Ensures all instances are periodically refreshed within 180 days for performance and security.| 28          | Critical |
| 35    | EC2     | Public instances have IAM profile attached                              | Confirms public instances are secure with appropriate IAM profile attached.                   | 6           | Critical |
| 36    | EKS     | Kubernetes secrets encryption using KMS                                   | Ensures Kubernetes secrets in EKS clusters are encrypted using AWS KMS for added data security.               | 2           | Critical |
| 37    | EKS     | Control plane audit logging enabled                                       | Enables logging for control plane operations in EKS, assisting in audit and security tracking.                | 2           | High     |
| 38    | ELB     | Connection draining enabled on Classic Load Balancers                     | Ensures Classic Load Balancers drain connections properly before scaling in or out.                           | 1           | Medium   |
| 39    | ELB     | Logging enabled for application and classic load balancers                | Enables logging for monitoring ELB traffic, assisting in troubleshooting and auditing.                        | 17          | High     |
| 40    | ELB     | SSL/HTTPS listeners on load balancers only                                | Configures load balancers to only use SSL or HTTPS for secure data transit.                                   | 22          | Critical |
| 41    | ELB     | Deletion protection enabled for application load balancers                | Protects application load balancers from accidental deletion.                                                 | 21          | High     |
| 42    | ELB     | Drop HTTP headers on application load balancers                           | Configures load balancers to drop HTTP headers to enhance privacy and security.                               | 21          | Medium   |
| 43    | ELB     | Web Application Firewall (WAF) enabled for application load balancers     | Adds WAF protection to filter out malicious requests, enhancing security.                                     | 21          | Critical |
| 44    | ELB     | HTTP to HTTPS redirection on application load balancers                   | Ensures HTTP requests are redirected to HTTPS to enforce secure connections.                                  | 3           | High     |
| 45    | ELB     | Cross-zone load balancing on classic load balancers                       | Balances traffic across multiple availability zones for improved resilience and performance.                  | 1           | Medium   |
| 46    | ELB     | SSL/HTTPS listeners for classic load balancers                            | Ensures Classic Load Balancers use SSL or HTTPS for secure communication.                                     | 1           | High     |
| 47    | ELB     | Secure SSL cipher usage on ELB listeners                                  | Configures ELB listeners to use secure SSL ciphers for safe data transmission.                                | 46          | Critical |
| 48    | ELB     | Load balancers prohibit public access                                     | Prevents public access to ELB load balancers, restricting access to private networks.                         | 18          | Critical |
| 49    | ELB     | TLS listener security policy on network load balancers                    | Configures TLS security policy for network load balancers to maintain secure communication.                   | 1           | High     |
| 50    | IAM     | Support role created for AWS Support incident management                                  | Ensures a dedicated support role is created for handling AWS Support incidents efficiently.                        | 1           | High     |
| 51    | IAM     | Password policy prevents password reuse                                                   | Prevents users from reusing previous passwords, strengthening password security.                                   | 1           | High     |
| 52    | IAM     | Password policy requires at least one number                                              | Enforces inclusion of numeric characters in passwords for better security.                                         | 1           | Medium   |
| 53    | IAM     | Password policy requires at least one symbol                                              | Enforces inclusion of special characters in passwords to enhance security.                                         | 1           | Medium   |
| 54    | IAM     | Policies attached only to groups or roles                                                 | Ensures policies are attached to IAM groups or roles only, not to individual users.                                | 17          | High     |
| 55    | IAM     | No full "*:*" administrative privileges in policies                                       | Prevents granting full access through IAM policies to minimize risks.                                              | 1           | Critical |
| 56    | IAM     | Policies should not grant full access to any service                                      | Limits permissions in policies to prevent unauthorized access.                                                     | 38          | Critical |
| 57    | IAM     | Administrator access policy should not be attached to any role                            | Avoids over-permissioning by preventing administrator access attachment to roles.                                  | 2           | High     |
| 58    | IAM     | Inline policies should not allow blocked actions on KMS keys                              | Prevents inline policies from allowing restricted actions on KMS keys.                                             | 1           | Critical |
| 59    | IAM     | Managed policies should not allow blocked actions on KMS keys                             | Ensures managed policies do not grant unauthorized actions on KMS keys.                                            | 5           | High     |
| 60    | IAM     | IAM Access Analyzer enabled in all regions                                                | Enables IAM Access Analyzer for comprehensive monitoring across all regions.                                       | 16          | Medium   |
| 61    | IAM     | Only one active access key per IAM user                                                   | Restricts IAM users to one active access key for security.                                                         | 4           | Medium   |
| 62    | IAM     | AWS managed policies attached to IAM roles                                                | Requires use of AWS managed policies on IAM roles for standardized permission management.                          | 1146        | High     |
| 63    | IAM     | IAM groups should have at least one user                                                  | Ensures IAM groups are populated with users for accountability.                                                    | 2           | Medium   |
| 64    | IAM     | No inline policies on groups, users, or roles                                             | Disallows inline policies for roles, groups, or users to maintain policy consistency.                              | 33          | High     |
| 65    | IAM     | Strong password configurations for IAM users                                              | Enforces strong password policies for IAM users to prevent unauthorized access.                                    | 1           | High     |
| 66    | IAM     | IAM policy usage                                                                          | Ensures policies are in use and actively managed.                                                                  | 1129        | Medium   |
| 67    | IAM     | IAM roles without assume role policies                                                    | Avoids improper access control by limiting the usage of assume role policies.                                      | 1           | Medium   |
| 68    | IAM     | Unused IAM roles removal                                                                  | Identifies and removes unused IAM roles for security and policy hygiene.                                           | 123         | Medium   |
| 69    | IAM     | Hardware MFA enabled for root user                                                        | Adds hardware MFA for root user to ensure strong authentication.                                                   | 1           | Critical |
| 70    | IAM     | MFA enabled for root user                                                                 | Requires MFA for root user to enhance security.                                                                    | 1           | High     |
| 71    | IAM     | Access key rotation every 90 days                                                         | Enforces access key rotation for IAM users to maintain security.                                                   | 42          | High     |
| 72    | IAM     | No inline or attached policies for IAM users                                              | Prevents IAM users from having inline or attached policies for minimized risk.                                     | 18          | High     |
| 73    | IAM     | Users must belong to at least one group                                                   | Ensures IAM users are part of a group for better access management.                                                | 9           | Medium   |
| 74    | IAM     | Hardware MFA for IAM users                                                                | Adds hardware MFA for IAM users to secure account access.                                                          | 33          | Critical |
| 75    | IAM     | Strong password policies for minimum length                                               | Ensures minimum password length of 8 characters for IAM users.                                                     | 1           | Medium   |
| 76    | Lambda  | Cloudwatch Lambda insights enabled                                                        | Enables Lambda insights for monitoring function performance and troubleshooting.                                   | 21          | High     |
| 77    | Lambda  | Encryption in transit for environment variables                                           | Protects environment variables with encryption to secure sensitive data.                                          | 21          | High     |
| 78    | Lambda  | CloudTrail logging enabled for Lambda functions                                           | Logs Lambda functions activities for enhanced auditing.                                                            | 21          | High     |
| 79    | Lambda  | Concurrent execution limit for Lambda functions                                           | Sets a limit on concurrent executions to avoid over-utilization.                                                   | 21          | Medium   |
| 80    | Lambda  | Lambda CORS configuration does not allow all origins                                     | Restricts CORS settings to prevent unauthorized cross-origin requests.                                             | 20          | High     |
| 81    | Lambda  | Dead-letter queue configured for Lambda functions                                        | Provides a dead-letter queue for handling failed events in Lambda functions.                                       | 21          | High     |
| 82    | Lambda  | Lambda functions in a VPC                                                                | Configures Lambda functions within a VPC to restrict access to private resources.                                 | 7           | High     |
| 83    | Lambda  | Multi-availability zone configuration for Lambda functions                               | Ensures Lambda functions operate across multiple availability zones for redundancy.                               | 1           | Medium   |
| 84    | Lambda  | Lambda functions restrict public access                                                  | Restricts public access to Lambda functions to prevent unauthorized use.                                           | 1           | High     |
| 85    | Lambda  | Lambda functions restrict public URL access                                              | Prevents Lambda functions from being publicly accessible via URL.                                                  | 21          | Critical |
| 86    | Lambda  | Lambda function tracing enabled                                                          | Enables tracing for Lambda functions for better performance monitoring.                                            | 21          | Medium   |
| 87    | Lambda  | No sensitive data in Lambda function variables                                           | Ensures Lambda variables do not contain sensitive data.                                                            | 13          | High     |
| 88    | RDS     | RDS event notifications subscription for critical cluster events              | Configures an RDS event notifications subscription to alert for critical cluster events.                   | 1           | High     |
| 89    | RDS     | RDS event notifications subscription for critical database instance events     | Ensures that an event notifications subscription is set for critical database instance events.              | 1           | High     |
| 90    | RDS     | RDS event notifications subscription for critical database parameter group events | Configures an event notifications subscription for critical database parameter group events.                | 1           | High     |
| 91    | RDS     | RDS event notifications subscription for critical database security group events | Ensures that an event notifications subscription is set for critical database security group events.        | 1           | High     |
| 92    | RDS     | Aurora MySQL DB clusters publish audit logs to CloudWatch Logs                | Ensures that Aurora MySQL DB clusters publish audit logs to CloudWatch Logs for better monitoring.         | 6           | Medium   |
| 93    | RDS     | Database logging should be enabled                                             | Ensures that database logging is enabled to maintain audit trails and access logs.                         | 13          | Medium   |
| 94    | RDS     | IAM authentication configured for RDS clusters                                  | Configures IAM authentication for enhanced security in RDS clusters.                                       | 6           | High     |
| 95    | RDS     | RDS Aurora clusters protected by backup plan                                    | Ensures RDS Aurora clusters are protected by a backup plan to prevent data loss.                           | 6           | High     |
| 96    | RDS     | RDS Aurora clusters have backtracking enabled                                   | Enables backtracking for RDS Aurora clusters to restore to a previous state quickly.                       | 6           | Medium   |
| 97    | RDS     | RDS Aurora PostgreSQL clusters not exposed to local file read vulnerability    | Ensures RDS Aurora PostgreSQL clusters are not exposed to local file read vulnerabilities.                 | 5           | High     |
| 98    | RDS     | RDS clusters have deletion protection enabled                                   | Ensures deletion protection is enabled for RDS clusters to prevent accidental deletion.                    | 3           | High     |
| 99    | RDS     | RDS database clusters use a custom administrator username                      | Configures RDS database clusters to use a custom administrator username for better security.               | 1           | High     |
| 100   | RDS     | RDS database instances use a custom administrator username                     | Configures RDS database instances to use a custom administrator username for better security.              | 1           | High     |
| 101   | RDS     | RDS databases and clusters not use default database engine port               | Ensures that RDS databases and clusters do not use the default database engine port for security reasons.  | 6           | High     |
| 102   | RDS     | RDS DB clusters configured for multiple Availability Zones                     | Configures RDS DB clusters for high availability across multiple Availability Zones.                        | 4           | High     |
| 103   | RDS     | RDS DB clusters encrypted with CMK                                             | Ensures RDS DB clusters are encrypted with Customer Managed Keys (CMK) for added security.                | 6           | High     |
| 104   | RDS     | RDS DB instance and cluster enhanced monitoring enabled                        | Ensures that enhanced monitoring is enabled for RDS DB instances and clusters for better performance insights. | 15          | Medium   |
| 105   | RDS     | RDS DB instance multi-AZ should be enabled                                     | Ensures RDS DB instances are configured for multi-AZ deployment for high availability.                     | 13          | High     |
| 106   | RDS     | RDS DB instance protected by backup plan                                       | Ensures that RDS DB instances are protected by a backup plan to prevent data loss.                        | 13          | High     |
| 107   | RDS     | RDS DB instances connections encrypted                                          | Ensures that connections to RDS DB instances are encrypted for security.                                   | 13          | High     |
| 108   | RDS     | RDS DB instances configured to copy tags to snapshots                          | Ensures that RDS DB instances are configured to copy tags to their snapshots for better management.        | 8           | Medium   |
| 109   | RDS     | RDS DB instances should be in a backup plan                                    | Ensures RDS DB instances are included in a backup plan for data safety.                                   | 13          | High     |
| 110   | RDS     | RDS DB instances integrated with CloudWatch logs                                | Ensures RDS DB instances are integrated with CloudWatch logs for monitoring and alerting.                 | 9           | Medium   |
| 111   | RDS     | RDS DB instances have deletion protection enabled                               | Ensures that deletion protection is enabled for RDS DB instances to prevent accidental deletion.           | 12          | High     |
| 112   | RDS     | RDS DB instances have IAM authentication enabled                               | Ensures IAM authentication is enabled for RDS DB instances for enhanced security.                         | 13          | High     |
| 113   | RDS     | RDS DB instances should not use public subnet                                   | Ensures RDS DB instances are not deployed in a public subnet for security reasons.                         | 13          | High     |
| 114   | RDS     | RDS snapshots should be encrypted at rest                                       | Ensures that RDS snapshots are encrypted at rest for data protection.                                      | 5           | High     |
| 115   | RDS     | RDS PostgreSQL DB instances not exposed to local file read vulnerability        | Ensures RDS PostgreSQL DB instances are not exposed to local file read vulnerabilities.                    | 11          | High     |
| 116   | S3      | All data in AWS S3 discovered, classified, and secured as required             | Ensures all S3 data is discovered, classified, and secured to meet compliance requirements.                 | 102         | High     |
| 117   | S3      | S3 buckets object logging enabled                                               | Ensures S3 buckets have object logging enabled for tracking access and changes.                           | 170         | Medium   |
| 118   | S3      | S3 buckets static website hosting disabled                                       | Ensures that static website hosting is disabled on S3 buckets to prevent unintended exposure.              | 2           | Medium   |
| 119   | S3      | S3 public access blocked at account level                                       | Ensures that public access is blocked at the account level for enhanced security.                          | 2           | High     |
| 120   | Secrets Manager   | Secrets Manager secrets should be encrypted using CMK                            | Ensures that all secrets are securely encrypted using Customer Master Keys (CMK). | 2           | High     |
| 121   | Secrets Manager   | Secrets Manager secrets should be rotated as per the rotation schedule           | Ensures that secrets are rotated regularly according to the defined schedule. | 2           | High     |
| 122   | Secrets Manager   | Secrets Manager secrets should be rotated within a specified number of days      | Ensures timely rotation of secrets to minimize exposure risk.             | 2           | High     |
| 123   | Secrets Manager   | Secrets Manager secrets should be rotated within specific number of days         | Ensures that secrets are rotated within the specified timeframe.          | 1           | High     |
| 124   | Secrets Manager   | Secrets Manager secrets should have automatic rotation enabled                   | Ensures that secrets are automatically rotated without manual intervention. | 2           | High     |
| 125   | Secrets Manager   | Secrets Manager secrets that have not been used in 90 days should be removed     | Identifies and removes secrets that are no longer in use, enhancing security. | 1           | High     |
| 126   | Security Hub      | AWS Security Hub should be enabled for an AWS Account                           | Ensures that Security Hub is active for centralized security management.   | 2           | High     |
| 127   | VPC               | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | Prevents unauthorized access to critical server administration ports.      | 2           | High     |
| 128   | VPC               | Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389   | Ensures that remote access ports are secured from unrestricted access.     | 2           | High     |
| 129   | VPC               | Security groups should not allow unrestricted access to ports with high risk     | Reduces the risk of exploitation by restricting access to sensitive ports.  | 2           | High     |
| 130   | VPC               | Unused EC2 security groups should be removed                                      | Helps to minimize security risk by cleaning up unused security groups.      | 65          | Medium   |
| 131   | VPC               | VPC default security group should not allow inbound and outbound traffic         | Ensures the default security group is properly configured for security.     | 2           | High     |
| 132   | VPC               | VPC endpoint services should have acceptance required enabled                     | Ensures that only authorized services can connect to the endpoint.         | 200         | High     |
| 133   | VPC               | VPC flow logs should be enabled                                                  | Ensures that traffic logs are collected for auditing and monitoring.       | 7           | High     |
| 134   | VPC               | VPC route table should restrict public access to IGW                             | Prevents unauthorized access to the internet through the Internet Gateway.  | 2           | High     |
| 135   | VPC               | VPC security groups should be associated with at least one ENI                   | Ensures proper network interface assignment to security groups.            | 65          | Medium   |
| 136   | VPC               | VPC Security groups should only allow unrestricted incoming traffic for authorized ports | Limits exposure by allowing only specified ports to receive traffic.      | 2           | High     |
| 137   | VPC               | VPC security groups should restrict ingress access on ports 20, 21, 22, 3306, 3389, 4333 from 0.0.0.0/0 | Protects against unauthorized access to commonly exploited ports.          | 2           | High     |
| 138   | VPC               | VPC security groups should restrict ingress SSH access from 0.0.0.0/0           | Secures SSH access by limiting source addresses.                           | 2           | High     |
| 139   | VPC               | VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0    | Ensures all ingress TCP and UDP traffic is properly controlled.           | 54          | High     |
| 140   | VPC               | VPC security groups should restrict uses of 'launch-wizard' security groups      | Avoids reliance on default security groups that may not be appropriately configured. | 2           | High     |
| 141   | VPC               | VPC should be configured to use VPC endpoints                                    | Enhances security by ensuring all services utilize VPC endpoints.         | 9           | High     |
| 142   | VPC               | VPC subnet auto assign public IP should be disabled                              | Prevents instances from being assigned a public IP by default.            | 33          | Medium   |
| 143   | VPC               | VPCs peering connection route tables should have least privilege                | Ensures that route tables are configured with the least privilege necessary for connectivity. | 16          | Medium   |
| 144   | VPC               | VPCs should exist in multiple regions                                            | Enhances resilience by distributing VPCs across multiple regions.         | 1           | High     |
| 145   | VPC               | VPCs should have both public and private subnets configured                     | Ensures proper segmentation and security of resources within VPCs.        | 9           | High     |
| 146   | VPC              | Count of title                                                                    | Total number of compliance titles associated with VPC.                   |             |          |
| 147   | VPC              | Count of control_title                                                             | Total number of control titles associated with VPC.                       |             |          |
| 148   | WAFv2           | Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs) | Ensures that logging is activated for monitoring and auditing purposes.   | 4           | High     |
| 149   | WAFv2           | Count of title                                                                    | Total number of compliance titles associated with WAFv2.                  |             |          |
| 150   | WAFv2           | Count of control_title                                                             | Total number of control titles associated with WAFv2.                     |             |          |
---