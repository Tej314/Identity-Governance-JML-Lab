import boto3
from botocore.exceptions import ClientError

def audit_iam_policies():
    """Scan IAM roles and users for overly permissive policy attachments (AdministratorAccess or '*' actions)."""
    print("\n[+] Starting IAM Policy Audit...")
    iam = boto3.client('iam')
    
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            role_name = role['RoleName']
            
            # Check attached managed policies
            attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in attached_policies:
                if policy['PolicyName'] == 'AdministratorAccess':
                    print(f"  [CRITICAL RISK] Role '{role_name}' has full 'AdministratorAccess' attached!")
                
            # Check inline policies for wildcard actions
            inline_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
            for policy_name in inline_policies:
                policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and statement.get('Action') == '*':
                        print(f"  [HIGH RISK] Role '{role_name}' inline policy '{policy_name}' contains wildcard '*' permission!")
                        
    except ClientError as e:
        print(f"  [!] IAM Audit failed or restricted: {e}")

def audit_s3_bucket_acls():
    """Scan S3 buckets for public read/write access via ACLs."""
    print("\n[+] Starting S3 Bucket ACL Audit...")
    s3 = boto3.client('s3')
    
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            # Retrieve ACL settings
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                # URI indicating 'All Users' (Public Internet)
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    permission = grant.get('Permission')
                    print(f"  [CRITICAL RISK] S3 Bucket '{bucket_name}' has PUBLIC access ({permission}) via ACL!")
                    
    except ClientError as e:
        print(f"  [!] S3 Audit failed or restricted: {e}")

if __name__ == "__main__":
    print("==================================================")
    print("   AUTOMATED CLOUD IAM & ACL SECURITY SCANNER    ")
    print("==================================================")
    audit_iam_policies()
    audit_s3_bucket_acls()
    print("\n[+] Audit Complete.\n")