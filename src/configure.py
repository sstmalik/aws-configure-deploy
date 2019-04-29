
import boto3
import botocore.session
import sys,os
import argparse
import json

m_debug=False

class IamHelper(object):

    def __init__(self):
        self.iamclient = None
        self.group = None
        self.devrole = None
        self.devuser = None
        self.policy = json.dumps({
                 "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Principal": {
                        "Service": ["lambda.amazonaws.com",
                                    "dynamodb.amazonaws.com",
                                    "sns.amazonaws.com",
                                    "ec2.amazonaws.com",
                                    "sqs.amazonaws.com",
                                    "logs.ap-south-1.amazonaws.com",
                                    "s3.amazonaws.com"
                                    ]
                      },
                      "Action": "sts:AssumeRole"
                    }
                  ]
                })

    def createClient( self, access_key, secret_key):
        self.iamclient = boto3.client("iam",
            aws_secret_access_key=secret_key,
            aws_access_key_id= access_key)
        print("Created IAM Client")
        if m_debug == True:
            print(self.iamclient)
        return True

    def createGroup( self, name):
        ##TODO: Setup right policy using non trust-policy json
        self.group = self.iamclient.create_group( GroupName=name)
        print("Created IAM Group")
        if m_debug == True:
            print(self.group)

        groupname = self.group['Group']['GroupName']
        response = self.iamclient.attach_group_policy( GroupName=groupname,
                                                       PolicyArn=self.policyarn)
        print("Attached IAM Group")
        if m_debug == True:
            print(response)
        return True
    
    def createRole( self, name):
        ##The Service-linked trust policy used above does not work for Group
        ## and user.
        self.devrole = self.iamclient.create_role( RoleName=name,
                                    Description='Default role for wfusers1',
                                    AssumeRolePolicyDocument=self.policy)
        print("Created IAM Role")
        if m_debug == True:
            print(self.devrole)
        return True
        
    def createUser(self, name):
        ##TODO: Setup right policy using non trust-policy json
        self.devuser = self.iamclient.create_user( UserName=name)
        print("Created IAM User")
        if m_debug == True:
            print(self.devuser)

        username = self.devuser['User']['UserName']
        groupname = self.group['Group']['GroupName']
        response = self.iamclient.attach_user_policy(UserName=username,
                                                    PolicyArn=self.policyarn)
        print("Attached IAM User Policy")
        if m_debug == True:
            print(response)

        response = self.iamclient.add_user_to_group(GroupName=groupname,
                                                    UserName=username)
        print("Attach IAM user to group")
        if m_debug == True:
            print(response)
        return True

    def printStats(self):
        print(self.devrole['Role']['Arn'])
        print("Use this for all aws cli based deployments\n",
                "For instance:\n",
                "aws lambda create-function --function-name demo --role <ROLE ARN>\n",
                "   --runtime provided --timeout 15 --memory-size 128\n",
                "   --handler demo --zip-file fileb://demo.zip\n", sep='')
        
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
##        We dont need to destroy anything. This script works.
##        Please use this for proper cleanup while testing.
        if m_debug == False:
            return
        
        if self.devuser is not None:
            self.iamclient.delete_user(UserName=self.devuser['User']['Username'])
            print("Deleted User")

        if self.devrole is not None:
            self.iamclient.delete_role(RoleName=self.devrole['Role']['RoleName'])
            print("Deleted Role")
            
        if self.group is not None:
            self.iamclient.delete_group(GroupName=self.group['Group']['GroupName'])
            print("Deleted Group")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", required=True, dest='access_key')
    parser.add_argument("-s", "--secret-key", required=True, dest='secret_key')
    parser.add_argument("-d", "--debug", dest='debug', choices=['true', 'false'], default='false',
                        help="No roles or groups will be created in debug mode")

    args = parser.parse_args()
    m_debug = (args.debug == 'true')
    
    with IamHelper() as iam:
        if iam.createClient(args.access_key, args.secret_key) is False:
            print("Create IAM Client failed", str(args))
            exit(1)

##        if iam.createGroup("wfusers") is False:
##            print("Create IAM User Group failed")
##            exit(1)

        if iam.createRole("wf-role") is False:
            print("Create IAM Role failed")
            exit(1)

##        We dont need a user to run any tasks on AWS.
##        https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
##        if iam.createUser("wfpricer") is False:
##            print("Create IAM User failed")
##            exit(1)

        iam.printStats()
        
    
if __name__ == "__main__":
    main()
