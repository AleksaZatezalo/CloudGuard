"""
AWS provider for authentication and service client management
"""

import logging
from typing import Dict, List, Optional
import boto3
from botocore.exceptions import ClientError


class AWSProvider:
    """AWS provider for authentication and service client management"""
    
    def __init__(self, access_key: str = None, secret_key: str = None, 
                 session_token: str = None, region: str = 'us-east-1',
                 profile: str = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.region = region
        self.profile = profile
        self.session = None
        self.account_id = None
        self._clients = {}
        
        self._initialize_session()
        self._get_account_id()
    
    def _initialize_session(self):
        """Initialize boto3 session with provided credentials"""
        try:
            if self.profile:
                self.session = boto3.Session(profile_name=self.profile)
            elif self.access_key and self.secret_key:
                self.session = boto3.Session(
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    aws_session_token=self.session_token,
                    region_name=self.region
                )
            else:
                # Use environment variables or instance metadata
                self.session = boto3.Session(region_name=self.region)
                
        except Exception as e:
            raise Exception(f"Failed to initialize AWS session: {str(e)}")
    
    def _get_account_id(self):
        """Get AWS account ID"""
        try:
            sts_client = self.get_client('sts')
            self.account_id = sts_client.get_caller_identity()['Account']
        except Exception as e:
            logging.warning(f"Could not retrieve account ID: {str(e)}")
            self.account_id = "unknown"
    
    def get_client(self, service_name: str, region: str = None):
        """Get boto3 client for AWS service"""
        if region is None:
            region = self.region
            
        client_key = f"{service_name}_{region}"
        if client_key not in self._clients:
            try:
                self._clients[client_key] = self.session.client(
                    service_name, region_name=region
                )
            except Exception as e:
                raise Exception(f"Failed to create {service_name} client: {str(e)}")
        
        return self._clients[client_key]
    
    def get_regions(self, service_name: str = 'ec2') -> List[str]:
        """Get list of available regions for a service"""
        try:
            client = self.get_client(service_name)
            regions = client.describe_regions()['Regions']
            return [region['RegionName'] for region in regions]
        except:
            # Fallback to common regions
            return [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-southeast-1',
                'ap-southeast-2', 'ap-northeast-1'
            ]
