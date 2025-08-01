import logging
from typing import Optional
import boto3
import botocore.exceptions
import botocore.session
from botocore.config import Config
import os
import webbrowser
import time
import configparser
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger('awsssomgr')
logger.addHandler(logging.NullHandler())
logging.getLogger("botocore").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)


class AWSLoginError(Exception):
    pass


class EmptyResultSet(Exception):
    pass


class AuthMode(Enum):
    default = 0
    sso = 1


class AWSLogin(object):

    def __init__(self, profile: str = "default", mode: AuthMode = AuthMode.sso, region: Optional[str] = None):
        self.config_directory = os.path.join(Path.home(), '.aws')
        self.config_file = os.path.join(self.config_directory, 'config')
        self.credential_file = os.path.join(self.config_directory, 'credentials')
        self.config_data = configparser.ConfigParser()
        self.credential_data = configparser.ConfigParser()
        self.profile = profile
        self.sso_session = None
        self.sso_account_id = None
        self.sso_role_name = None
        self.sso_start_url = None
        self.sso_region = None
        self.sso_registration_scopes = None
        self.aws_region = None
        self.zone_list = []
        self.access_key = None
        self.secret_key = None
        self.token = None
        self.token_expiration = None
        self.timeouts = Config(
            connect_timeout=1,
            read_timeout=1,
            retries={'max_attempts': 2}
        )

        self.read_config()

        if mode == AuthMode.default:
            self.default_auth()
        else:
            self.sso_auth()

        if region:
            self.aws_region = region
            os.environ['AWS_REGION'] = region
        elif os.environ.get('AWS_REGION'):
            self.aws_region = os.environ['AWS_REGION']
        else:
            self.aws_region = 'us-east-1'

        if self.access_key:
            os.environ['AWS_ACCESS_KEY_ID'] = self.access_key
        if self.secret_key:
            os.environ['AWS_SECRET_ACCESS_KEY'] = self.secret_key
        if self.token:
            os.environ['AWS_SESSION_TOKEN'] = self.token

        try:
            self.ec2_client = boto3.client('ec2', region_name=self.aws_region)
            self.dns_client = boto3.client('route53')
            self.sts_client = boto3.client('sts')
        except Exception as err:
            raise AWSLoginError(f"can not initialize AWS environment: {err}")

    @property
    def account_id(self):
        return self.sts_client.get_caller_identity()["Account"]

    def test_session(self):
        try:
            client = boto3.client('s3', region_name=self.aws_region)
            client.list_buckets()
        except Exception as err:
            raise AWSLoginError(f"not authorized: {err}")

    def read_config(self):
        if os.path.exists(self.config_file):
            try:
                self.config_data.read(self.config_file)
            except Exception as err:
                raise AWSLoginError(f"can not read config file {self.config_file}: {err}")

        if os.path.exists(self.credential_file):
            try:
                self.credential_data.read(self.credential_file)
            except Exception as err:
                raise AWSLoginError(f"can not read config file {self.credential_file}: {err}")

    def read_sso_config(self):
        for section, contents in self.config_data.items():
            if section.startswith('profile'):
                profile_name = section.split()[1]
                if self.profile != 'default':
                    if profile_name != self.profile:
                        continue
                else:
                    self.profile = profile_name
                logger.debug(f"SSO: using profile {self.profile}")
                self.sso_session = contents.get('sso_session')
                self.sso_account_id = contents.get('sso_account_id')
                self.sso_role_name = contents.get('sso_role_name')
                self.aws_region = contents.get('region')
                if not self.sso_session:
                    self.sso_start_url = contents.get('sso_start_url')
                    self.sso_region = contents.get('sso_region')
                    self.sso_registration_scopes = 'sso:account:access'
                break

        for section, contents in self.config_data.items():
            if section.startswith('sso-session'):
                session_name = section.split()[1]
                if session_name == self.sso_session:
                    self.sso_start_url = contents.get('sso_start_url')
                    self.sso_region = contents.get('sso_region')
                    self.sso_registration_scopes = contents.get('sso_registration_scopes')

    def get_auth_config(self) -> dict:
        self.test_session()
        session = botocore.session.get_session()
        return {
            'AWS_ACCESS_KEY_ID': session.get_credentials().access_key,
            'AWS_SECRET_ACCESS_KEY': session.get_credentials().secret_key,
            'AWS_SESSION_TOKEN': session.get_credentials().token,
        }

    @staticmethod
    def auth_expired(timestamp):
        if timestamp:
            _timestamp = timestamp / 1000
            expires = datetime.fromtimestamp(_timestamp).astimezone(timezone.utc)
            if datetime.now(timezone.utc) < expires:
                return False
        return True

    def default_auth(self):
        if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
            self.access_key = os.environ['AWS_ACCESS_KEY_ID']
            self.secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
            if 'AWS_SESSION_TOKEN' in os.environ:
                self.token = os.environ['AWS_SESSION_TOKEN']
        else:
            session = boto3.Session(profile_name=self.profile)
            credentials = session.get_credentials()
            self.access_key = credentials.access_key
            self.secret_key = credentials.secret_key

    def save_auth(self):
        dt = datetime.fromtimestamp(self.token_expiration / 1000)
        token_expiration = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')
        self.credential_data[self.profile] = {
            'aws_access_key_id': self.access_key,
            'aws_secret_access_key': self.secret_key,
            'aws_session_token': self.token,
            'x_security_token_expires': token_expiration
        }
        with open(self.credential_file, 'w') as config_file:
            self.credential_data.write(config_file)

    def sso_auth(self):
        token = {}

        self.read_sso_config()

        session = botocore.session.Session()
        profiles_config = session.full_config.get('profiles', {})
        default_config = profiles_config.get(self.profile, {})

        self.access_key = default_config.get("aws_access_key_id")
        self.secret_key = default_config.get("aws_secret_access_key")
        self.token = default_config.get("aws_session_token")
        token_expiration_str = default_config.get("x_security_token_expires")
        if token_expiration_str:
            dt = datetime.strptime(token_expiration_str, '%Y-%m-%dT%H:%M:%S.%f')
            self.token_expiration = dt.timestamp() * 1000

        if not self.auth_expired(self.token_expiration):
            return

        if not self.sso_account_id or not self.sso_start_url or not self.sso_region:
            AWSLoginError("Please run \"aws configure sso\" to setup SSO")

        session = boto3.Session()
        account_id = self.sso_account_id
        start_url = self.sso_start_url
        region = self.sso_region
        sso_oidc = session.client('sso-oidc', region_name=region)
        client_creds = sso_oidc.register_client(
            clientName='couch-formation',
            clientType='public',
        )
        device_authorization = sso_oidc.start_device_authorization(
            clientId=client_creds['clientId'],
            clientSecret=client_creds['clientSecret'],
            startUrl=start_url,
        )
        url = device_authorization['verificationUriComplete']
        device_code = device_authorization['deviceCode']
        expires_in = device_authorization['expiresIn']
        interval = device_authorization['interval']

        logger.info(f"If a browser window does not open, follow this URL to continue: {url}")
        webbrowser.open_new_tab(url)

        for n in range(1, expires_in // interval + 1):
            time.sleep(interval)
            try:
                token = sso_oidc.create_token(
                    grantType='urn:ietf:params:oauth:grant-type:device_code',
                    deviceCode=device_code,
                    clientId=client_creds['clientId'],
                    clientSecret=client_creds['clientSecret'],
                )
                break
            except sso_oidc.exceptions.AuthorizationPendingException:
                pass

        access_token = token['accessToken']
        sso = session.client('sso', region_name=region)
        account_roles = sso.list_account_roles(
            accessToken=access_token,
            accountId=account_id,
        )
        roles = account_roles['roleList']
        role = next((r for r in roles if r.get('roleName') == self.sso_role_name), None)
        if not role:
            AWSLoginError(f"Role {self.sso_role_name} is not available for account {self.sso_account_id}")
        role_creds = sso.get_role_credentials(
            roleName=role['roleName'],
            accountId=account_id,
            accessToken=access_token,
        )

        session_creds = role_creds['roleCredentials']

        self.access_key = session_creds['accessKeyId']
        self.secret_key = session_creds['secretAccessKey']
        self.token = session_creds['sessionToken']
        self.token_expiration = session_creds['expiration']
        self.save_auth()

    @property
    def region(self):
        return self.aws_region

    @staticmethod
    def tag_exists(key, tags):
        for i in range(len(tags)):
            if tags[i]['Key'] == key:
                return True
        return False

    @staticmethod
    def get_tag(key, tags):
        for i in range(len(tags)):
            if tags[i]['Key'] == key:
                return tags[i]['Value']
        return None

    def get_all_regions(self) -> list:
        regions = self.ec2_client.describe_regions(AllRegions=False)
        region_list = list(r['RegionName'] for r in regions['Regions'])
        return region_list

    def availability_zones(self) -> list:
        try:
            zone_list = self.ec2_client.describe_availability_zones()
        except Exception as err:
            raise AWSLoginError(f"error getting availability zones: {err}")

        for availability_zone in zone_list['AvailabilityZones']:
            self.zone_list.append(availability_zone['ZoneName'])

        self.zone_list = sorted(set(self.zone_list))

        if len(self.zone_list) == 0:
            raise AWSLoginError("can not get AWS availability zones")

        return self.zone_list
