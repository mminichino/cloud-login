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
import shutil
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from enum import Enum
from cloudlogin.exceptions import Unauthorized

logger = logging.getLogger("awsssomgr")
logger.addHandler(logging.NullHandler())
logging.getLogger("botocore").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)


class AWSLoginError(Exception):
    pass


class AuthMode(Enum):
    default = 0
    sso = 1


class AWSLogin(object):
    def __init__(
        self,
        mode: AuthMode = AuthMode.sso,
        profile: Optional[str] = None,
        region: Optional[str] = None,
    ):
        self.config_directory = os.path.join(Path.home(), ".aws")
        self.config_file = os.path.join(self.config_directory, "config")
        self.credential_file = os.path.join(self.config_directory, "credentials")
        self.config_data = configparser.ConfigParser()
        self.credential_data = configparser.ConfigParser()
        self.profile = profile if profile else "default"
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
            connect_timeout=1, read_timeout=1, retries={"max_attempts": 2}
        )

        self.read_config()
        self.sts_client = boto3.client("sts")

        if region:
            self.aws_region = region
            os.environ["AWS_REGION"] = region
        elif os.environ.get("AWS_REGION"):
            self.aws_region = os.environ["AWS_REGION"]
        else:
            self.aws_region = "us-east-1"

        if os.environ.get("AWS_PROFILE"):
            self.profile = os.environ["AWS_PROFILE"]

        self.default_auth()

        if mode == AuthMode.sso:
            self.sso_auth()

        if not self.is_session_valid():
            raise Unauthorized("can not login to AWS")

        try:
            logger.debug(f"Initializing AWS environment in region {self.aws_region}")
            self.ec2_client = boto3.client("ec2", region_name=self.aws_region)
            self.s3_client = boto3.client("s3", region_name=self.aws_region)
            self.dns_client = boto3.client("route53", region_name=self.aws_region)
        except Exception as err:
            raise AWSLoginError(f"can not initialize AWS environment: {err}")

    @property
    def account_id(self):
        return self.sts_client.get_caller_identity()["Account"]

    def read_config(self):
        if os.path.exists(self.config_file):
            try:
                self.config_data.read(self.config_file)
            except Exception as err:
                raise AWSLoginError(
                    f"can not read config file {self.config_file}: {err}"
                )

        if os.path.exists(self.credential_file):
            try:
                self.credential_data.read(self.credential_file)
            except Exception as err:
                raise AWSLoginError(
                    f"can not read config file {self.credential_file}: {err}"
                )

    def read_sso_config(self):
        for section, contents in self.config_data.items():
            if section.startswith("profile"):
                profile_name = section.split()[1]
                if self.profile != "default":
                    if profile_name != self.profile:
                        continue
                else:
                    self.profile = profile_name
                logger.debug(f"SSO: using profile {self.profile}")
                self.sso_session = contents.get("sso_session")
                self.sso_account_id = contents.get("sso_account_id")
                self.sso_role_name = contents.get("sso_role_name")
                if not self.sso_session:
                    self.sso_start_url = contents.get("sso_start_url")
                    self.sso_region = contents.get("sso_region")
                    self.sso_registration_scopes = "sso:account:access"
                break

        for section, contents in self.config_data.items():
            if section.startswith("sso-session"):
                session_name = section.split()[1]
                if session_name == self.sso_session:
                    self.sso_start_url = contents.get("sso_start_url")
                    self.sso_region = contents.get("sso_region")
                    self.sso_registration_scopes = contents.get(
                        "sso_registration_scopes"
                    )

    @staticmethod
    def get_auth_config() -> dict:
        session = botocore.session.get_session()
        return {
            "aws_access_key_id": session.get_credentials().access_key,
            "aws_secret_access_key": session.get_credentials().secret_key,
            "aws_session_token": session.get_credentials().token,
        }

    def is_session_valid(self) -> bool:
        try:
            self.sts_client.get_caller_identity()
            return True
        except Exception as err:
            logger.debug(f"is_session_valid: {err}")
            return False

    def default_auth(self):
        if "AWS_ACCESS_KEY_ID" in os.environ and "AWS_SECRET_ACCESS_KEY" in os.environ:
            self.access_key = os.environ["AWS_ACCESS_KEY_ID"]
            self.secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
            if "AWS_SESSION_TOKEN" in os.environ:
                self.token = os.environ["AWS_SESSION_TOKEN"]
        else:
            session = botocore.session.Session()
            profiles_config = session.full_config.get("profiles", {})
            default_config: dict = profiles_config.get(self.profile, {})

            self.access_key = default_config.get("aws_access_key_id")
            self.secret_key = default_config.get("aws_secret_access_key")
            self.token = default_config.get("aws_session_token")

    def save_auth(self):
        profile_config: dict = {
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_key,
            "aws_session_token": self.token,
        }
        self.credential_data[self.profile] = profile_config
        with open(self.credential_file, "w") as config_file:
            self.credential_data.write(config_file)

    def clear_cached_credentials(self):
        cli_cache_dir = os.path.join(self.config_directory, "cli", "cache")
        sso_cache_dir = os.path.join(self.config_directory, "sso", "cache")

        for cache_dir in [cli_cache_dir, sso_cache_dir]:
            if os.path.exists(cache_dir):
                logger.debug(f"Cleaning cache directory: {cache_dir}")
                try:
                    shutil.rmtree(cache_dir)
                    logger.debug("Cleaned cache directory")
                except Exception as err:
                    logger.warning(
                        f"Failed to clean cache directory {cache_dir}: {err}"
                    )

    def save_sso_token(
        self, token_data, client_creds, session_name, start_url, sso_region
    ):
        try:
            sso_cache_dir = os.path.join(self.config_directory, "sso", "cache")
            os.makedirs(sso_cache_dir, exist_ok=True)

            token_cache_key = hashlib.sha1(session_name.encode("utf-8")).hexdigest()
            token_cache_file = os.path.join(sso_cache_dir, f"{token_cache_key}.json")

            expires_in = token_data.get("expiresIn", 3600)
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            expires_at = expires_at.replace(microsecond=0)

            registration_expires_at = datetime.now(timezone.utc) + timedelta(days=90)
            registration_expires_at = registration_expires_at.replace(microsecond=0)

            token_cache_data = {
                "startUrl": start_url,
                "region": sso_region,
                "accessToken": token_data["accessToken"],
                "expiresAt": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "clientId": client_creds["clientId"],
                "clientSecret": client_creds["clientSecret"],
                "registrationExpiresAt": registration_expires_at.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }

            if "refreshToken" in token_data:
                token_cache_data["refreshToken"] = token_data["refreshToken"]

            with open(token_cache_file, "w") as f:
                json.dump(token_cache_data, f)

            logger.debug(f"Saved SSO token to cache: {token_cache_file}")
        except Exception as err:
            logger.warning(f"Failed to save SSO token to cache: {err}")

    def sso_auth(self):
        token = {}

        self.read_sso_config()

        if self.is_session_valid():
            logger.debug("sso_auth: using existing session")
            return

        if not self.sso_account_id or not self.sso_start_url or not self.sso_region:
            AWSLoginError('Please run "aws configure sso" to setup SSO')

        self.clear_cached_credentials()

        session = boto3.Session()
        account_id = self.sso_account_id
        start_url = self.sso_start_url
        region = self.sso_region
        sso_oidc = session.client("sso-oidc", region_name=region)
        client_creds = sso_oidc.register_client(
            clientName="couch-formation",
            clientType="public",
        )
        device_authorization = sso_oidc.start_device_authorization(
            clientId=client_creds["clientId"],
            clientSecret=client_creds["clientSecret"],
            startUrl=start_url,
        )
        url = device_authorization["verificationUriComplete"]
        device_code = device_authorization["deviceCode"]
        expires_in = device_authorization["expiresIn"]
        interval = device_authorization["interval"]

        logger.info(
            f"If a browser window does not open, follow this URL to continue: {url}"
        )
        webbrowser.open_new_tab(url)

        for n in range(1, expires_in // interval + 1):
            time.sleep(interval)
            try:
                token = sso_oidc.create_token(
                    grantType="urn:ietf:params:oauth:grant-type:device_code",
                    deviceCode=device_code,
                    clientId=client_creds["clientId"],
                    clientSecret=client_creds["clientSecret"],
                )
                break
            except sso_oidc.exceptions.AuthorizationPendingException:
                pass

        if token:
            self.save_sso_token(
                token, client_creds, self.sso_session, start_url, region
            )

        access_token = token["accessToken"]
        sso = session.client("sso", region_name=region)
        account_roles = sso.list_account_roles(
            accessToken=access_token,
            accountId=account_id,
        )
        roles = account_roles["roleList"]
        role = next((r for r in roles if r.get("roleName") == self.sso_role_name), None)
        if not role:
            raise AWSLoginError(
                f"Role {self.sso_role_name} is not available for account {self.sso_account_id}"
            )
        role_creds = sso.get_role_credentials(
            roleName=role["roleName"],
            accountId=account_id,
            accessToken=access_token,
        )

        session_creds = role_creds["roleCredentials"]

        self.access_key = session_creds["accessKeyId"]
        self.secret_key = session_creds["secretAccessKey"]
        self.token = session_creds["sessionToken"]
        self.token_expiration = session_creds["expiration"]
        self.save_auth()

    @property
    def expiration(self) -> Optional[datetime]:
        if not self.token_expiration:
            return None
        dt = datetime.fromtimestamp(self.token_expiration / 1000)
        return dt

    @property
    def region(self):
        return self.aws_region

    @staticmethod
    def tag_exists(key, tags):
        for i in range(len(tags)):
            if tags[i]["Key"] == key:
                return True
        return False

    @staticmethod
    def get_tag(key, tags):
        for i in range(len(tags)):
            if tags[i]["Key"] == key:
                return tags[i]["Value"]
        return None

    def get_all_regions(self) -> list:
        regions = self.ec2_client.describe_regions(AllRegions=False)
        region_list = list(r["RegionName"] for r in regions["Regions"])
        return region_list

    def availability_zones(self) -> list:
        try:
            zone_list = self.ec2_client.describe_availability_zones()
        except Exception as err:
            raise AWSLoginError(f"error getting availability zones: {err}")

        for availability_zone in zone_list["AvailabilityZones"]:
            self.zone_list.append(availability_zone["ZoneName"])

        self.zone_list = sorted(set(self.zone_list))

        if len(self.zone_list) == 0:
            raise AWSLoginError("can not get AWS availability zones")

        return self.zone_list
