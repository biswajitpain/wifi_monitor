import subprocess
import platform
from .utils import get_public_ip
import boto3
from botocore.exceptions import ClientError

class WiFiMonitor:
    def __init__(self, aws_region, security_group_id, target_wifi_names):
        self.aws_region = aws_region
        self.security_group_id = security_group_id
        self.target_wifi_names = target_wifi_names
        self.system = platform.system()

    def get_wifi_name(self):
        try:
            if self.system == "Darwin":  # macOS
                result = subprocess.check_output(['networksetup', '-getairportnetwork', 'en0']).decode('utf-8')
                return result.split(': ')[1].strip()
            elif self.system == "Linux":
                result = subprocess.check_output(['iwgetid', '-r']).decode('utf-8')
                return result.strip()
            elif self.system == "Windows":
                result = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces']).decode('utf-8')
                for line in result.split('\n'):
                    if "SSID" in line and "BSSID" not in line:
                        return line.split(':')[1].strip()
            else:
                print(f"Unsupported operating system: {self.system}")
        except subprocess.CalledProcessError:
            print(f"Error: Unable to get Wi-Fi information on {self.system}")
        return None

    def update_aws_security_group(self, ip_address):
        try:
            ec2 = boto3.client('ec2', region_name=self.aws_region)
            
            response = ec2.describe_security_groups(GroupIds=[self.security_group_id])
            existing_rules = response['SecurityGroups'][0]['IpPermissions']
            
            if existing_rules:
                ec2.revoke_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=existing_rules
                )
            
            ec2.authorize_security_group_ingress(
                GroupId=self.security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': f'{ip_address}/32'}]
                    }
                ]
            )
            
            print(f"Successfully updated security group with IP: {ip_address}")
        except ClientError as e:
            print(f"Error updating security group: {e}")

    def run(self):
        wifi_name = self.get_wifi_name()
        if wifi_name in self.target_wifi_names:
            public_ip = get_public_ip()
            if public_ip:
                print(f"Connected to {wifi_name}")
                print(f"Public IP: {public_ip}")
                self.update_aws_security_group(public_ip)
            else:
                print("Unable to determine public IP")
        else:
            print(f"Not connected to any target Wi-Fi. Current Wi-Fi: {wifi_name}")