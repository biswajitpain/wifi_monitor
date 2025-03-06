from botocore.exceptions import ClientError
from moto import mock_ec2
from unittest.mock import patch
from unittest.mock import patch, MagicMock
from unittest.mock import patch, Mock
from wifi_monitor.monitor import WiFiMonitor
import boto3
import platform
import pytest
import subprocess
import unittest

class TestMonitor:

    def test___init___1(self):
        """
        Test the initialization of WiFiMonitor with valid parameters.
        Verify that the instance attributes are correctly set.
        """
        aws_region = "us-west-2"
        security_group_id = "sg-12345678"
        target_wifi_names = ["WiFi1", "WiFi2"]

        monitor = WiFiMonitor(aws_region, security_group_id, target_wifi_names)

        assert monitor.aws_region == aws_region
        assert monitor.security_group_id == security_group_id
        assert monitor.target_wifi_names == target_wifi_names
        assert monitor.system == platform.system()

    def test___init___with_empty_target_wifi_names(self):
        """
        Test initializing WiFiMonitor with an empty list for target_wifi_names.
        This tests the edge case of providing an empty list, which is handled
        implicitly by the method accepting any iterable for target_wifi_names.
        """
        monitor = WiFiMonitor("us-west-2", "sg-12345678", [])
        assert monitor.target_wifi_names == []
        assert monitor.aws_region == "us-west-2"
        assert monitor.security_group_id == "sg-12345678"
        assert monitor.system == platform.system()

    def test_get_wifi_name_1(self):
        """
        Test get_wifi_name method when the system is macOS (Darwin).

        This test verifies that the method correctly extracts and returns
        the Wi-Fi name from the subprocess output on a macOS system.
        """
        with patch('platform.system', return_value='Darwin'), \
             patch('subprocess.check_output', return_value=b'Current Wi-Fi Network: TestWiFi\n'):
            monitor = WiFiMonitor('us-west-2', 'sg-1234567890abcdef0', ['TestWiFi'])
            result = monitor.get_wifi_name()
            self.assertEqual(result, 'TestWiFi')

    def test_get_wifi_name_2(self):
        """
        Test get_wifi_name method for Linux systems.

        This test case verifies that the get_wifi_name method correctly
        returns the Wi-Fi network name on a Linux system by mocking the
        subprocess.check_output function and simulating its behavior.
        """
        with patch('platform.system', return_value="Linux"):
            with patch('subprocess.check_output', return_value=b'MyWiFiNetwork\n'):
                monitor = WiFiMonitor("us-west-2", "sg-12345678", ["Target"])
                wifi_name = monitor.get_wifi_name()
                assert wifi_name == "MyWiFiNetwork"

    def test_get_wifi_name_3(self):
        """
        Test get_wifi_name method for Windows system when SSID is present in the output.

        This test case verifies that the get_wifi_name method correctly extracts and returns
        the WiFi name (SSID) from the output of 'netsh wlan show interfaces' command on Windows.
        It mocks the subprocess.check_output to return a predefined output containing an SSID.
        """
        with patch('platform.system', return_value='Windows'):
            with patch('subprocess.check_output') as mock_check_output:
                mock_check_output.return_value = b'''
                    Interface name : Wi-Fi
                    There is 1 interface on the system:

                    Name                   : Wi-Fi
                    Description            : Realtek 8822BE Wireless LAN 802.11ac PCI-E NIC
                    GUID                   : 7b4e87d6-5c78-4d1b-8b4e-ea2811a4f1bc
                    Physical address       : 00:11:22:33:44:55
                    State                  : connected
                    SSID                   : TestWiFi
                    BSSID                  : aa:bb:cc:dd:ee:ff
                    Network type           : Infrastructure
                    Radio type             : 802.11n
                    Authentication         : WPA2-Personal
                    Cipher                 : CCMP
                    Connection mode        : Auto Connect
                    Channel                : 1
                    Receive rate (Mbps)    : 144
                    Transmit rate (Mbps)   : 144
                    Signal                 : 100%
                    Profile                : TestWiFi

                    Hosted network status  : Not available
                '''

                wifi_monitor = WiFiMonitor('us-west-2', 'sg-12345678', ['TestWiFi'])
                result = wifi_monitor.get_wifi_name()
                self.assertEqual(result, 'TestWiFi')

    def test_get_wifi_name_subprocess_error(self):
        """
        Test get_wifi_name method when subprocess.check_output raises a CalledProcessError.
        This test verifies that the method handles subprocess errors by returning None
        and printing an error message.
        """
        with patch('subprocess.check_output', side_effect=subprocess.CalledProcessError(1, 'cmd')):
            monitor = WiFiMonitor('us-west-2', 'sg-12345678', ['Target_WiFi'])
            result = monitor.get_wifi_name()
            assert result is None

    def test_get_wifi_name_unsupported_os(self):
        """
        Test the get_wifi_name method when the operating system is not supported.

        This test verifies that the method returns None and prints an error message
        when the system is neither Darwin (macOS), Linux, nor Windows.
        """
        with patch('platform.system', return_value='SomeOtherOS'):
            monitor = WiFiMonitor('us-west-2', 'sg-12345678', ['Target_WiFi'])
            with patch('builtins.print') as mock_print:
                result = monitor.get_wifi_name()
                mock_print.assert_called_once_with("Unsupported operating system: SomeOtherOS")
                assert result is None

    def test_get_wifi_name_unsupported_os_2(self):
        """
        Test get_wifi_name method with an unsupported operating system.
        This test verifies that the method handles unsupported operating systems
        by returning None and printing an error message.
        """
        with patch('platform.system', return_value='UnknownOS'):
            monitor = WiFiMonitor('us-west-2', 'sg-12345678', ['Target_WiFi'])
            result = monitor.get_wifi_name()
            assert result is None

    def test_run_1(self):
        """
        Tests the run method when connected to a target WiFi and public IP is available.

        This test verifies that:
        1. The correct WiFi name is detected
        2. The public IP is successfully retrieved
        3. The AWS security group is updated with the correct IP
        4. Appropriate messages are printed
        """
        mock_wifi_monitor = WiFiMonitor("us-west-2", "sg-1234567890abcdef0", ["Target_WiFi"])

        with patch.object(mock_wifi_monitor, 'get_wifi_name', return_value="Target_WiFi"), \
             patch('wifi_monitor.wifi_monitor.monitor.get_public_ip', return_value="1.2.3.4"), \
             patch.object(mock_wifi_monitor, 'update_aws_security_group') as mock_update, \
             patch('builtins.print') as mock_print:

            mock_wifi_monitor.run()

            mock_update.assert_called_once_with("1.2.3.4")
            mock_print.assert_any_call("Connected to Target_WiFi")
            mock_print.assert_any_call("Public IP: 1.2.3.4")

    def test_run_2(self):
        """
        Tests the run method when connected to a target Wi-Fi but unable to determine public IP.

        This test verifies that the run method behaves correctly when:
        1. The current Wi-Fi name is in the list of target Wi-Fi names.
        2. The public IP cannot be determined (get_public_ip returns None).

        Expected behavior:
        - The method should print that it's connected to the Wi-Fi.
        - It should also print that it's unable to determine the public IP.
        - The update_aws_security_group method should not be called.
        """
        mock_wifi_name = "Target_WiFi"
        mock_target_wifi_names = ["Target_WiFi", "Another_WiFi"]

        with patch('wifi_monitor.wifi_monitor.monitor.WiFiMonitor.get_wifi_name', return_value=mock_wifi_name), \
             patch('wifi_monitor.wifi_monitor.monitor.get_public_ip', return_value=None), \
             patch('builtins.print') as mock_print, \
             patch('wifi_monitor.wifi_monitor.monitor.WiFiMonitor.update_aws_security_group') as mock_update:

            monitor = WiFiMonitor("us-west-2", "sg-12345", mock_target_wifi_names)
            monitor.run()

            mock_print.assert_any_call(f"Connected to {mock_wifi_name}")
            mock_print.assert_any_call("Unable to determine public IP")
            mock_update.assert_not_called()

    def test_run_3(self):
        """
        Test the run method when the current WiFi is not in the target WiFi names.

        This test verifies that the appropriate message is printed when the device
        is connected to a WiFi network that is not in the list of target networks.
        """
        # Mock the WiFiMonitor instance
        monitor = WiFiMonitor("us-west-2", "sg-1234567890abcdef0", ["Target1", "Target2"])

        # Mock the get_wifi_name method to return a non-target WiFi
        with patch.object(WiFiMonitor, 'get_wifi_name', return_value='NonTargetWiFi'):
            # Capture the printed output
            with patch('builtins.print') as mock_print:
                monitor.run()

                # Assert that the correct message is printed
                mock_print.assert_called_once_with("Not connected to any target Wi-Fi. Current Wi-Fi: NonTargetWiFi")

    def test_run_non_target_wifi(self):
        """
        Test the run method when connected to a non-target Wi-Fi network.
        This is an edge case explicitly handled in the focal method.
        """
        monitor = WiFiMonitor("us-west-2", "sg-12345678", ["Target1", "Target2"])
        with patch.object(monitor, 'get_wifi_name', return_value="NonTarget"):
            with patch('builtins.print') as mock_print:
                monitor.run()
                mock_print.assert_called_with("Not connected to any target Wi-Fi. Current Wi-Fi: NonTarget")

    def test_run_unable_to_determine_public_ip(self):
        """
        Test the run method when unable to determine the public IP.
        This is an edge case explicitly handled in the focal method.
        """
        monitor = WiFiMonitor("us-west-2", "sg-12345678", ["Target1", "Target2"])
        with patch.object(monitor, 'get_wifi_name', return_value="Target1"):
            with patch('wifi_monitor.wifi_monitor.monitor.get_public_ip', return_value=None):
                with patch('builtins.print') as mock_print:
                    monitor.run()
                    mock_print.assert_called_with("Unable to determine public IP")

    @mock_ec2
    def test_update_aws_security_group_2(self):
        """
        Test updating AWS security group when there are no existing rules.

        This test verifies that the update_aws_security_group method correctly
        handles the case where there are no existing rules in the security group.
        It checks if the method successfully adds a new ingress rule for the given IP address.
        """
        # Set up mock EC2 client and create a security group
        ec2 = boto3.client('ec2', region_name='us-west-2')
        response = ec2.create_security_group(
            GroupName='test-group',
            Description='Test security group'
        )
        security_group_id = response['GroupId']

        # Create WiFiMonitor instance
        monitor = WiFiMonitor('us-west-2', security_group_id, ['TestWiFi'])

        # Call the method under test
        ip_address = '192.168.1.1'
        monitor.update_aws_security_group(ip_address)

        # Verify the security group was updated correctly
        response = ec2.describe_security_groups(GroupIds=[security_group_id])
        rules = response['SecurityGroups'][0]['IpPermissions']

        assert len(rules) == 1
        assert rules[0]['IpProtocol'] == 'tcp'
        assert rules[0]['FromPort'] == 22
        assert rules[0]['ToPort'] == 22
        assert rules[0]['IpRanges'][0]['CidrIp'] == f'{ip_address}/32'

    def test_update_aws_security_group_client_error(self):
        """
        Test that ClientError is handled when updating the AWS security group.
        """
        monitor = WiFiMonitor("us-west-2", "sg-12345", ["Test-WiFi"])

        with patch('boto3.client') as mock_client:
            mock_ec2 = MagicMock()
            mock_client.return_value = mock_ec2
            mock_ec2.describe_security_groups.side_effect = ClientError(
                {'Error': {'Code': 'InvalidGroupId.NotFound', 'Message': 'The security group ID does not exist'}},
                'DescribeSecurityGroups'
            )

            with pytest.raises(SystemExit):
                monitor.update_aws_security_group("192.168.1.1")

            assert mock_ec2.describe_security_groups.called
            assert not mock_ec2.revoke_security_group_ingress.called
            assert not mock_ec2.authorize_security_group_ingress.called

    def test_update_aws_security_group_with_existing_rules(self):
        """
        Test updating AWS security group when existing rules are present.
        This test verifies that the method correctly revokes existing rules
        and authorizes new ingress rules for the specified IP address.
        """
        mock_ec2 = Mock()
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'IpPermissions': [{'existing': 'rule'}]
            }]
        }

        with patch('boto3.client', return_value=mock_ec2):
            monitor = WiFiMonitor('us-west-2', 'sg-12345', ['TestWiFi'])
            monitor.update_aws_security_group('192.168.1.1')

        mock_ec2.revoke_security_group_ingress.assert_called_once_with(
            GroupId='sg-12345',
            IpPermissions=[{'existing': 'rule'}]
        )
        mock_ec2.authorize_security_group_ingress.assert_called_once_with(
            GroupId='sg-12345',
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '192.168.1.1/32'}]
                }
            ]
        )
