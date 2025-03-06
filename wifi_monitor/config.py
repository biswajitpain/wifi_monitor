class ConfigManager:
    @staticmethod
    def load_config():
        # In a real-world scenario, you might load this from a config file
        return {
            'aws_region': 'your-aws-region',
            'security_group_id': 'your-security-group-id',
            'target_wifi_names': ['Wi-Fi Name 1', 'Wi-Fi Name 2', 'Wi-Fi Name 3']
        }