
"""
Recursively Converts .env data into vault entries
Great for converting docker .env files into vault records
"""

import hvac
import os
from dotenv import dotenv_values

environment=dotenv_values("/home/coder/Master/Dev/Docker_Containers/Production/Environment/.env")
client = hvac.Client(url='http://192.168.3.201:8200', token=environment["vault_token"])

def add_env_files_to_vault(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.env'):
                env_path = os.path.join(root, file)
                env_vars = dotenv_values(env_path)
                for key, value in env_vars.items():
                    client.secrets.kv.v2.create_or_update_secret(
                        path= f'{os.path.basename(root)}/{key}',
                        secret=dict(key=value),
                    )
                    # secret_path = f'kv/{os.path.basename(root)}/{key}'
                    # client.write(secret_path, "10s")
                    print(f"Added secret '{key}' to Vault.")

# Specify the directory to start the search
directory_to_search = '/home/coder/Master/Dev/Docker_Containers/Production'

# Execute function to add .env files to Vault
add_env_files_to_vault(directory_to_search)

