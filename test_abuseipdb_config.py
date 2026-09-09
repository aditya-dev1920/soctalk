#!/usr/bin/env python
"""Test AbuseIPDB MCP configuration generation."""

import os
import sys
from pathlib import Path

# Set up environment
os.environ['ABUSEIPDB_API_KEY'] = 'test'
os.environ['ABUSEIPDB_ENABLED'] = 'true'

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from soctalk.settings_provider import (
    load_integration_settings_from_env, 
    create_mcp_configs,
    load_integration_secrets_from_env
)

# Load settings and secrets
secrets = load_integration_secrets_from_env()
settings = load_integration_settings_from_env()

print('=' * 60)
print('AbuseIPDB Configuration Test')
print('=' * 60)

print('\n✓ Secrets loaded:')
print(f'  abuseipdb_api_key present: {bool(secrets.abuseipdb_api_key)}')

print('\n✓ Integration settings loaded:')
print(f'  abuseipdb_enabled: {settings.abuseipdb_enabled}')

# Create MCP configs
configs = create_mcp_configs(settings)

print('\n✓ EnabledMCPServers created:')
print(f'  abuseipdb config: {configs.abuseipdb is not None}')
print(f'  enabled_count: {configs.enabled_count}')

if configs.abuseipdb:
    print('\n✓ AbuseIPDB MCPServerConfig details:')
    print(f'  name: {configs.abuseipdb.name}')
    print(f'  path: {configs.abuseipdb.path}')
    print(f'  args: {configs.abuseipdb.args}')
    print(f'  env_vars: {configs.abuseipdb.env_vars}')
    
    # Verify it matches expected format
    print('\n✓ Validation checks:')
    path_matches = str(configs.abuseipdb.path) == 'uvx'
    args_matches = configs.abuseipdb.args == ['mcp-abuseipdb']
    env_matches = configs.abuseipdb.env_vars == {'ABUSEIPDB_API_KEY': 'test'}
    
    print(f'  Path is "uvx": {path_matches}')
    print(f'  Args are ["mcp-abuseipdb"]: {args_matches}')
    print(f'  Env vars correct: {env_matches}')
    
    if path_matches and args_matches and env_matches:
        print('\n' + '=' * 60)
        print('✓ Configuration matches acceptance criteria!')
        print('=' * 60)
        sys.exit(0)
    else:
        print('\n' + '=' * 60)
        print('✗ Configuration does not match acceptance criteria')
        print('=' * 60)
        sys.exit(1)
else:
    print('\n' + '=' * 60)
    print('✗ ERROR: abuseipdb config is None!')
    print('=' * 60)
    sys.exit(1)
