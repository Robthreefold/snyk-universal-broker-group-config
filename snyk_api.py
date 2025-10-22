#!/usr/bin/env python3
"""
Snyk API Client for Mass Broker Configuration

This module provides a comprehensive Snyk API client based on the snyk-sca-validator
project, enhanced with broker-specific functionality for mass organization configuration.
"""

import requests
import json
from typing import Dict, List, Optional, Any, NamedTuple
from datetime import datetime
import logging
from dataclasses import dataclass


@dataclass
class Organization:
    """Data model for Snyk organization"""
    id: str
    name: str
    slug: str
    group_id: str
    is_personal: bool
    access_requests_enabled: bool
    created_at: str
    updated_at: str


@dataclass
class BrokerConnection:
    """Data model for Snyk broker connection"""
    id: str
    name: str
    connection_type: str
    deployment_id: str


@dataclass
class BrokerIntegration:
    """Data model for Snyk broker integration"""
    id: str
    org_id: str
    integration_type: str


class SnykAPI:
    """
    Snyk API client for fetching organizations, targets, projects, and managing broker configurations.
    
    This class is based on the snyk-sca-validator project and enhanced with broker-specific
    functionality for mass organization configuration.
    """
    
    def __init__(self, token: str, tenant_id: str = None, group_id: str = None, source_org_id: str = None, region: str = 'SNYK-US-01', debug: bool = False):
        """
        Initialize the Snyk API client.
        
        Args:
            token: Snyk API token
            tenant_id: Snyk tenant ID (optional)
            group_id: Snyk group ID for collecting organizations
            source_org_id: Source organization ID for broker configuration
            region: Snyk API region (default: SNYK-US-01)
            debug: Enable debug logging
        """
        self.token = token
        self.tenant_id = tenant_id
        self.group_id = group_id
        self.source_org_id = source_org_id
        self.region = region
        self.debug = debug
        self.base_url = f"https://api.snyk.io/rest"
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {token}',
            'Content-Type': 'application/vnd.api+json'
        })
        
        # Set up logging
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
    
    def _debug_log(self, message: str) -> None:
        """Print debug message if debug mode is enabled"""
        if self.debug:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"[{timestamp}] 🔍 DEBUG: {message}")
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling and debug logging"""
        self._debug_log(f"API Request - {method} {url}")
        if 'params' in kwargs:
            self._debug_log(f"Params: {kwargs['params']}")
        if 'json' in kwargs:
            self._debug_log(f"JSON: {kwargs['json']}")
        
        response = self.session.request(method, url, **kwargs)
        self._debug_log(f"Response status: {response.status_code}")
        
        if response.status_code >= 400:
            self._debug_log(f"Error response: {response.text}")
        
        return response
    
    def get_organizations(self) -> List[Dict]:
        """Get list of organizations accessible to the token"""
        self._debug_log("Fetching Snyk organizations")
        url = f"{self.base_url}/orgs"
        resp = self._make_request('GET', url)
        
        if resp.status_code == 200:
            data = resp.json()
            orgs = data.get('data', [])
            self._debug_log(f"Found {len(orgs)} organizations")
            return orgs
        else:
            self._debug_log(f"Snyk organizations error: {resp.status_code} - {resp.text}")
            return []
    
    def get_organizations_for_group(self, group_id: str = None) -> List[Organization]:
        """
        Get list of organizations in a specific group using the official API endpoint.
        
        Args:
            group_id: Group ID to fetch organizations for. If None, uses self.group_id
            
        Returns:
            List of Organization objects
        """
        if group_id is None:
            group_id = self.group_id
            
        if not group_id:
            raise ValueError("Group ID must be provided either as parameter or in constructor")
            
        self._debug_log(f"Fetching organizations for group: {group_id}")
        
        url = f"{self.base_url}/groups/{group_id}/orgs"
        params = {'version': '2024-10-15', 'limit': 100}
        
        all_orgs = []
        page = 1
        
        while True:
            self._debug_log(f"Group orgs API - URL: {url}, params: {params}, page: {page}")
            resp = self._make_request('GET', url, params=params)
            
            if resp.status_code == 200:
                data = resp.json()
                orgs = data.get('data', [])
                if not orgs:
                    break
                
                # Convert to Organization objects
                for org_data in orgs:
                    attrs = org_data.get('attributes', {})
                    org = Organization(
                        id=org_data.get('id'),
                        name=attrs.get('name', ''),
                        slug=attrs.get('slug', ''),
                        group_id=attrs.get('group_id', ''),
                        is_personal=attrs.get('is_personal', False),
                        access_requests_enabled=attrs.get('access_requests_enabled', False),
                        created_at=attrs.get('created_at', ''),
                        updated_at=attrs.get('updated_at', '')
                    )
                    all_orgs.append(org)
                
                self._debug_log(f"Fetched {len(orgs)} orgs on page {page}, total: {len(all_orgs)}")
                
                # Check for next page using links.next
                links = data.get('links', {})
                next_url = links.get('next')
                if not next_url:
                    break
                
                # Ensure the URL has the full base URL
                if next_url.startswith('/'):
                    url = f"https://api.snyk.io{next_url}"
                else:
                    url = next_url
                page += 1
                
            elif resp.status_code == 404:
                self._debug_log(f"Group {group_id} not found")
                return []
            elif resp.status_code in [403, 401]:
                self._debug_log(f"Access denied to group {group_id}")
                return []
            else:
                self._debug_log(f"Group orgs API error {resp.status_code}: {resp.text}")
                return []
        
        self._debug_log(f"Successfully fetched {len(all_orgs)} organizations for group {group_id}")
        return all_orgs
    
    def _get_group_orgs_with_version(self, group_id: str, version: str) -> Optional[List[Dict]]:
        """Get organizations for group with specific API version"""
        url = f"{self.base_url}/groups/{group_id}/orgs"
        params = {'version': version, 'limit': 100}
        
        all_orgs = []
        page = 1
        
        while True:
            self._debug_log(f"Group orgs API - URL: {url}, params: {params}, page: {page}")
            resp = self._make_request('GET', url, params=params)
            
            if resp.status_code == 200:
                data = resp.json()
                orgs = data.get('data', [])
                if not orgs:
                    break
                
                all_orgs.extend(orgs)
                self._debug_log(f"Fetched {len(orgs)} orgs on page {page}, total: {len(all_orgs)}")
                
                # Check for next page using links.next
                links = data.get('links', {})
                next_url = links.get('next')
                if not next_url:
                    break
                
                # Ensure the URL has the full base URL
                if next_url.startswith('/'):
                    url = f"https://api.snyk.io{next_url}"
                else:
                    url = next_url
                page += 1
                
            elif resp.status_code == 404:
                self._debug_log(f"Group {group_id} not found with version {version}")
                return None
            elif resp.status_code in [403, 401]:
                self._debug_log(f"Access denied to group {group_id} with version {version}")
                return None
            else:
                self._debug_log(f"Group orgs API error {resp.status_code}: {resp.text}")
                return None
        
        return all_orgs
    
    def validate_organization_access(self, org_id: str) -> bool:
        """Check if organization is accessible with API version fallback"""
        self._debug_log(f"Validating access to organization: {org_id}")
        
        # Try different API versions
        versions = ['2024-10-15', '2023-05-29', '2023-06-18']
        
        for version in versions:
            self._debug_log(f"Trying API version: {version}")
            url = f"{self.base_url}/orgs/{org_id}"
            params = {'version': version}
            
            resp = self._make_request('GET', url, params=params)
            
            if resp.status_code == 200:
                self._debug_log(f"Organization access successful with version {version}")
                return True
            elif resp.status_code == 404:
                self._debug_log(f"Organization not found with version {version}")
                continue
            elif resp.status_code in [403, 401]:
                self._debug_log(f"Access denied to organization with version {version}")
                return False
            else:
                self._debug_log(f"Unexpected error {resp.status_code} with version {version}: {resp.text}")
                continue
        
        self._debug_log("Organization access failed with all API versions")
        return False
    
    def get_organization_details(self, org_id: str) -> Optional[Dict]:
        """Get detailed information about a specific organization"""
        self._debug_log(f"Fetching organization details: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}"
        params = {'version': '2024-10-15'}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            self._debug_log(f"Retrieved organization details for {org_id}")
            return data.get('data')
        else:
            self._debug_log(f"Organization details API error {resp.status_code}: {resp.text}")
            return None
    
    def get_organization_name(self, org_id: str) -> str:
        """Get organization name by ID"""
        org_details = self.get_organization_details(org_id)
        if org_details:
            return org_details.get('attributes', {}).get('name', org_id)
        return org_id
    
    def get_targets_for_org(self, org_id: str) -> List[Dict]:
        """Get targets for organization with API version fallback"""
        self._debug_log(f"Fetching targets for organization: {org_id}")
        
        # First validate organization access
        if not self.validate_organization_access(org_id):
            self._debug_log(f"Organization {org_id} is not accessible")
            return []
        
        # Try different API versions for targets
        versions = ['2024-10-15', '2023-05-29', '2023-06-18']
        
        for version in versions:
            self._debug_log(f"Trying targets API with version: {version}")
            targets = self._get_targets_with_version(org_id, version)
            if targets is not None:
                self._debug_log(f"Successfully fetched {len(targets)} targets with version {version}")
                return targets
            else:
                self._debug_log(f"Failed to fetch targets with version {version}")
        
        self._debug_log("Failed to fetch targets with all API versions")
        return []
    
    def _get_targets_with_version(self, org_id: str, version: str) -> Optional[List[Dict]]:
        """Get targets for organization with specific API version"""
        url = f"{self.base_url}/orgs/{org_id}/targets"
        params = {'version': version}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            targets = data.get('data', [])
            self._debug_log(f"Found {len(targets)} targets")
            return targets
        elif resp.status_code == 404:
            self._debug_log(f"Organization {org_id} not found with version {version}")
            return None
        elif resp.status_code in [403, 401]:
            self._debug_log(f"Access denied to organization {org_id} with version {version}")
            return None
        else:
            self._debug_log(f"Targets API error {resp.status_code}: {resp.text}")
            return None
    
    def get_projects_for_org(self, org_id: str) -> List[Dict]:
        """Get all projects for an organization"""
        self._debug_log(f"Fetching all projects for org: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/projects"
        params = {'version': '2024-10-15'}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            projects = data.get('data', [])
            self._debug_log(f"Found {len(projects)} total projects in org {org_id}")
            return projects
        else:
            self._debug_log(f"All projects API error {resp.status_code}: {resp.text}")
            return []
    
    def get_project_details(self, org_id: str, project_id: str) -> Optional[Dict]:
        """Get detailed information about a specific project"""
        self._debug_log(f"Fetching project details: {project_id}")
        url = f"{self.base_url}/orgs/{org_id}/projects/{project_id}"
        params = {'version': '2024-10-15'}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            self._debug_log(f"Retrieved project details for {project_id}")
            return data.get('data')
        else:
            self._debug_log(f"Project details API error {resp.status_code}: {resp.text}")
            return None
    
    # Broker-specific methods for mass configuration
    
    def get_integrations_for_org(self, org_id: str) -> List[Dict]:
        """Get integrations for an organization"""
        self._debug_log(f"Fetching integrations for organization: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/integrations"
        params = {'version': '2024-10-15'}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            integrations = data.get('data', [])
            self._debug_log(f"Found {len(integrations)} integrations for org {org_id}")
            return integrations
        else:
            self._debug_log(f"Integrations API error {resp.status_code}: {resp.text}")
            return []
    
    def create_integration(self, org_id: str, integration_type: str, settings: Dict) -> Optional[Dict]:
        """Create a new integration for an organization"""
        self._debug_log(f"Creating {integration_type} integration for organization: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/integrations"
        params = {'version': '2024-10-15'}
        
        payload = {
            'data': {
                'type': 'integration',
                'attributes': {
                    'type': integration_type,
                    'settings': settings
                }
            }
        }
        
        resp = self._make_request('POST', url, params=params, json=payload)
        
        if resp.status_code == 201:
            data = resp.json()
            self._debug_log(f"Successfully created {integration_type} integration")
            return data.get('data')
        else:
            self._debug_log(f"Integration creation error {resp.status_code}: {resp.text}")
            return None
    
    def update_integration(self, org_id: str, integration_id: str, settings: Dict) -> Optional[Dict]:
        """Update an existing integration"""
        self._debug_log(f"Updating integration {integration_id} for organization: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/integrations/{integration_id}"
        params = {'version': '2024-10-15'}
        
        payload = {
            'data': {
                'type': 'integration',
                'id': integration_id,
                'attributes': {
                    'settings': settings
                }
            }
        }
        
        resp = self._make_request('PATCH', url, params=params, json=payload)
        
        if resp.status_code == 200:
            data = resp.json()
            self._debug_log(f"Successfully updated integration {integration_id}")
            return data.get('data')
        else:
            self._debug_log(f"Integration update error {resp.status_code}: {resp.text}")
            return None
    
    def delete_integration(self, org_id: str, integration_id: str) -> bool:
        """Delete an integration"""
        self._debug_log(f"Deleting integration {integration_id} for organization: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/integrations/{integration_id}"
        params = {'version': '2024-10-15'}
        
        resp = self._make_request('DELETE', url, params=params)
        
        if resp.status_code == 204:
            self._debug_log(f"Successfully deleted integration {integration_id}")
            return True
        else:
            self._debug_log(f"Integration deletion error {resp.status_code}: {resp.text}")
            return False
    
    def get_broker_integrations(self, org_id: str) -> List[Dict]:
        """Get broker integrations for an organization"""
        integrations = self.get_integrations_for_org(org_id)
        broker_integrations = []
        
        for integration in integrations:
            integration_type = integration.get('attributes', {}).get('type', '')
            if 'broker' in integration_type.lower() or 'snyk-broker' in integration_type.lower():
                broker_integrations.append(integration)
        
        self._debug_log(f"Found {len(broker_integrations)} broker integrations for org {org_id}")
        return broker_integrations
    
    def configure_broker_integration(self, org_id: str, broker_settings: Dict) -> Optional[Dict]:
        """
        Configure or update broker integration for an organization.
        
        Args:
            org_id: Organization ID
            broker_settings: Dictionary containing broker configuration settings
                Example: {
                    'broker_token': 'your-broker-token',
                    'broker_server_url': 'https://broker.snyk.io',
                    'allowed_orgs': ['org1', 'org2'],
                    'snyk_api_url': 'https://api.snyk.io',
                    'snyk_api_token': 'your-snyk-token'
                }
        """
        self._debug_log(f"Configuring broker integration for organization: {org_id}")
        
        # Check if broker integration already exists
        existing_brokers = self.get_broker_integrations(org_id)
        
        if existing_brokers:
            # Update existing broker integration
            broker_id = existing_brokers[0].get('id')
            self._debug_log(f"Updating existing broker integration: {broker_id}")
            return self.update_integration(org_id, broker_id, broker_settings)
        else:
            # Create new broker integration
            self._debug_log("Creating new broker integration")
            return self.create_integration(org_id, 'snyk-broker', broker_settings)
    
    def mass_configure_broker(self, org_ids: List[str], broker_settings: Dict) -> Dict[str, Any]:
        """
        Mass configure broker integration for multiple organizations.
        
        Args:
            org_ids: List of organization IDs to configure
            broker_settings: Broker configuration settings
            
        Returns:
            Dictionary with results for each organization
        """
        results = {
            'success': [],
            'failed': [],
            'skipped': []
        }
        
        self._debug_log(f"Starting mass broker configuration for {len(org_ids)} organizations")
        
        for i, org_id in enumerate(org_ids, 1):
            self._debug_log(f"Processing organization {i}/{len(org_ids)}: {org_id}")
            
            try:
                # Validate organization access
                if not self.validate_organization_access(org_id):
                    results['skipped'].append({
                        'org_id': org_id,
                        'reason': 'Organization not accessible'
                    })
                    continue
                
                # Configure broker integration
                result = self.configure_broker_integration(org_id, broker_settings)
                
                if result:
                    results['success'].append({
                        'org_id': org_id,
                        'org_name': self.get_organization_name(org_id),
                        'integration_id': result.get('id'),
                        'status': 'configured'
                    })
                else:
                    results['failed'].append({
                        'org_id': org_id,
                        'org_name': self.get_organization_name(org_id),
                        'reason': 'Failed to configure broker integration'
                    })
                    
            except Exception as e:
                self._debug_log(f"Error configuring broker for org {org_id}: {str(e)}")
                results['failed'].append({
                    'org_id': org_id,
                    'org_name': self.get_organization_name(org_id),
                    'reason': f"Exception: {str(e)}"
                })
        
        self._debug_log(f"Mass configuration complete: {len(results['success'])} success, {len(results['failed'])} failed, {len(results['skipped'])} skipped")
        return results
    
    def get_organization_settings(self, org_id: str) -> Optional[Dict]:
        """Get organization settings and configuration"""
        self._debug_log(f"Fetching organization settings: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/settings"
        params = {'version': '2024-10-15'}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            self._debug_log(f"Retrieved organization settings for {org_id}")
            return data.get('data')
        else:
            self._debug_log(f"Organization settings API error {resp.status_code}: {resp.text}")
            return None
    
    def update_organization_settings(self, org_id: str, settings: Dict) -> Optional[Dict]:
        """Update organization settings"""
        self._debug_log(f"Updating organization settings: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/settings"
        params = {'version': '2024-10-15'}
        
        payload = {
            'data': {
                'type': 'settings',
                'attributes': settings
            }
        }
        
        resp = self._make_request('PATCH', url, params=params, json=payload)
        
        if resp.status_code == 200:
            data = resp.json()
            self._debug_log(f"Successfully updated organization settings for {org_id}")
            return data.get('data')
        else:
            self._debug_log(f"Organization settings update error {resp.status_code}: {resp.text}")
            return None
    
    # Broker-specific methods for mass configuration
    
    def get_broker_connections(self, org_id: str = None) -> List[BrokerConnection]:
        """
        Get broker connections for an organization.
        
        Args:
            org_id: Organization ID. If None, uses self.source_org_id
            
        Returns:
            List of BrokerConnection objects
        """
        if org_id is None:
            org_id = self.source_org_id
            
        if not org_id:
            raise ValueError("Organization ID must be provided either as parameter or in constructor")
            
        self._debug_log(f"Fetching broker connections for organization: {org_id}")
        url = f"{self.base_url}/orgs/{org_id}/brokers/connections"
        params = {'version': '2025-09-28', 'limit': 100}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            connections_data = data.get('data', [])
            
            connections = []
            for conn_data in connections_data:
                attrs = conn_data.get('attributes', {})
                connection = BrokerConnection(
                    id=conn_data.get('id'),
                    name=attrs.get('name', ''),
                    connection_type=attrs.get('connection_type', ''),
                    deployment_id=attrs.get('deployment_id', '')
                )
                connections.append(connection)
            
            self._debug_log(f"Found {len(connections)} broker connections for org {org_id}")
            return connections
        else:
            self._debug_log(f"Broker connections API error {resp.status_code}: {resp.text}")
            return []
    
    def get_target_organizations_for_broker_config(self) -> List[Organization]:
        """
        Get all organizations in the group except the source organization.
        This is used to determine which organizations need broker configuration.
        
        Returns:
            List of Organization objects (excluding source org)
        """
        if not self.group_id:
            raise ValueError("Group ID must be provided in constructor")
            
        if not self.source_org_id:
            raise ValueError("Source organization ID must be provided in constructor")
        
        # Get all organizations in the group
        all_orgs = self.get_organizations_for_group()
        
        # Filter out the source organization
        target_orgs = [org for org in all_orgs if org.id != self.source_org_id]
        
        self._debug_log(f"Found {len(target_orgs)} target organizations (excluding source org {self.source_org_id})")
        return target_orgs
    
    def configure_broker_for_organizations_bulk(self, broker_connection_id: str = None) -> Dict[str, List[str]]:
        """
        Configure broker for all target organizations using bulk approach.
        
        Workflow:
        1. Get all orgs from group
        2. Identify source org's broker configuration
        3. Delete ALL broker configs for target orgs
        4. Configure broker on all target orgs
        
        Args:
            broker_connection_id: Specific broker connection ID to use (optional)
            
        Returns:
            Dictionary with 'success', 'failed', and 'skipped' lists
        """
        # Step 1: Get all organizations from the group
        all_orgs = self.get_organizations_for_group()
        if not all_orgs:
            self._debug_log("No organizations found in group")
            return {'success': [], 'failed': [], 'skipped': []}
        
        self._debug_log(f"Found {len(all_orgs)} organizations in group")
        
        # Step 2: Identify source org's broker configuration
        if not broker_connection_id:
            source_connections = self.get_broker_connections(self.source_org_id)
            if not source_connections:
                self._debug_log(f"No broker connections found in source org {self.source_org_id}")
                return {'success': [], 'failed': [], 'skipped': []}
            
            broker_connection_id = source_connections[0].id
            self._debug_log(f"Using broker connection {broker_connection_id} from source org")
        
        # Get source org's integration details
        source_integrations = self.get_broker_integrations_for_connection(broker_connection_id)
        source_integration = None
        for integration in source_integrations:
            if integration.org_id == self.source_org_id:
                source_integration = integration
                break
        
        if not source_integration:
            self._debug_log(f"Source org {self.source_org_id} does not have integration for connection {broker_connection_id}")
            return {'success': [], 'failed': [], 'skipped': []}
        
        self._debug_log(f"Source org integration: {source_integration.id}, type: {source_integration.integration_type}")
        
        # Step 3: Delete ALL broker configurations for target orgs
        target_orgs = [org for org in all_orgs if org.id != self.source_org_id]
        self._debug_log(f"Deleting existing broker configurations for {len(target_orgs)} target organizations")
        
        for integration in source_integrations:
            if integration.org_id != self.source_org_id:  # Skip source org
                self._debug_log(f"Deleting existing integration {integration.id} for org {integration.org_id}")
                success = self.delete_broker_integration(broker_connection_id, integration.org_id, integration.id)
                if not success:
                    self._debug_log(f"Failed to delete integration {integration.id} for org {integration.org_id}")
        
        # Step 4: Configure broker on all target orgs
        success_list = []
        failed_list = []
        skipped_list = []
        
        for i, org in enumerate(target_orgs, 1):
            self._debug_log(f"Configuring broker for organization {i}/{len(target_orgs)}: {org.name} ({org.id})")
            
            try:
                # Validate access to organization
                if not self.validate_organization_access(org.id):
                    self._debug_log(f"Access denied to organization {org.id}")
                    failed_list.append({
                        'org_id': org.id,
                        'org_name': org.name,
                        'reason': 'Access denied'
                    })
                    continue
                
                # Create new broker integration
                success = self.create_broker_integration(
                    broker_connection_id,
                    org.id,
                    f"{org.id}-{broker_connection_id}",  # Generate unique integration ID
                    source_integration.integration_type
                )
                
                if success:
                    success_list.append({
                        'org_id': org.id,
                        'org_name': org.name,
                        'broker_connection_id': broker_connection_id,
                        'status': 'configured'
                    })
                    self._debug_log(f"Successfully configured broker for {org.name}")
                else:
                    failed_list.append({
                        'org_id': org.id,
                        'org_name': org.name,
                        'reason': 'Failed to create broker integration'
                    })
                    self._debug_log(f"Failed to configure broker for {org.name}")
                    
            except Exception as e:
                self._debug_log(f"Error processing organization {org.id}: {str(e)}")
                failed_list.append({
                    'org_id': org.id,
                    'org_name': org.name,
                    'reason': str(e)
                })
        
        return {
            'success': success_list,
            'failed': failed_list,
            'skipped': skipped_list
        }

    def configure_broker_for_organizations(self, broker_connection_id: str, target_org_ids: List[str] = None) -> Dict[str, Any]:
        """
        Configure broker for target organizations.
        
        Args:
            broker_connection_id: ID of the broker connection from source org
            target_org_ids: List of target organization IDs. If None, uses all orgs in group except source
            
        Returns:
            Dictionary with results for each organization
        """
        if target_org_ids is None:
            target_orgs = self.get_target_organizations_for_broker_config()
            target_org_ids = [org.id for org in target_orgs]
        
        results = {
            'success': [],
            'failed': [],
            'skipped': []
        }
        
        self._debug_log(f"Starting broker configuration for {len(target_org_ids)} target organizations")
        
        for i, org_id in enumerate(target_org_ids, 1):
            self._debug_log(f"Processing organization {i}/{len(target_org_ids)}: {org_id}")
            
            try:
                # Validate organization access
                if not self.validate_organization_access(org_id):
                    results['skipped'].append({
                        'org_id': org_id,
                        'org_name': self.get_organization_name(org_id),
                        'reason': 'Organization not accessible'
                    })
                    continue
                
                # Configure broker integration for this organization
                # This would need to be implemented based on the specific broker configuration API
                # For now, we'll simulate the configuration
                success = self._configure_broker_for_org(org_id, broker_connection_id)
                
                if success:
                    results['success'].append({
                        'org_id': org_id,
                        'org_name': self.get_organization_name(org_id),
                        'broker_connection_id': broker_connection_id,
                        'status': 'configured'
                    })
                else:
                    results['failed'].append({
                        'org_id': org_id,
                        'org_name': self.get_organization_name(org_id),
                        'reason': 'Failed to configure broker integration'
                    })
                    
            except Exception as e:
                self._debug_log(f"Error configuring broker for org {org_id}: {str(e)}")
                results['failed'].append({
                    'org_id': org_id,
                    'org_name': self.get_organization_name(org_id),
                    'reason': f"Exception: {str(e)}"
                })
        
        self._debug_log(f"Broker configuration complete: {len(results['success'])} success, {len(results['failed'])} failed, {len(results['skipped'])} skipped")
        return results
    
    def get_broker_integrations_for_connection(self, connection_id: str) -> List[BrokerIntegration]:
        """
        Get all integrations using a specific broker connection.
        
        Args:
            connection_id: Broker connection ID
            
        Returns:
            List of BrokerIntegration objects
        """
        if not self.tenant_id:
            raise ValueError("Tenant ID must be provided in constructor")
            
        self._debug_log(f"Fetching broker integrations for connection: {connection_id}")
        url = f"{self.base_url}/tenants/{self.tenant_id}/brokers/connections/{connection_id}/integrations"
        params = {'version': '2025-09-28'}
        
        resp = self._make_request('GET', url, params=params)
        
        if resp.status_code == 200:
            data = resp.json()
            integrations_data = data.get('data', [])
            
            integrations = []
            for integration_data in integrations_data:
                integration = BrokerIntegration(
                    id=integration_data.get('id'),
                    org_id=integration_data.get('org_id'),
                    integration_type=integration_data.get('integration_type')
                )
                integrations.append(integration)
            
            self._debug_log(f"Found {len(integrations)} broker integrations for connection {connection_id}")
            return integrations
        else:
            self._debug_log(f"Broker integrations API error {resp.status_code}: {resp.text}")
            return []
    
    def delete_broker_integration(self, connection_id: str, org_id: str, integration_id: str) -> bool:
        """
        Delete a broker integration for an organization.
        
        Args:
            connection_id: Broker connection ID
            org_id: Organization ID
            integration_id: Integration ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        if not self.tenant_id:
            raise ValueError("Tenant ID must be provided in constructor")
            
        self._debug_log(f"Deleting broker integration {integration_id} for org {org_id}")
        url = f"{self.base_url}/tenants/{self.tenant_id}/brokers/connections/{connection_id}/orgs/{org_id}/integrations/{integration_id}"
        params = {'version': '2025-09-28'}
        
        resp = self._make_request('DELETE', url, params=params)
        
        if resp.status_code == 204:
            self._debug_log(f"Successfully deleted broker integration {integration_id}")
            return True
        else:
            self._debug_log(f"Failed to delete broker integration {integration_id}: {resp.status_code} - {resp.text}")
            return False
    
    def create_broker_integration(self, connection_id: str, org_id: str, integration_id: str, integration_type: str) -> bool:
        """
        Create a broker integration for an organization.
        
        Args:
            connection_id: Broker connection ID
            org_id: Organization ID
            integration_id: Integration ID to create
            integration_type: Type of integration (e.g., 'bitbucket-server')
            
        Returns:
            True if successful, False otherwise
        """
        if not self.tenant_id:
            raise ValueError("Tenant ID must be provided in constructor")
            
        self._debug_log(f"Creating broker integration {integration_id} for org {org_id}")
        url = f"{self.base_url}/tenants/{self.tenant_id}/brokers/connections/{connection_id}/orgs/{org_id}/integration"
        params = {'version': '2025-09-28'}
        
        payload = {
            'data': {
                'type': integration_type
            }
        }
        
        resp = self._make_request('POST', url, params=params, json=payload)
        
        if resp.status_code == 201:
            self._debug_log(f"Successfully created broker integration {integration_id}")
            return True
        else:
            self._debug_log(f"Failed to create broker integration {integration_id}: {resp.status_code} - {resp.text}")
            return False
    
    def _configure_broker_for_org(self, org_id: str, broker_connection_id: str) -> bool:
        """
        Configure broker for a specific organization.
        This method implements the complete workflow:
        1. Check if org already has the target broker connection
        2. If yes, skip
        3. If no, check for existing integrations and remove them
        4. Create new broker integration
        
        Args:
            org_id: Target organization ID
            broker_connection_id: Broker connection ID from source org
            
        Returns:
            True if successful, False otherwise
        """
        self._debug_log(f"Configuring broker connection {broker_connection_id} for org {org_id}")
        
        try:
            # Step 1: Get all integrations using this broker connection
            integrations = self.get_broker_integrations_for_connection(broker_connection_id)
            
            # Step 2: Check if source org has the connection (required)
            source_has_connection = False
            source_integration = None
            for integration in integrations:
                if integration.org_id == self.source_org_id:
                    source_has_connection = True
                    source_integration = integration
                    break
            
            if not source_has_connection:
                self._debug_log(f"ERROR: Source org {self.source_org_id} does not have broker connection {broker_connection_id}")
                return False
            
            # Step 3: Delete any existing integrations for the target org
            for integration in integrations:
                if integration.org_id == org_id:
                    self._debug_log(f"Removing existing integration {integration.id} for org {org_id}")
                    success = self.delete_broker_integration(broker_connection_id, org_id, integration.id)
                    if not success:
                        self._debug_log(f"Failed to remove existing integration {integration.id}")
                        return False
            
            # Step 4: Create new integration for the target org
            integration_type = source_integration.integration_type
            
            success = self.create_broker_integration(
                broker_connection_id, 
                org_id, 
                integration_id,  # This will be generated by the API
                integration_type
            )
            
            if success:
                self._debug_log(f"Successfully configured broker for org {org_id}")
                return True
            else:
                self._debug_log(f"Failed to create broker integration for org {org_id}")
                return False
                
        except Exception as e:
            self._debug_log(f"Error configuring broker for org {org_id}: {str(e)}")
            return False
