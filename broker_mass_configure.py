#!/usr/bin/env python3
"""
Mass Broker Configuration Script

This script demonstrates the complete workflow for mass configuring
Snyk organizations with broker connections.
"""

import os
import sys
import argparse
import logging
from snyk_api import SnykAPI, Organization, BrokerConnection


def main():
    """Main function for mass broker configuration"""
    
    # Configure logging to both file and console
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('broker_config.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    parser = argparse.ArgumentParser(description="Mass configure Snyk broker for organizations")
    parser.add_argument('--snyk-token', required=True, help='Snyk API token')
    parser.add_argument('--tenant-id', required=True, help='Snyk tenant ID')
    parser.add_argument('--group-id', required=True, help='Snyk group ID')
    parser.add_argument('--source-org-id', required=False, help='Source organization ID with broker connection (required for configuration)')
    parser.add_argument('--broker-connection-id', help='Specific broker connection ID to use (optional)')
    parser.add_argument('--remove-connection', help='Remove this broker connection ID from all orgs in the group')
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making changes')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Validate mode-specific requirements
    if not args.remove_connection and not args.source_org_id:
        parser.error('--source-org-id is required unless --remove-connection is provided')

    # Initialize Snyk API client
    snyk = SnykAPI(
        token=args.snyk_token,
        tenant_id=args.tenant_id,
        group_id=args.group_id,
        source_org_id=args.source_org_id,
        debug=args.debug
    )
    
    print("🚀 Starting Mass Broker Configuration")
    print("=" * 50)
    
    try:
        # If removal mode is requested, run it and exit
        if args.remove_connection:
            print(f"\n🗑️  Removal mode: connection {args.remove_connection} across group {args.group_id}")
            if args.dry_run:
                print("🧪 DRY RUN ENABLED: No changes will be made")
            results = snyk.remove_connection_from_all_orgs(
                connection_id=args.remove_connection,
                group_id=args.group_id,
                dry_run=args.dry_run,
            )
            print("\n📊 Removal Results:")
            print(f"  ✅ Success: {len(results['success'])}")
            print(f"  ❌ Failed: {len(results['failed'])}")
            print(f"  🔎 Not Found: {len(results['not_found'])}")
            if results['success']:
                print("\n✅ Orgs updated:")
                for r in results['success']:
                    if results.get('dry_run'):
                        print(f"  - {r['org_name']} ({r['org_id']}): would remove {r['integrations_to_remove']} integration(s)")
                    else:
                        print(f"  - {r['org_name']} ({r['org_id']}): removed {r['integrations_removed']} integration(s)")
            if results['failed']:
                print("\n❌ Failed removals:")
                for r in results['failed']:
                    print(f"  - {r['org_name']} ({r['org_id']}): {r['reason']}")
            if results['not_found']:
                print("\n🔎 Connection not found in:")
                for r in results['not_found']:
                    print(f"  - {r['org_name']} ({r['org_id']})")
            print("\n✅ Removal process completed!")
            return

        # Step 1: Get all organizations in the group
        print(f"\n📋 Step 1: Fetching organizations for group {args.group_id}...")
        all_orgs = snyk.get_organizations_for_group()
        print(f"Found {len(all_orgs)} organizations in group")
        
        # Step 2: Get target organizations (excluding source org)
        print(f"\n🎯 Step 2: Identifying target organizations (excluding source org {args.source_org_id})...")
        target_orgs = snyk.get_target_organizations_for_broker_config()
        print(f"Found {len(target_orgs)} target organizations:")
        for org in target_orgs:
            print(f"  - {org.name} ({org.id})")
        
        if not target_orgs:
            print("❌ No target organizations found. Exiting.")
            return
        
        # Step 3: Get broker connections from source organization
        print(f"\n🔗 Step 3: Fetching broker connections from source organization {args.source_org_id}...")
        broker_connections = snyk.get_broker_connections()
        
        if not broker_connections:
            print(f"❌ No broker connections found in source organization {args.source_org_id}")
            print("   Please ensure the source organization has broker connections configured")
            return
        
        print(f"Found {len(broker_connections)} broker connections:")
        for i, connection in enumerate(broker_connections, 1):
            print(f"  {i}. {connection.name} ({connection.id})")
            print(f"     Type: {connection.connection_type}")
            print(f"     Deployment: {connection.deployment_id}")
        
        # Step 4: Select broker connection
        if args.broker_connection_id:
            # Use specified broker connection
            selected_connection = None
            for connection in broker_connections:
                if connection.id == args.broker_connection_id:
                    selected_connection = connection
                    break
            
            if not selected_connection:
                print(f"❌ Broker connection {args.broker_connection_id} not found")
                return
        else:
            # Use first broker connection
            selected_connection = broker_connections[0]
        
        print(f"\n🔧 Step 4: Using broker connection: {selected_connection.name} ({selected_connection.id})")
        
        # Step 5: Configure broker for target organizations
        if args.dry_run:
            print(f"\n🧪 DRY RUN: Would configure broker for {len(target_orgs)} organizations")
            print("Target organizations:")
            for org in target_orgs:
                print(f"  - {org.name} ({org.id})")
            print("\n✅ Dry run completed. No changes were made.")
        else:
            print(f"\n🚀 Step 5: Configuring broker for {len(target_orgs)} target organizations...")
            results = snyk.configure_broker_for_organizations_bulk(selected_connection.id)
            
            # Display results
            print(f"\n📊 Configuration Results:")
            print(f"  ✅ Success: {len(results['success'])}")
            print(f"  ❌ Failed: {len(results['failed'])}")
            print(f"  ⏭️  Skipped: {len(results['skipped'])}")
            
            if results['success']:
                print(f"\n✅ Successfully configured organizations:")
                for result in results['success']:
                    print(f"  - {result['org_name']} ({result['org_id']})")
            
            if results['failed']:
                print(f"\n❌ Failed to configure organizations:")
                for result in results['failed']:
                    print(f"  - {result['org_name']} ({result['org_id']}): {result['reason']}")
            
            if results['skipped']:
                print(f"\n⏭️  Skipped organizations:")
                for result in results['skipped']:
                    print(f"  - {result['org_id']}: {result['reason']}")
        
        print(f"\n✅ Mass broker configuration completed!")
        
    except Exception as e:
        print(f"❌ Error during broker configuration: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
