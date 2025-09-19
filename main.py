#!/usr/bin/env python3
"""
AWS Network Discovery and Analysis Script
Main entry point for the application.
"""

import click
import logging
import sys
from pathlib import Path
from typing import List, Optional

from aws_network_discovery.config.settings import Config
from aws_network_discovery.auth.sso_auth import SSOAuthenticator
from aws_network_discovery.discovery.orchestrator import DiscoveryOrchestrator
from aws_network_discovery.analysis.analyzer import NetworkAnalyzer
from aws_network_discovery.outputs.report_generator import ReportGenerator
from aws_network_discovery.utils.logger import setup_logging


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--log-level', default='INFO', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']))
@click.option('--log-file', type=click.Path(), help='Log file path')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification for AWS SDK calls (not recommended)')
@click.pass_context
def cli(ctx, config, log_level, log_file, no_ssl_verify):
    """AWS Network Discovery and Analysis Tool"""
    ctx.ensure_object(dict)
    
    # Setup logging
    setup_logging(log_level, log_file)
    
    # Load configuration
    ctx.obj['config'] = Config(config_file=config)
    # SSL verification flag
    ctx.obj['no_ssl_verify'] = bool(no_ssl_verify)


@cli.command()
@click.option('--profile', multiple=True, required=True, help='AWS SSO profile name. Repeat this option to specify multiple profiles, e.g., --profile prof1 --profile prof2')
@click.option('--regions', default='us-east-1,eu-west-1,eu-central-1', help='Comma-separated list of regions')
@click.option('--output-file', '-o', default='network_data.json', help='Output JSON file path')
@click.option('--accounts', help='Comma-separated list of account IDs (optional)')
@click.option('--role-arn-template', help='AssumeRole ARN template for cross-account discovery, e.g., arn:aws:iam::{account}:role/NetworkAuditRole')
@click.pass_context
def discover(ctx, profile, regions, output_file, accounts, role_arn_template):
    """Discover AWS network resources and save to JSON file"""
    config = ctx.obj['config']
    
    try:
        # Parse regions and accounts
        region_list = [r.strip() for r in regions.split(',')]
        account_list = [a.strip() for a in accounts.split(',')] if accounts else None
        profiles = list(profile) if isinstance(profile, (list, tuple)) else [profile]

        combined_data = {}
        for prof in profiles:
            # Authenticate per profile
            authenticator = SSOAuthenticator(prof)
            credentials = authenticator.get_credentials()

            cross_account_roles = _build_cross_account_roles(account_list, role_arn_template)
            orchestrator = DiscoveryOrchestrator(
                credentials,
                config,
                profile_name=prof,
                cross_account_roles=cross_account_roles,
                no_ssl_verify=ctx.obj.get('no_ssl_verify', False)
            )
            profile_data = orchestrator.discover_all(region_list, account_list)

            # Merge into combined dataset
            combined_data = _merge_discovery_datasets(combined_data, profile_data)

        # Save merged data to file
        # Use the last orchestrator for saving convenience (same formatting)
        orchestrator.save_data(combined_data, output_file)

        click.echo(f"✅ Discovery completed. Profiles: {', '.join(profiles)}. Data saved to {output_file}")
        
    except Exception as e:
        logging.error(f"Discovery failed: {str(e)}")
        sys.exit(1)


# French alias for analyze
@cli.command(name='analyse')
@click.option('--input-file', '-i', required=True, type=click.Path(exists=True), help='Chemin du fichier JSON en entrée')
@click.option('--output-dir', '-o', default='./reports', help='Répertoire de sortie pour les rapports')
@click.pass_context
def analyse(ctx, input_file, output_dir):
    """Alias français pour la commande analyze"""
    return ctx.invoke(analyze, input_file=input_file, output_dir=output_dir)


@cli.command()
@click.option('--input-file', '-i', required=True, type=click.Path(exists=True), help='Input JSON file path')
@click.option('--output-dir', '-o', default='./reports', help='Output directory for reports')
@click.pass_context
def analyze(ctx, input_file, output_dir):
    """Analyze network data from JSON file and generate reports"""
    config = ctx.obj['config']
    
    try:
        # Load data
        analyzer = NetworkAnalyzer(config)
        network_data = analyzer.load_data(input_file)
        
        # Analyze communication paths
        analysis_results = analyzer.analyze_communication_paths(network_data)
        
        # Generate reports
        report_generator = ReportGenerator(config)
        report_generator.generate_all_reports(analysis_results, output_dir)
        
        click.echo(f"✅ Analysis completed. Reports generated in {output_dir}")
        
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}")
        sys.exit(1)


@cli.command()
@click.option('--profile', multiple=True, required=True, help='AWS SSO profile name. Repeat this option to specify multiple profiles, e.g., --profile prof1 --profile prof2')
@click.option('--regions', default='us-east-1,eu-west-1,eu-central-1', help='Comma-separated list of regions')
@click.option('--output-dir', '-o', default='./reports', help='Output directory for reports')
@click.option('--accounts', help='Comma-separated list of account IDs (optional)')
@click.option('--data-file', help='Intermediate data file name (default: network_data.json)')
@click.option('--role-arn-template', help='AssumeRole ARN template for cross-account discovery, e.g., arn:aws:iam::{account}:role/NetworkAuditRole')
@click.pass_context
def full(ctx, profile, regions, output_dir, accounts, data_file, role_arn_template):
    """Run full discovery and analysis pipeline"""
    config = ctx.obj['config']
    
    if not data_file:
        data_file = Path(output_dir) / 'network_data.json'
    
    try:
        # Parse regions and accounts
        region_list = [r.strip() for r in regions.split(',')]
        account_list = [a.strip() for a in accounts.split(',')] if accounts else None
        profiles = list(profile) if isinstance(profile, (list, tuple)) else [profile]
        
        # Phase 1: Discovery
        click.echo("🔍 Starting discovery phase...")
        combined_data = {}
        orchestrator = None
        for prof in profiles:
            authenticator = SSOAuthenticator(prof)
            credentials = authenticator.get_credentials()

            cross_account_roles = _build_cross_account_roles(account_list, role_arn_template)
            orchestrator = DiscoveryOrchestrator(credentials, config, profile_name=prof, cross_account_roles=cross_account_roles)
            profile_data = orchestrator.discover_all(region_list, account_list)
            combined_data = _merge_discovery_datasets(combined_data, profile_data)
        
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        orchestrator.save_data(combined_data, str(data_file))
        
        click.echo(f"✅ Discovery completed for profiles: {', '.join(profiles)}. Data saved to {data_file}")
        
        # Phase 2: Analysis
        click.echo("📊 Starting analysis phase...")
        analyzer = NetworkAnalyzer(config)
        analysis_results = analyzer.analyze_communication_paths(combined_data)
        
        # Generate reports
        report_generator = ReportGenerator(config)
        report_generator.generate_all_reports(analysis_results, output_dir)
        
        click.echo(f"✅ Full pipeline completed. Reports generated in {output_dir}")
        
    except Exception as e:
        logging.error(f"Pipeline failed: {str(e)}")
        sys.exit(1)


def _merge_discovery_datasets(base: dict, incoming: dict) -> dict:
    """Deep-merge two discovery datasets by concatenating regional lists.

    This keeps the schema expected by the analyzer intact while aggregating data
    across multiple profiles/accounts. Assumes leaf nodes under region keys are lists
    and merges dict subtrees recursively.
    """
    if not base:
        return incoming or {}
    if not incoming:
        return base

    def merge(a, b):
        if isinstance(a, dict) and isinstance(b, dict):
            out = dict(a)
            for k, v in b.items():
                if k in out:
                    out[k] = merge(out[k], v)
                else:
                    out[k] = v
            return out
        elif isinstance(a, list) and isinstance(b, list):
            return a + b
        else:
            # Prefer incoming for scalars/others
            return b

    return merge(base, incoming)


def _build_cross_account_roles(account_list: Optional[List[str]], role_arn_template: Optional[str]) -> Optional[dict]:
    """Build a mapping of account_id -> role_arn using a template.

    Example template: arn:aws:iam::{account}:role/NetworkAuditRole
    """
    if not account_list or not role_arn_template:
        return {}

    mapping = {}
    for acct in account_list:
        role_arn = role_arn_template.replace('{account}', acct)
        mapping[acct] = role_arn
    return mapping


@cli.command()
@click.option('--profile', required=True, help='AWS SSO profile name')
def test_auth(profile):
    """Test AWS SSO authentication"""
    try:
        authenticator = SSOAuthenticator(profile)
        credentials = authenticator.get_credentials()
        
        click.echo("✅ Authentication successful!")
        click.echo(f"Access Key: {credentials['AccessKeyId'][:10]}...")
        
    except Exception as e:
        click.echo(f"❌ Authentication failed: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
