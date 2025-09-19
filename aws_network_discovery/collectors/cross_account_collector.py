"""
Cross-Account Resource Collector
Handles discovery of resources across multiple AWS accounts
"""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError
import boto3

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)


class CrossAccountCollector(BaseCollector):
    """Collector for cross-account resource discovery"""
    
    def __init__(self, authenticator, config):
        super().__init__(authenticator, config)
        self.account_roles = {}  # Maps account_id -> role_arn
        self.cross_account_sessions = {}  # Cache for cross-account sessions
        
    def get_resource_type(self) -> str:
        return 'cross_account_resources'
    
    def set_cross_account_roles(self, account_roles: Dict[str, str]) -> None:
        """
        Set cross-account role mappings
        
        Args:
            account_roles: Dictionary mapping account_id -> role_arn
        """
        self.account_roles = account_roles
        logger.info(f"Configured cross-account access for {len(account_roles)} accounts")
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect cross-account connectivity resources
        
        Args:
            regions: List of AWS regions
            account_ids: List of account IDs to collect from
            
        Returns:
            Dictionary containing cross-account resource data
        """
        if not account_ids:
            logger.warning("No account IDs provided for cross-account collection")
            return {}
        
        logger.info(f"Collecting cross-account resources from {len(account_ids)} accounts across {len(regions)} regions")
        
        results = {
            'vpc_peering_connections': {},
            'transit_gateway_attachments': {},
            'cross_account_security_group_refs': {},
            'vpc_endpoints': {},
            'cross_region_replications': {}
        }
        
        for account_id in account_ids:
            logger.info(f"Processing account: {account_id}")
            
            # Collect VPC peering connections
            peering_data = self._collect_vpc_peering_connections(regions, account_id)
            results['vpc_peering_connections'][account_id] = peering_data
            
            # Collect Transit Gateway attachments
            tgw_data = self._collect_transit_gateway_attachments(regions, account_id)
            results['transit_gateway_attachments'][account_id] = tgw_data
            
            # Collect cross-account security group references
            sg_refs = self._collect_cross_account_sg_refs(regions, account_id)
            results['cross_account_security_group_refs'][account_id] = sg_refs
            
            # Collect VPC endpoints
            vpc_endpoints = self._collect_vpc_endpoints(regions, account_id)
            results['vpc_endpoints'][account_id] = vpc_endpoints
        
        self.collected_data = results
        return results
    
    def _get_cross_account_client(self, service_name: str, region: str, account_id: str):
        """
        Get AWS client for cross-account access
        
        Args:
            service_name: AWS service name
            region: AWS region
            account_id: Target account ID
            
        Returns:
            AWS service client for the target account
        """
        session_key = f"{account_id}_{region}"
        
        if session_key not in self.cross_account_sessions:
            try:
                # Get the role ARN for this account
                role_arn = self.account_roles.get(account_id)
                if not role_arn:
                    logger.warning(f"No cross-account role configured for account {account_id}")
                    return None
                
                # Assume the cross-account role
                sts_client = self.authenticator.get_client('sts', region)
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=f"NetworkTopologyAnalyzer-{account_id}"
                )
                
                credentials = assumed_role['Credentials']
                
                # Create session with assumed role credentials
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=region
                )
                
                self.cross_account_sessions[session_key] = session
                logger.debug(f"Created cross-account session for account {account_id} in region {region}")
                
            except ClientError as e:
                logger.error(f"Failed to assume role for account {account_id}: {e}")
                return None
        
        session = self.cross_account_sessions[session_key]
        return session.client(service_name)
    
    def _collect_vpc_peering_connections(self, regions: List[str], account_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect VPC peering connections for cross-VPC communication
        
        Args:
            regions: List of regions to collect from
            account_id: Account ID to collect from
            
        Returns:
            Dictionary with region as key and peering connections as value
        """
        results = {}
        
        for region in regions:
            try:
                ec2_client = self._get_cross_account_client('ec2', region, account_id)
                if not ec2_client:
                    results[region] = []
                    continue
                
                # Get VPC peering connections
                response = ec2_client.describe_vpc_peering_connections()
                peering_connections = response.get('VpcPeeringConnections', [])
                
                enriched_connections = []
                for conn in peering_connections:
                    enriched_conn = self._enrich_peering_connection(conn, region, account_id)
                    enriched_connections.append(enriched_conn)
                
                results[region] = enriched_connections
                logger.debug(f"Collected {len(enriched_connections)} VPC peering connections from account {account_id}, region {region}")
                
            except Exception as e:
                logger.error(f"Failed to collect VPC peering connections from account {account_id}, region {region}: {e}")
                results[region] = []
        
        return results
    
    def _collect_transit_gateway_attachments(self, regions: List[str], account_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect Transit Gateway attachments for cross-region/cross-account routing
        
        Args:
            regions: List of regions to collect from
            account_id: Account ID to collect from
            
        Returns:
            Dictionary with region as key and TGW attachments as value
        """
        results = {}
        
        for region in regions:
            try:
                ec2_client = self._get_cross_account_client('ec2', region, account_id)
                if not ec2_client:
                    results[region] = []
                    continue
                
                # Get Transit Gateways
                tgw_response = ec2_client.describe_transit_gateways()
                transit_gateways = tgw_response.get('TransitGateways', [])
                
                all_attachments = []
                for tgw in transit_gateways:
                    tgw_id = tgw['TransitGatewayId']
                    
                    # Get attachments for this TGW
                    attachments_response = ec2_client.describe_transit_gateway_attachments(
                        Filters=[
                            {'Name': 'transit-gateway-id', 'Values': [tgw_id]}
                        ]
                    )
                    
                    attachments = attachments_response.get('TransitGatewayAttachments', [])
                    for attachment in attachments:
                        enriched_attachment = self._enrich_tgw_attachment(attachment, tgw, region, account_id)
                        all_attachments.append(enriched_attachment)
                
                results[region] = all_attachments
                logger.debug(f"Collected {len(all_attachments)} TGW attachments from account {account_id}, region {region}")
                
            except Exception as e:
                logger.error(f"Failed to collect TGW attachments from account {account_id}, region {region}: {e}")
                results[region] = []
        
        return results
    
    def _collect_cross_account_sg_refs(self, regions: List[str], account_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect security groups with cross-account references
        
        Args:
            regions: List of regions to collect from
            account_id: Account ID to collect from
            
        Returns:
            Dictionary with region as key and cross-account SG references as value
        """
        results = {}
        
        for region in regions:
            try:
                ec2_client = self._get_cross_account_client('ec2', region, account_id)
                if not ec2_client:
                    results[region] = []
                    continue
                
                # Get all security groups
                response = ec2_client.describe_security_groups()
                security_groups = response.get('SecurityGroups', [])
                
                cross_account_refs = []
                for sg in security_groups:
                    cross_refs = self._find_cross_account_sg_references(sg, account_id)
                    if cross_refs:
                        cross_account_refs.extend(cross_refs)
                
                results[region] = cross_account_refs
                logger.debug(f"Found {len(cross_account_refs)} cross-account SG references in account {account_id}, region {region}")
                
            except Exception as e:
                logger.error(f"Failed to collect cross-account SG refs from account {account_id}, region {region}: {e}")
                results[region] = []
        
        return results
    
    def _collect_vpc_endpoints(self, regions: List[str], account_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect VPC endpoints for private service connections
        
        Args:
            regions: List of regions to collect from
            account_id: Account ID to collect from
            
        Returns:
            Dictionary with region as key and VPC endpoints as value
        """
        results = {}
        
        for region in regions:
            try:
                ec2_client = self._get_cross_account_client('ec2', region, account_id)
                if not ec2_client:
                    results[region] = []
                    continue
                
                # Get VPC endpoints
                response = ec2_client.describe_vpc_endpoints()
                vpc_endpoints = response.get('VpcEndpoints', [])
                
                enriched_endpoints = []
                for endpoint in vpc_endpoints:
                    enriched_endpoint = self._enrich_vpc_endpoint(endpoint, region, account_id)
                    enriched_endpoints.append(enriched_endpoint)
                
                results[region] = enriched_endpoints
                logger.debug(f"Collected {len(enriched_endpoints)} VPC endpoints from account {account_id}, region {region}")
                
            except Exception as e:
                logger.error(f"Failed to collect VPC endpoints from account {account_id}, region {region}: {e}")
                results[region] = []
        
        return results
    
    def _enrich_peering_connection(self, conn: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich VPC peering connection data"""
        enriched = self._enrich_resource_data(conn, region, account_id)
        
        # Add cross-account/cross-region flags
        accepter_vpc = conn.get('AccepterVpcInfo', {})
        requester_vpc = conn.get('RequesterVpcInfo', {})
        
        enriched.update({
            'IsCrossAccount': accepter_vpc.get('OwnerId') != requester_vpc.get('OwnerId'),
            'IsCrossRegion': accepter_vpc.get('Region') != requester_vpc.get('Region'),
            'AccepterAccountId': accepter_vpc.get('OwnerId'),
            'RequesterAccountId': requester_vpc.get('OwnerId'),
            'AccepterRegion': accepter_vpc.get('Region'),
            'RequesterRegion': requester_vpc.get('Region'),
            'ConnectionType': 'VPC_PEERING'
        })
        
        return enriched
    
    def _enrich_tgw_attachment(self, attachment: Dict[str, Any], tgw: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich Transit Gateway attachment data"""
        enriched = self._enrich_resource_data(attachment, region, account_id)
        
        enriched.update({
            'TransitGatewayId': tgw.get('TransitGatewayId'),
            'TransitGatewayArn': tgw.get('TransitGatewayArn'),
            'TransitGatewayOwnerId': tgw.get('OwnerId'),
            'IsCrossAccount': attachment.get('ResourceOwnerId') != tgw.get('OwnerId'),
            'ConnectionType': 'TRANSIT_GATEWAY',
            'ResourceType': attachment.get('ResourceType'),
            'ResourceId': attachment.get('ResourceId')
        })
        
        return enriched
    
    def _enrich_vpc_endpoint(self, endpoint: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich VPC endpoint data"""
        enriched = self._enrich_resource_data(endpoint, region, account_id)
        
        enriched.update({
            'ConnectionType': 'VPC_ENDPOINT',
            'ServiceName': endpoint.get('ServiceName'),
            'VpcEndpointType': endpoint.get('VpcEndpointType'),
            'IsPrivateService': endpoint.get('ServiceName', '').startswith('com.amazonaws.'),
            'RouteTableIds': endpoint.get('RouteTableIds', []),
            'SubnetIds': endpoint.get('SubnetIds', []),
            'SecurityGroupIds': endpoint.get('Groups', [])
        })
        
        return enriched
    
    def _find_cross_account_sg_references(self, sg: Dict[str, Any], current_account_id: str) -> List[Dict[str, Any]]:
        """Find cross-account security group references in rules"""
        cross_refs = []
        
        # Check inbound rules
        for rule in sg.get('IpPermissions', []):
            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                ref_account_id = user_id_group_pair.get('UserId')
                if ref_account_id and ref_account_id != current_account_id:
                    cross_refs.append({
                        'SourceSecurityGroupId': sg.get('GroupId'),
                        'SourceSecurityGroupName': sg.get('GroupName'),
                        'ReferencedSecurityGroupId': user_id_group_pair.get('GroupId'),
                        'ReferencedAccountId': ref_account_id,
                        'RuleDirection': 'inbound',
                        'Protocol': rule.get('IpProtocol'),
                        'FromPort': rule.get('FromPort'),
                        'ToPort': rule.get('ToPort'),
                        'ConnectionType': 'CROSS_ACCOUNT_SECURITY_GROUP'
                    })
        
        # Check outbound rules
        for rule in sg.get('IpPermissionsEgress', []):
            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                ref_account_id = user_id_group_pair.get('UserId')
                if ref_account_id and ref_account_id != current_account_id:
                    cross_refs.append({
                        'SourceSecurityGroupId': sg.get('GroupId'),
                        'SourceSecurityGroupName': sg.get('GroupName'),
                        'ReferencedSecurityGroupId': user_id_group_pair.get('GroupId'),
                        'ReferencedAccountId': ref_account_id,
                        'RuleDirection': 'outbound',
                        'Protocol': rule.get('IpProtocol'),
                        'FromPort': rule.get('FromPort'),
                        'ToPort': rule.get('ToPort'),
                        'ConnectionType': 'CROSS_ACCOUNT_SECURITY_GROUP'
                    })
        
        return cross_refs
