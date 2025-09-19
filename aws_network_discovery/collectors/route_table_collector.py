"""
Route Table Collector
Collects route tables and their routing rules for path analysis
"""

import logging
from typing import Dict, List, Any, Optional
from ipaddress import IPv4Network, IPv6Network, AddressValueError

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)


class RouteTableCollector(BaseCollector):
    """Collector for Route Tables"""
    
    def get_resource_type(self) -> str:
        return 'route_tables'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect Route Tables from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing Route Table data by region
        """
        logger.info(f"Collecting Route Tables from {len(regions)} regions")
        
        def collect_region_route_tables(region: str) -> List[Dict[str, Any]]:
            return self._collect_route_tables_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_route_tables, "Collecting Route Tables")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_route_tables = sum(len(rts) for rts in results.values())
        logger.info(f"Collected {total_route_tables} Route Tables across {len(regions)} regions")
        
        return results
    
    def _collect_route_tables_from_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Collect Route Tables from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            List of Route Table data
        """
        try:
            ec2_client = self._get_client('ec2', region)
            
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # Collect route tables using pagination
            route_tables = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_route_tables')
            )
            
            # Enrich each route table with detailed analysis
            enriched_route_tables = []
            for rt in route_tables:
                enriched_rt = self._enrich_route_table_data(rt, region, account_id)
                enriched_route_tables.append(enriched_rt)
            
            # Filter based on configuration
            filtered_route_tables = self._filter_resources(enriched_route_tables)
            
            logger.debug(f"Collected {len(filtered_route_tables)} Route Tables from region {region}")
            return filtered_route_tables
            
        except Exception as e:
            logger.error(f"Failed to collect Route Tables from region {region}: {e}")
            return []
    
    def _enrich_route_table_data(self, rt: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich route table data with detailed analysis
        
        Args:
            rt: Raw route table data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched route table data
        """
        # Start with base enrichment
        enriched = self._enrich_resource_data(rt, region, account_id)
        
        # Add route table-specific enrichments
        enriched.update({
            'Name': self._extract_name_from_tags(rt.get('Tags', [])),
            'RouteTableId': rt.get('RouteTableId'),
            'VpcId': rt.get('VpcId'),
            'IsMainRouteTable': self._is_main_route_table(rt),
            'AssociatedSubnets': self._get_associated_subnets(rt.get('Associations', [])),
            'Routes': self._process_routes(rt.get('Routes', [])),
            'RouteAnalysis': self._analyze_routes(rt.get('Routes', [])),
            'ConnectivityMap': self._build_connectivity_map(rt.get('Routes', [])),
            'SecurityImpact': self._assess_route_security_impact(rt.get('Routes', []))
        })
        
        return enriched
    
    def _process_routes(self, routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and enrich route entries
        
        Args:
            routes: List of route entries
            
        Returns:
            List of processed routes
        """
        processed_routes = []
        
        for route in routes:
            processed_route = {
                'DestinationCidrBlock': route.get('DestinationCidrBlock'),
                'DestinationIpv6CidrBlock': route.get('DestinationIpv6CidrBlock'),
                'DestinationPrefixListId': route.get('DestinationPrefixListId'),
                'State': route.get('State'),
                'Origin': route.get('Origin'),
                'RouteType': self._determine_route_type(route),
                'Target': self._get_route_target(route),
                'TargetType': self._get_route_target_type(route),
                'IsActive': route.get('State') == 'active',
                'IsLocal': route.get('GatewayId') == 'local',
                'IsCrossRegion': self._is_cross_region_route(route),
                'IsCrossAccount': self._is_cross_account_route(route),
                'SecurityRisk': self._assess_route_security_risk(route)
            }
            
            # Add network analysis
            processed_route['NetworkAnalysis'] = self._analyze_route_network(processed_route)
            
            processed_routes.append(processed_route)
        
        return processed_routes
    
    def _analyze_routes(self, routes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze route table for patterns and issues
        
        Args:
            routes: List of route entries
            
        Returns:
            Dictionary containing route analysis
        """
        analysis = {
            'total_routes': len(routes),
            'active_routes': len([r for r in routes if r.get('State') == 'active']),
            'local_routes': len([r for r in routes if r.get('GatewayId') == 'local']),
            'internet_routes': 0,
            'nat_routes': 0,
            'vpc_peering_routes': 0,
            'transit_gateway_routes': 0,
            'vpn_routes': 0,
            'default_route_exists': False,
            'route_conflicts': [],
            'redundant_routes': [],
            'security_issues': []
        }
        
        # Categorize routes by target type
        for route in routes:
            if route.get('State') != 'active':
                continue
                
            # Check for default route
            if route.get('DestinationCidrBlock') == '0.0.0.0/0':
                analysis['default_route_exists'] = True
            
            # Categorize by gateway type
            if route.get('GatewayId'):
                gateway_id = route.get('GatewayId')
                if gateway_id.startswith('igw-'):
                    analysis['internet_routes'] += 1
                elif gateway_id.startswith('nat-'):
                    analysis['nat_routes'] += 1
                elif gateway_id.startswith('vgw-') or gateway_id.startswith('vpn-'):
                    analysis['vpn_routes'] += 1
            
            if route.get('VpcPeeringConnectionId'):
                analysis['vpc_peering_routes'] += 1
            
            if route.get('TransitGatewayId'):
                analysis['transit_gateway_routes'] += 1
        
        # Find route conflicts and redundancies
        analysis['route_conflicts'] = self._find_route_conflicts(routes)
        analysis['redundant_routes'] = self._find_redundant_routes(routes)
        analysis['security_issues'] = self._find_route_security_issues(routes)
        
        return analysis
    
    def _build_connectivity_map(self, routes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build a connectivity map showing reachable destinations
        
        Args:
            routes: List of route entries
            
        Returns:
            Dictionary containing connectivity information
        """
        connectivity = {
            'internet_access': False,
            'private_networks': [],
            'cross_vpc_connections': [],
            'external_connections': [],
            'reachable_cidrs': []
        }
        
        for route in routes:
            if route.get('State') != 'active':
                continue
            
            dest_cidr = route.get('DestinationCidrBlock')
            dest_ipv6_cidr = route.get('DestinationIpv6CidrBlock')
            
            # Check for internet access
            if dest_cidr == '0.0.0.0/0' and route.get('GatewayId', '').startswith('igw-'):
                connectivity['internet_access'] = True
            
            # Collect reachable CIDRs
            if dest_cidr:
                connectivity['reachable_cidrs'].append({
                    'cidr': dest_cidr,
                    'target': self._get_route_target(route),
                    'target_type': self._get_route_target_type(route),
                    'is_private': self._is_private_cidr(dest_cidr)
                })
            
            if dest_ipv6_cidr:
                connectivity['reachable_cidrs'].append({
                    'cidr': dest_ipv6_cidr,
                    'target': self._get_route_target(route),
                    'target_type': self._get_route_target_type(route),
                    'is_private': self._is_private_ipv6_cidr(dest_ipv6_cidr)
                })
            
            # Identify cross-VPC connections
            if route.get('VpcPeeringConnectionId'):
                connectivity['cross_vpc_connections'].append({
                    'destination_cidr': dest_cidr or dest_ipv6_cidr,
                    'peering_connection_id': route.get('VpcPeeringConnectionId'),
                    'connection_type': 'vpc_peering'
                })
            
            if route.get('TransitGatewayId'):
                connectivity['cross_vpc_connections'].append({
                    'destination_cidr': dest_cidr or dest_ipv6_cidr,
                    'transit_gateway_id': route.get('TransitGatewayId'),
                    'connection_type': 'transit_gateway'
                })
        
        return connectivity
    
    def _assess_route_security_impact(self, routes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess the security impact of route table configuration
        
        Args:
            routes: List of route entries
            
        Returns:
            Dictionary containing security impact assessment
        """
        impact = {
            'risk_level': 'low',
            'security_issues': [],
            'recommendations': [],
            'compliance_status': 'compliant'
        }
        
        for route in routes:
            if route.get('State') != 'active':
                continue
            
            dest_cidr = route.get('DestinationCidrBlock')
            
            # Check for overly broad routes to internet
            if dest_cidr == '0.0.0.0/0' and route.get('GatewayId', '').startswith('igw-'):
                impact['security_issues'].append('Default route to internet gateway')
                impact['risk_level'] = 'medium'
            
            # Check for routes to private networks via internet gateway
            if (dest_cidr and self._is_private_cidr(dest_cidr) and 
                route.get('GatewayId', '').startswith('igw-')):
                impact['security_issues'].append(f'Private network {dest_cidr} routed via internet gateway')
                impact['risk_level'] = 'high'
        
        # Generate recommendations
        if impact['security_issues']:
            impact['recommendations'].extend([
                'Review routes to ensure private traffic does not go through internet gateway',
                'Use NAT gateways for outbound internet access from private subnets',
                'Implement least privilege routing principles'
            ])
            impact['compliance_status'] = 'review_required'
        
        return impact
    
    def _determine_route_type(self, route: Dict[str, Any]) -> str:
        """Determine the type of route based on its target"""
        if route.get('GatewayId') == 'local':
            return 'local'
        elif route.get('GatewayId', '').startswith('igw-'):
            return 'internet_gateway'
        elif route.get('GatewayId', '').startswith('nat-'):
            return 'nat_gateway'
        elif route.get('GatewayId', '').startswith('vgw-'):
            return 'vpn_gateway'
        elif route.get('VpcPeeringConnectionId'):
            return 'vpc_peering'
        elif route.get('TransitGatewayId'):
            return 'transit_gateway'
        elif route.get('NetworkInterfaceId'):
            return 'network_interface'
        elif route.get('InstanceId'):
            return 'instance'
        else:
            return 'unknown'
    
    def _get_route_target(self, route: Dict[str, Any]) -> str:
        """Get the target of the route"""
        targets = [
            route.get('GatewayId'),
            route.get('VpcPeeringConnectionId'),
            route.get('TransitGatewayId'),
            route.get('NetworkInterfaceId'),
            route.get('InstanceId'),
            route.get('NatGatewayId'),
            route.get('EgressOnlyInternetGatewayId')
        ]
        
        for target in targets:
            if target:
                return target
        
        return 'unknown'
    
    def _get_route_target_type(self, route: Dict[str, Any]) -> str:
        """Get the type of route target"""
        if route.get('GatewayId'):
            return 'gateway'
        elif route.get('VpcPeeringConnectionId'):
            return 'vpc_peering_connection'
        elif route.get('TransitGatewayId'):
            return 'transit_gateway'
        elif route.get('NetworkInterfaceId'):
            return 'network_interface'
        elif route.get('InstanceId'):
            return 'instance'
        elif route.get('NatGatewayId'):
            return 'nat_gateway'
        elif route.get('EgressOnlyInternetGatewayId'):
            return 'egress_only_internet_gateway'
        else:
            return 'unknown'
    
    def _is_cross_region_route(self, route: Dict[str, Any]) -> bool:
        """Check if route targets a cross-region resource"""
        # This would require additional logic to determine if the target is in a different region
        # For now, return False as a placeholder
        return False
    
    def _is_cross_account_route(self, route: Dict[str, Any]) -> bool:
        """Check if route targets a cross-account resource"""
        # This would require additional logic to determine if the target is in a different account
        # For now, return False as a placeholder
        return False
    
    def _assess_route_security_risk(self, route: Dict[str, Any]) -> str:
        """Assess the security risk of a single route"""
        dest_cidr = route.get('DestinationCidrBlock')
        
        if dest_cidr == '0.0.0.0/0':
            if route.get('GatewayId', '').startswith('igw-'):
                return 'high'  # Default route to internet
            elif route.get('GatewayId', '').startswith('nat-'):
                return 'low'   # Default route to NAT (normal)
        
        if dest_cidr and self._is_private_cidr(dest_cidr):
            if route.get('GatewayId', '').startswith('igw-'):
                return 'critical'  # Private network via internet gateway
        
        return 'low'
    
    def _analyze_route_network(self, route: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network characteristics of a route"""
        analysis = {
            'is_default_route': False,
            'is_private_destination': False,
            'is_internet_bound': False,
            'network_size': 0,
            'host_count': 0
        }
        
        dest_cidr = route.get('DestinationCidrBlock')
        if dest_cidr:
            analysis['is_default_route'] = dest_cidr == '0.0.0.0/0'
            analysis['is_private_destination'] = self._is_private_cidr(dest_cidr)
            analysis['is_internet_bound'] = route.get('TargetType') == 'gateway' and route.get('Target', '').startswith('igw-')
            
            try:
                network = IPv4Network(dest_cidr, strict=False)
                analysis['network_size'] = network.prefixlen
                analysis['host_count'] = network.num_addresses
            except AddressValueError:
                pass
        
        return analysis
    
    def _is_main_route_table(self, rt: Dict[str, Any]) -> bool:
        """Check if this is the main route table for the VPC"""
        associations = rt.get('Associations', [])
        return any(assoc.get('Main', False) for assoc in associations)
    
    def _get_associated_subnets(self, associations: List[Dict[str, Any]]) -> List[str]:
        """Get list of subnet IDs associated with this route table"""
        return [assoc.get('SubnetId') for assoc in associations if assoc.get('SubnetId')]
    
    def _is_private_cidr(self, cidr: str) -> bool:
        """Check if CIDR block is in private IP range"""
        try:
            network = IPv4Network(cidr, strict=False)
            return network.is_private
        except AddressValueError:
            return False
    
    def _is_private_ipv6_cidr(self, cidr: str) -> bool:
        """Check if IPv6 CIDR block is in private range"""
        try:
            network = IPv6Network(cidr, strict=False)
            return network.is_private
        except AddressValueError:
            return False
    
    def _find_route_conflicts(self, routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find conflicting routes in the route table"""
        conflicts = []
        
        # Group routes by destination CIDR
        cidr_routes = {}
        for route in routes:
            if route.get('State') == 'active':
                dest_cidr = route.get('DestinationCidrBlock')
                if dest_cidr:
                    if dest_cidr not in cidr_routes:
                        cidr_routes[dest_cidr] = []
                    cidr_routes[dest_cidr].append(route)
        
        # Find CIDRs with multiple active routes
        for cidr, route_list in cidr_routes.items():
            if len(route_list) > 1:
                conflicts.append({
                    'type': 'multiple_routes_same_destination',
                    'destination_cidr': cidr,
                    'route_count': len(route_list),
                    'targets': [self._get_route_target(r) for r in route_list]
                })
        
        return conflicts
    
    def _find_redundant_routes(self, routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find redundant routes that may be unnecessary"""
        redundant = []
        
        # This is a simplified implementation
        # In practice, you'd need more sophisticated CIDR overlap detection
        
        active_routes = [r for r in routes if r.get('State') == 'active']
        
        for i, route1 in enumerate(active_routes):
            for j, route2 in enumerate(active_routes[i+1:], i+1):
                if (route1.get('DestinationCidrBlock') == route2.get('DestinationCidrBlock') and
                    self._get_route_target(route1) == self._get_route_target(route2)):
                    redundant.append({
                        'type': 'duplicate_route',
                        'destination_cidr': route1.get('DestinationCidrBlock'),
                        'target': self._get_route_target(route1)
                    })
        
        return redundant
    
    def _find_route_security_issues(self, routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find security issues in routes"""
        issues = []
        
        for route in routes:
            if route.get('State') != 'active':
                continue
            
            dest_cidr = route.get('DestinationCidrBlock')
            target = self._get_route_target(route)
            
            # Check for private networks routed to internet gateway
            if (dest_cidr and self._is_private_cidr(dest_cidr) and 
                target.startswith('igw-')):
                issues.append({
                    'type': 'private_network_via_internet_gateway',
                    'destination_cidr': dest_cidr,
                    'target': target,
                    'severity': 'high'
                })
            
            # Check for overly broad internet routes
            if dest_cidr == '0.0.0.0/0' and target.startswith('igw-'):
                issues.append({
                    'type': 'default_route_to_internet',
                    'destination_cidr': dest_cidr,
                    'target': target,
                    'severity': 'medium'
                })
        
        return issues
    
    def _extract_name_from_tags(self, tags: List[Dict[str, str]]) -> Optional[str]:
        """Extract Name tag value from tags list"""
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value')
        return None
