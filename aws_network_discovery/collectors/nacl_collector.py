"""
Network ACL Collector
Collects Network Access Control Lists and their rules
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)


class NACLCollector(BaseCollector):
    """Collector for Network Access Control Lists"""
    
    def get_resource_type(self) -> str:
        return 'network_acls'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect Network ACLs from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing Network ACL data by region
        """
        logger.info(f"Collecting Network ACLs from {len(regions)} regions")
        
        def collect_region_nacls(region: str) -> List[Dict[str, Any]]:
            return self._collect_nacls_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_nacls, "Collecting Network ACLs")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_nacls = sum(len(nacls) for nacls in results.values())
        logger.info(f"Collected {total_nacls} Network ACLs across {len(regions)} regions")
        
        return results
    
    def _collect_nacls_from_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Collect Network ACLs from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            List of Network ACL data
        """
        try:
            ec2_client = self._get_client('ec2', region)
            
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # Collect Network ACLs using pagination
            nacls = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_network_acls')
            )
            
            # Enrich each NACL with detailed rule analysis
            enriched_nacls = []
            for nacl in nacls:
                enriched_nacl = self._enrich_nacl_data(nacl, region, account_id)
                enriched_nacls.append(enriched_nacl)
            
            # Filter based on configuration
            filtered_nacls = self._filter_resources(enriched_nacls)
            
            logger.debug(f"Collected {len(filtered_nacls)} Network ACLs from region {region}")
            return filtered_nacls
            
        except Exception as e:
            logger.error(f"Failed to collect Network ACLs from region {region}: {e}")
            return []
    
    def _enrich_nacl_data(self, nacl: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich Network ACL data with detailed rule analysis
        
        Args:
            nacl: Raw Network ACL data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched Network ACL data
        """
        # Start with base enrichment
        enriched = self._enrich_resource_data(nacl, region, account_id)
        
        # Add NACL-specific enrichments
        enriched.update({
            'Name': self._extract_name_from_tags(nacl.get('Tags', [])),
            'IsDefault': nacl.get('IsDefault', False),
            'VpcId': nacl.get('VpcId'),
            'NetworkAclId': nacl.get('NetworkAclId'),
            'AssociatedSubnets': [assoc.get('SubnetId') for assoc in nacl.get('Associations', [])],
            'InboundRules': self._process_nacl_rules(nacl.get('Entries', []), 'inbound'),
            'OutboundRules': self._process_nacl_rules(nacl.get('Entries', []), 'outbound'),
            'RuleAnalysis': self._analyze_nacl_rules(nacl.get('Entries', [])),
            'SecurityImpact': self._assess_nacl_security_impact(nacl.get('Entries', []))
        })
        
        return enriched
    
    def _process_nacl_rules(self, entries: List[Dict[str, Any]], direction: str) -> List[Dict[str, Any]]:
        """
        Process and enrich NACL rules for a specific direction
        
        Args:
            entries: List of NACL entries
            direction: 'inbound' or 'outbound'
            
        Returns:
            List of processed rules
        """
        processed_rules = []
        
        for entry in entries:
            # Filter by direction (inbound = False, outbound = True for Egress field)
            is_egress = entry.get('Egress', False)
            if (direction == 'inbound' and is_egress) or (direction == 'outbound' and not is_egress):
                continue
            
            rule = {
                'RuleNumber': entry.get('RuleNumber'),
                'Protocol': self._get_protocol_name(entry.get('Protocol')),
                'ProtocolNumber': entry.get('Protocol'),
                'RuleAction': entry.get('RuleAction'),
                'CidrBlock': entry.get('CidrBlock'),
                'Ipv6CidrBlock': entry.get('Ipv6CidrBlock'),
                'Direction': direction,
                'IsEgress': is_egress
            }
            
            # Add port information if available
            port_range = entry.get('PortRange', {})
            if port_range:
                rule.update({
                    'FromPort': port_range.get('From'),
                    'ToPort': port_range.get('To'),
                    'PortRange': f"{port_range.get('From', '')}-{port_range.get('To', '')}" if port_range.get('From') != port_range.get('To') else str(port_range.get('From', ''))
                })
            
            # Add ICMP information if available
            icmp_type_code = entry.get('IcmpTypeCode', {})
            if icmp_type_code:
                rule.update({
                    'IcmpType': icmp_type_code.get('Type'),
                    'IcmpCode': icmp_type_code.get('Code')
                })
            
            # Analyze rule impact
            rule['SecurityImpact'] = self._analyze_rule_security_impact(rule)
            rule['IsRestrictive'] = rule['RuleAction'] == 'deny'
            rule['IsPermissive'] = rule['RuleAction'] == 'allow' and (
                rule.get('CidrBlock') == '0.0.0.0/0' or rule.get('Ipv6CidrBlock') == '::/0'
            )
            
            processed_rules.append(rule)
        
        # Sort rules by rule number
        processed_rules.sort(key=lambda x: x.get('RuleNumber', 32767))
        
        return processed_rules
    
    def _analyze_nacl_rules(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze NACL rules for security patterns and issues
        
        Args:
            entries: List of NACL entries
            
        Returns:
            Dictionary containing rule analysis
        """
        analysis = {
            'total_rules': len(entries),
            'inbound_rules': len([e for e in entries if not e.get('Egress', False)]),
            'outbound_rules': len([e for e in entries if e.get('Egress', False)]),
            'allow_rules': len([e for e in entries if e.get('RuleAction') == 'allow']),
            'deny_rules': len([e for e in entries if e.get('RuleAction') == 'deny']),
            'open_to_internet': False,
            'common_ports_exposed': [],
            'restrictive_rules': [],
            'rule_conflicts': []
        }
        
        # Check for rules open to internet
        for entry in entries:
            if (entry.get('CidrBlock') == '0.0.0.0/0' or entry.get('Ipv6CidrBlock') == '::/0') and entry.get('RuleAction') == 'allow':
                analysis['open_to_internet'] = True
                
                # Check for common ports
                port_range = entry.get('PortRange', {})
                if port_range:
                    from_port = port_range.get('From')
                    to_port = port_range.get('To')
                    
                    common_ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 21: 'FTP', 23: 'Telnet'}
                    for port, service in common_ports.items():
                        if from_port <= port <= to_port:
                            analysis['common_ports_exposed'].append({
                                'port': port,
                                'service': service,
                                'rule_number': entry.get('RuleNumber')
                            })
        
        # Find restrictive deny rules
        for entry in entries:
            if entry.get('RuleAction') == 'deny' and entry.get('RuleNumber', 32767) < 32767:
                analysis['restrictive_rules'].append({
                    'rule_number': entry.get('RuleNumber'),
                    'protocol': self._get_protocol_name(entry.get('Protocol')),
                    'cidr': entry.get('CidrBlock') or entry.get('Ipv6CidrBlock'),
                    'direction': 'outbound' if entry.get('Egress') else 'inbound'
                })
        
        # Check for rule conflicts (simplified)
        analysis['rule_conflicts'] = self._find_rule_conflicts(entries)
        
        return analysis
    
    def _assess_nacl_security_impact(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess the security impact of NACL configuration
        
        Args:
            entries: List of NACL entries
            
        Returns:
            Dictionary containing security impact assessment
        """
        impact = {
            'risk_level': 'low',
            'security_issues': [],
            'recommendations': [],
            'compliance_status': 'compliant'
        }
        
        # Check for high-risk configurations
        for entry in entries:
            if entry.get('RuleAction') == 'allow' and (entry.get('CidrBlock') == '0.0.0.0/0' or entry.get('Ipv6CidrBlock') == '::/0'):
                port_range = entry.get('PortRange', {})
                protocol = entry.get('Protocol')
                
                # Check for dangerous open ports
                if port_range:
                    from_port = port_range.get('From', 0)
                    to_port = port_range.get('To', 65535)
                    
                    if from_port <= 22 <= to_port:  # SSH
                        impact['security_issues'].append('SSH (port 22) open to internet')
                        impact['risk_level'] = 'high'
                    
                    if from_port <= 3389 <= to_port:  # RDP
                        impact['security_issues'].append('RDP (port 3389) open to internet')
                        impact['risk_level'] = 'high'
                
                # Check for all protocols open
                if protocol == '-1':
                    impact['security_issues'].append('All protocols open to internet')
                    impact['risk_level'] = 'critical'
        
        # Generate recommendations
        if impact['security_issues']:
            impact['recommendations'].extend([
                'Restrict NACL rules to specific IP ranges instead of 0.0.0.0/0',
                'Use security groups for more granular access control',
                'Implement least privilege principle for network access'
            ])
            impact['compliance_status'] = 'non_compliant'
        
        return impact
    
    def _get_protocol_name(self, protocol_number: str) -> str:
        """Convert protocol number to name"""
        protocol_map = {
            '-1': 'all',
            '1': 'icmp',
            '6': 'tcp',
            '17': 'udp',
            '47': 'gre',
            '50': 'esp',
            '51': 'ah'
        }
        return protocol_map.get(str(protocol_number), f'protocol-{protocol_number}')
    
    def _analyze_rule_security_impact(self, rule: Dict[str, Any]) -> str:
        """Analyze the security impact of a single rule"""
        if rule.get('RuleAction') == 'deny':
            return 'restrictive'
        
        if rule.get('CidrBlock') == '0.0.0.0/0' or rule.get('Ipv6CidrBlock') == '::/0':
            if rule.get('Protocol') == 'all':
                return 'high_risk'
            elif rule.get('FromPort') in [22, 3389]:  # SSH, RDP
                return 'medium_risk'
            else:
                return 'low_risk'
        
        return 'normal'
    
    def _find_rule_conflicts(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find potential conflicts between NACL rules"""
        conflicts = []
        
        # Sort entries by rule number
        sorted_entries = sorted(entries, key=lambda x: x.get('RuleNumber', 32767))
        
        # Look for allow rules that might be blocked by earlier deny rules
        for i, entry in enumerate(sorted_entries):
            if entry.get('RuleAction') == 'allow':
                for j in range(i):
                    earlier_entry = sorted_entries[j]
                    if (earlier_entry.get('RuleAction') == 'deny' and 
                        self._rules_overlap(entry, earlier_entry)):
                        conflicts.append({
                            'type': 'allow_blocked_by_deny',
                            'allow_rule': entry.get('RuleNumber'),
                            'deny_rule': earlier_entry.get('RuleNumber'),
                            'description': f"Allow rule {entry.get('RuleNumber')} may be blocked by deny rule {earlier_entry.get('RuleNumber')}"
                        })
        
        return conflicts
    
    def _rules_overlap(self, rule1: Dict[str, Any], rule2: Dict[str, Any]) -> bool:
        """Check if two NACL rules overlap in scope"""
        # Simplified overlap detection
        # In a real implementation, this would check CIDR blocks, ports, and protocols
        
        # Check if same direction
        if rule1.get('Egress') != rule2.get('Egress'):
            return False
        
        # Check if protocols match
        if rule1.get('Protocol') != rule2.get('Protocol') and rule1.get('Protocol') != '-1' and rule2.get('Protocol') != '-1':
            return False
        
        # Check CIDR overlap (simplified)
        cidr1 = rule1.get('CidrBlock') or rule1.get('Ipv6CidrBlock')
        cidr2 = rule2.get('CidrBlock') or rule2.get('Ipv6CidrBlock')
        
        if cidr1 == '0.0.0.0/0' or cidr2 == '0.0.0.0/0' or cidr1 == cidr2:
            return True
        
        return False
    
    def _extract_name_from_tags(self, tags: List[Dict[str, str]]) -> Optional[str]:
        """Extract Name tag value from tags list"""
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value')
        return None
