"""
Network Firewall Collector
Collects AWS Network Firewall configurations and rules
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)


class NetworkFirewallCollector(BaseCollector):
    """Collector for AWS Network Firewall"""
    
    def get_resource_type(self) -> str:
        return 'network_firewalls'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect Network Firewalls from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing Network Firewall data by region
        """
        logger.info(f"Collecting Network Firewalls from {len(regions)} regions")
        
        def collect_region_firewalls(region: str) -> List[Dict[str, Any]]:
            return self._collect_firewalls_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_firewalls, "Collecting Network Firewalls")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_firewalls = sum(len(fw) for fw in results.values())
        logger.info(f"Collected {total_firewalls} Network Firewalls across {len(regions)} regions")
        
        return results
    
    def _collect_firewalls_from_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Collect Network Firewalls from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            List of Network Firewall data
        """
        try:
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # Get Network Firewall client
            nfw_client = self._get_client('network-firewall', region)
            
            # List firewalls
            firewalls_response = nfw_client.list_firewalls()
            firewalls = firewalls_response.get('Firewalls', [])
            
            enriched_firewalls = []
            for firewall in firewalls:
                # Get detailed firewall information
                firewall_detail = self._get_firewall_details(nfw_client, firewall.get('FirewallArn'))
                if firewall_detail:
                    enriched_firewall = self._enrich_firewall_data(firewall_detail, region, account_id)
                    enriched_firewalls.append(enriched_firewall)
            
            logger.debug(f"Collected {len(enriched_firewalls)} Network Firewalls from region {region}")
            return enriched_firewalls
            
        except Exception as e:
            logger.error(f"Failed to collect Network Firewalls from region {region}: {e}")
            return []
    
    def _get_firewall_details(self, nfw_client, firewall_arn: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific firewall
        
        Args:
            nfw_client: Network Firewall client
            firewall_arn: Firewall ARN
            
        Returns:
            Detailed firewall information
        """
        try:
            # Get firewall details
            firewall_response = nfw_client.describe_firewall(FirewallArn=firewall_arn)
            firewall = firewall_response.get('Firewall', {})
            firewall_status = firewall_response.get('FirewallStatus', {})
            
            # Get firewall policy details
            policy_arn = firewall.get('FirewallPolicyArn')
            policy_details = None
            if policy_arn:
                policy_details = self._get_firewall_policy_details(nfw_client, policy_arn)
            
            # Combine firewall and policy information
            firewall['FirewallStatus'] = firewall_status
            firewall['PolicyDetails'] = policy_details
            
            return firewall
            
        except Exception as e:
            logger.error(f"Failed to get firewall details for {firewall_arn}: {e}")
            return None
    
    def _get_firewall_policy_details(self, nfw_client, policy_arn: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a firewall policy
        
        Args:
            nfw_client: Network Firewall client
            policy_arn: Policy ARN
            
        Returns:
            Detailed policy information
        """
        try:
            policy_response = nfw_client.describe_firewall_policy(FirewallPolicyArn=policy_arn)
            policy = policy_response.get('FirewallPolicy', {})
            
            # Get rule group details
            rule_groups = []
            
            # Stateless rule groups
            for rule_group_ref in policy.get('StatelessRuleGroupReferences', []):
                rule_group_arn = rule_group_ref.get('ResourceArn')
                rule_group_details = self._get_rule_group_details(nfw_client, rule_group_arn)
                if rule_group_details:
                    rule_group_details['Type'] = 'stateless'
                    rule_group_details['Priority'] = rule_group_ref.get('Priority')
                    rule_groups.append(rule_group_details)
            
            # Stateful rule groups
            for rule_group_ref in policy.get('StatefulRuleGroupReferences', []):
                rule_group_arn = rule_group_ref.get('ResourceArn')
                rule_group_details = self._get_rule_group_details(nfw_client, rule_group_arn)
                if rule_group_details:
                    rule_group_details['Type'] = 'stateful'
                    rule_group_details['Priority'] = rule_group_ref.get('Priority', 0)
                    rule_groups.append(rule_group_details)
            
            policy['RuleGroupDetails'] = rule_groups
            return policy
            
        except Exception as e:
            logger.error(f"Failed to get policy details for {policy_arn}: {e}")
            return None
    
    def _get_rule_group_details(self, nfw_client, rule_group_arn: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a rule group
        
        Args:
            nfw_client: Network Firewall client
            rule_group_arn: Rule group ARN
            
        Returns:
            Detailed rule group information
        """
        try:
            rule_group_response = nfw_client.describe_rule_group(RuleGroupArn=rule_group_arn)
            rule_group = rule_group_response.get('RuleGroup', {})
            rule_group_metadata = rule_group_response.get('RuleGroupResponse', {})
            
            # Combine rule group and metadata
            rule_group.update(rule_group_metadata)
            
            return rule_group
            
        except Exception as e:
            logger.error(f"Failed to get rule group details for {rule_group_arn}: {e}")
            return None
    
    def _enrich_firewall_data(self, firewall: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich firewall data with detailed analysis
        
        Args:
            firewall: Raw firewall data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched firewall data
        """
        # Start with base enrichment
        enriched = self._enrich_resource_data(firewall, region, account_id)
        
        # Add firewall-specific enrichments
        enriched.update({
            'Name': firewall.get('FirewallName'),
            'FirewallId': firewall.get('FirewallId'),
            'FirewallArn': firewall.get('FirewallArn'),
            'VpcId': firewall.get('VpcId'),
            'SubnetMappings': firewall.get('SubnetMappings', []),
            'FirewallPolicyArn': firewall.get('FirewallPolicyArn'),
            'Status': firewall.get('FirewallStatus', {}).get('Status'),
            'ConfigurationSyncState': firewall.get('FirewallStatus', {}).get('ConfigurationSyncState'),
            'RuleAnalysis': self._analyze_firewall_rules(firewall.get('PolicyDetails', {})),
            'SecurityPosture': self._assess_firewall_security_posture(firewall),
            'ComplianceStatus': self._assess_firewall_compliance(firewall),
            'PerformanceMetrics': self._analyze_firewall_performance(firewall)
        })
        
        return enriched
    
    def _analyze_firewall_rules(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze firewall rules for patterns and effectiveness
        
        Args:
            policy: Firewall policy details
            
        Returns:
            Dictionary containing rule analysis
        """
        analysis = {
            'total_rule_groups': 0,
            'stateless_rule_groups': 0,
            'stateful_rule_groups': 0,
            'total_rules': 0,
            'allow_rules': 0,
            'deny_rules': 0,
            'drop_rules': 0,
            'pass_rules': 0,
            'rule_coverage': {},
            'security_gaps': [],
            'rule_conflicts': []
        }
        
        if not policy:
            return analysis
        
        rule_groups = policy.get('RuleGroupDetails', [])
        analysis['total_rule_groups'] = len(rule_groups)
        
        for rule_group in rule_groups:
            rule_group_type = rule_group.get('Type', 'unknown')
            
            if rule_group_type == 'stateless':
                analysis['stateless_rule_groups'] += 1
                self._analyze_stateless_rules(rule_group, analysis)
            elif rule_group_type == 'stateful':
                analysis['stateful_rule_groups'] += 1
                self._analyze_stateful_rules(rule_group, analysis)
        
        # Analyze rule coverage
        analysis['rule_coverage'] = self._analyze_rule_coverage(rule_groups)
        
        # Find security gaps
        analysis['security_gaps'] = self._find_security_gaps(rule_groups)
        
        # Find rule conflicts
        analysis['rule_conflicts'] = self._find_rule_conflicts(rule_groups)
        
        return analysis
    
    def _analyze_stateless_rules(self, rule_group: Dict[str, Any], analysis: Dict[str, Any]) -> None:
        """Analyze stateless rules in a rule group"""
        rules_source = rule_group.get('RulesSource', {})
        stateless_rules = rules_source.get('StatelessRulesAndCustomActions', {})
        
        for rule in stateless_rules.get('StatelessRules', []):
            analysis['total_rules'] += 1
            
            rule_definition = rule.get('RuleDefinition', {})
            actions = rule_definition.get('Actions', [])
            
            for action in actions:
                if action == 'aws:pass':
                    analysis['pass_rules'] += 1
                elif action == 'aws:drop':
                    analysis['drop_rules'] += 1
                elif action == 'aws:forward_to_sfe':
                    analysis['allow_rules'] += 1
    
    def _analyze_stateful_rules(self, rule_group: Dict[str, Any], analysis: Dict[str, Any]) -> None:
        """Analyze stateful rules in a rule group"""
        rules_source = rule_group.get('RulesSource', {})
        
        # Suricata rules
        if 'RulesString' in rules_source:
            suricata_rules = rules_source.get('RulesString', '')
            rule_lines = [line.strip() for line in suricata_rules.split('\n') if line.strip()]
            
            for rule_line in rule_lines:
                analysis['total_rules'] += 1
                
                if rule_line.startswith('pass'):
                    analysis['pass_rules'] += 1
                elif rule_line.startswith('drop'):
                    analysis['drop_rules'] += 1
                elif rule_line.startswith('reject'):
                    analysis['deny_rules'] += 1
                elif rule_line.startswith('alert'):
                    analysis['allow_rules'] += 1
        
        # Domain list rules
        if 'RulesSourceList' in rules_source:
            domain_rules = rules_source.get('RulesSourceList', {})
            targets = domain_rules.get('Targets', [])
            analysis['total_rules'] += len(targets)
            
            # Assume domain rules are typically DENY rules
            analysis['deny_rules'] += len(targets)
        
        # Stateful rules
        if 'StatefulRules' in rules_source:
            stateful_rules = rules_source.get('StatefulRules', [])
            for rule in stateful_rules:
                analysis['total_rules'] += 1
                action = rule.get('Action', '').lower()
                
                if action == 'pass':
                    analysis['pass_rules'] += 1
                elif action == 'drop':
                    analysis['drop_rules'] += 1
                elif action == 'alert':
                    analysis['allow_rules'] += 1
    
    def _analyze_rule_coverage(self, rule_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze what traffic is covered by firewall rules"""
        coverage = {
            'protocols_covered': set(),
            'ports_covered': set(),
            'source_ips_covered': set(),
            'destination_ips_covered': set(),
            'coverage_percentage': 0.0
        }
        
        # This is a simplified analysis
        # In practice, you'd need to parse all rules and determine coverage
        
        for rule_group in rule_groups:
            rules_source = rule_group.get('RulesSource', {})
            
            # Analyze stateless rules
            if 'StatelessRulesAndCustomActions' in rules_source:
                stateless_rules = rules_source['StatelessRulesAndCustomActions']
                for rule in stateless_rules.get('StatelessRules', []):
                    rule_def = rule.get('RuleDefinition', {})
                    match_attributes = rule_def.get('MatchAttributes', {})
                    
                    # Extract protocols
                    protocols = match_attributes.get('Protocols', [])
                    coverage['protocols_covered'].update(protocols)
                    
                    # Extract ports
                    dest_ports = match_attributes.get('DestinationPorts', [])
                    for port_range in dest_ports:
                        from_port = port_range.get('FromPort')
                        to_port = port_range.get('ToPort')
                        if from_port == to_port:
                            coverage['ports_covered'].add(from_port)
                        else:
                            coverage['ports_covered'].update(range(from_port, to_port + 1))
        
        # Convert sets to lists for JSON serialization
        coverage['protocols_covered'] = list(coverage['protocols_covered'])
        coverage['ports_covered'] = list(coverage['ports_covered'])[:100]  # Limit for readability
        coverage['source_ips_covered'] = list(coverage['source_ips_covered'])
        coverage['destination_ips_covered'] = list(coverage['destination_ips_covered'])
        
        return coverage
    
    def _find_security_gaps(self, rule_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find potential security gaps in firewall configuration"""
        gaps = []
        
        # Check for common security gaps
        has_dns_filtering = False
        has_http_inspection = False
        has_tls_inspection = False
        
        for rule_group in rule_groups:
            rules_source = rule_group.get('RulesSource', {})
            
            # Check for DNS filtering
            if 'RulesSourceList' in rules_source:
                has_dns_filtering = True
            
            # Check for HTTP/HTTPS inspection (simplified)
            if 'RulesString' in rules_source:
                rules_string = rules_source.get('RulesString', '')
                if 'http' in rules_string.lower():
                    has_http_inspection = True
                if 'tls' in rules_string.lower() or 'ssl' in rules_string.lower():
                    has_tls_inspection = True
        
        if not has_dns_filtering:
            gaps.append({
                'type': 'missing_dns_filtering',
                'severity': 'medium',
                'description': 'No DNS filtering rules detected'
            })
        
        if not has_http_inspection:
            gaps.append({
                'type': 'missing_http_inspection',
                'severity': 'medium',
                'description': 'No HTTP inspection rules detected'
            })
        
        if not has_tls_inspection:
            gaps.append({
                'type': 'missing_tls_inspection',
                'severity': 'low',
                'description': 'No TLS inspection rules detected'
            })
        
        return gaps
    
    def _find_rule_conflicts(self, rule_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find potential conflicts between firewall rules"""
        conflicts = []
        
        # This is a simplified implementation
        # In practice, you'd need sophisticated rule conflict detection
        
        priorities = []
        for rule_group in rule_groups:
            priority = rule_group.get('Priority', 0)
            rule_type = rule_group.get('Type', 'unknown')
            priorities.append((priority, rule_type, rule_group.get('RuleGroupName', 'unknown')))
        
        # Check for duplicate priorities
        priority_counts = {}
        for priority, rule_type, name in priorities:
            key = f"{rule_type}_{priority}"
            if key not in priority_counts:
                priority_counts[key] = []
            priority_counts[key].append(name)
        
        for key, names in priority_counts.items():
            if len(names) > 1:
                conflicts.append({
                    'type': 'duplicate_priority',
                    'priority': key,
                    'rule_groups': names,
                    'description': f"Multiple rule groups with same priority: {key}"
                })
        
        return conflicts
    
    def _assess_firewall_security_posture(self, firewall: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the overall security posture of the firewall"""
        posture = {
            'overall_score': 0.0,
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        policy_details = firewall.get('PolicyDetails', {})
        rule_analysis = self._analyze_firewall_rules(policy_details)
        
        score = 50.0  # Base score
        
        # Positive factors
        if rule_analysis.get('total_rule_groups', 0) > 0:
            score += 20
            posture['strengths'].append('Has configured rule groups')
        
        if rule_analysis.get('stateful_rule_groups', 0) > 0:
            score += 15
            posture['strengths'].append('Uses stateful inspection')
        
        if rule_analysis.get('deny_rules', 0) > 0:
            score += 10
            posture['strengths'].append('Has explicit deny rules')
        
        # Negative factors
        security_gaps = rule_analysis.get('security_gaps', [])
        if security_gaps:
            score -= len(security_gaps) * 5
            posture['weaknesses'].extend([gap['description'] for gap in security_gaps])
        
        rule_conflicts = rule_analysis.get('rule_conflicts', [])
        if rule_conflicts:
            score -= len(rule_conflicts) * 10
            posture['weaknesses'].extend([conflict['description'] for conflict in rule_conflicts])
        
        posture['overall_score'] = max(0.0, min(100.0, score))
        
        # Generate recommendations
        if posture['overall_score'] < 70:
            posture['recommendations'].extend([
                'Review and enhance firewall rule coverage',
                'Implement comprehensive threat detection rules',
                'Regular review and update of firewall policies'
            ])
        
        return posture
    
    def _assess_firewall_compliance(self, firewall: Dict[str, Any]) -> Dict[str, Any]:
        """Assess firewall compliance with security standards"""
        compliance = {
            'overall_status': 'compliant',
            'standards_checked': ['basic_security', 'network_segmentation'],
            'violations': [],
            'recommendations': []
        }
        
        policy_details = firewall.get('PolicyDetails', {})
        rule_analysis = self._analyze_firewall_rules(policy_details)
        
        # Check basic security compliance
        if rule_analysis.get('total_rules', 0) == 0:
            compliance['violations'].append({
                'standard': 'basic_security',
                'violation': 'No firewall rules configured',
                'severity': 'high'
            })
            compliance['overall_status'] = 'non_compliant'
        
        # Check for proper network segmentation
        if rule_analysis.get('deny_rules', 0) == 0:
            compliance['violations'].append({
                'standard': 'network_segmentation',
                'violation': 'No explicit deny rules for network segmentation',
                'severity': 'medium'
            })
        
        return compliance
    
    def _analyze_firewall_performance(self, firewall: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze firewall performance characteristics"""
        performance = {
            'rule_complexity': 'low',
            'processing_overhead': 'low',
            'scalability_concerns': [],
            'optimization_opportunities': []
        }
        
        policy_details = firewall.get('PolicyDetails', {})
        rule_analysis = self._analyze_firewall_rules(policy_details)
        
        total_rules = rule_analysis.get('total_rules', 0)
        
        # Assess rule complexity
        if total_rules > 1000:
            performance['rule_complexity'] = 'high'
            performance['scalability_concerns'].append('High number of rules may impact performance')
        elif total_rules > 500:
            performance['rule_complexity'] = 'medium'
        
        # Assess processing overhead
        stateful_rules = rule_analysis.get('stateful_rule_groups', 0)
        if stateful_rules > 10:
            performance['processing_overhead'] = 'high'
            performance['optimization_opportunities'].append('Consider consolidating stateful rule groups')
        elif stateful_rules > 5:
            performance['processing_overhead'] = 'medium'
        
        return performance
