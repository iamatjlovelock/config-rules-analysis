#!/usr/bin/env python3
"""
Analyze Config rules for potential duplicates.

Compares rules based on name similarity and description similarity
to identify pairs that may represent the same functionality.
"""

import json
import re
import csv
from collections import defaultdict
from difflib import SequenceMatcher


def load_rules():
    """Load rules from control catalog and managed rules."""
    rules = {}

    # Load from control catalog
    try:
        with open('control-catalog/detective-controls.json', 'r') as f:
            catalog = json.load(f)
        for rule_id, data in catalog.get('controls', {}).items():
            rules[rule_id] = {
                'id': rule_id,
                'description': data.get('description', ''),
                'source': 'catalog'
            }
    except Exception as e:
        print(f"Warning: Could not load catalog: {e}")

    # Load from managed rules docs if available
    try:
        with open('control-catalog/managed-rules-docs.json', 'r') as f:
            managed = json.load(f)
        for rule_id, data in managed.get('rules', {}).items():
            if rule_id not in rules:
                rules[rule_id] = {
                    'id': rule_id,
                    'description': data.get('description', ''),
                    'source': 'managed'
                }
            elif not rules[rule_id]['description']:
                rules[rule_id]['description'] = data.get('description', '')
    except Exception:
        pass

    return rules


def normalize_name(name):
    """Normalize rule name for comparison."""
    # Remove common suffixes
    name = re.sub(r'_CHECK$|_ENABLED$|_CONFIGURED$|_ENCRYPTED$', '', name)
    return name.lower()


def get_service_prefix(name):
    """Extract service prefix from rule name."""
    parts = name.split('_')
    if len(parts) >= 2:
        # Common service prefixes
        prefixes = ['EC2', 'ECS', 'EKS', 'ELB', 'ALB', 'NLB', 'RDS', 'S3', 'IAM', 'KMS',
                   'LAMBDA', 'VPC', 'SNS', 'SQS', 'DMS', 'EMR', 'EFS', 'FSX', 'REDSHIFT',
                   'DYNAMODB', 'ELASTICSEARCH', 'OPENSEARCH', 'CLOUDFRONT', 'CLOUDWATCH',
                   'CLOUDTRAIL', 'ACM', 'API', 'APIGATEWAY', 'AUTOSCALING', 'BACKUP',
                   'CODEBUILD', 'CODEPIPELINE', 'COGNITO', 'DAX', 'DOCDB', 'NEPTUNE',
                   'SECRETSMANAGER', 'SSM', 'WAF', 'WAFV2', 'GUARDDUTY', 'SECURITYHUB',
                   'MACIE', 'INSPECTOR', 'KINESIS', 'GLUE', 'ATHENA', 'SAGEMAKER',
                   'STEPFUNCTIONS', 'MQ', 'MSK', 'TRANSFER', 'WORKSPACES', 'APPSTREAM',
                   'ROUTE53', 'ECR', 'EBS', 'ELASTIC', 'NETFW', 'NETWORK']
        if parts[0].upper() in prefixes:
            return parts[0].upper()
        if len(parts) >= 2 and f"{parts[0]}_{parts[1]}".upper() in ['API_GW', 'AUTO_SCALING']:
            return f"{parts[0]}_{parts[1]}".upper()
    return parts[0].upper() if parts else ''


def similarity_score(str1, str2):
    """Calculate similarity between two strings."""
    if not str1 or not str2:
        return 0
    return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()


def find_potential_duplicates(rules):
    """Find potential duplicate rules."""
    duplicates = []
    rule_list = list(rules.values())
    seen_pairs = set()

    # Group rules by service prefix
    by_prefix = defaultdict(list)
    for rule in rule_list:
        prefix = get_service_prefix(rule['id'])
        by_prefix[prefix].append(rule)

    # Compare rules within same service prefix
    for prefix, prefix_rules in by_prefix.items():
        for i, rule1 in enumerate(prefix_rules):
            for rule2 in prefix_rules[i+1:]:
                pair_key = tuple(sorted([rule1['id'], rule2['id']]))
                if pair_key in seen_pairs:
                    continue

                score = calculate_duplicate_score(rule1, rule2)
                if score >= 4:  # Minimum threshold
                    seen_pairs.add(pair_key)
                    duplicates.append({
                        'rule1': rule1['id'],
                        'desc1': rule1.get('description', ''),
                        'rule2': rule2['id'],
                        'desc2': rule2.get('description', ''),
                        'score': score,
                        'reason': get_duplicate_reason(rule1, rule2)
                    })

    # Also check for cross-service duplicates with very similar names
    all_names = [(r['id'], normalize_name(r['id'])) for r in rule_list]
    for i, (id1, norm1) in enumerate(all_names):
        for id2, norm2 in all_names[i+1:]:
            pair_key = tuple(sorted([id1, id2]))
            if pair_key in seen_pairs:
                continue

            if get_service_prefix(id1) != get_service_prefix(id2):
                name_sim = similarity_score(norm1, norm2)
                if name_sim > 0.7:
                    rule1 = rules[id1]
                    rule2 = rules[id2]
                    score = calculate_duplicate_score(rule1, rule2)
                    if score >= 5:
                        seen_pairs.add(pair_key)
                        duplicates.append({
                            'rule1': id1,
                            'desc1': rule1.get('description', ''),
                            'rule2': id2,
                            'desc2': rule2.get('description', ''),
                            'score': score,
                            'reason': get_duplicate_reason(rule1, rule2)
                        })

    return sorted(duplicates, key=lambda x: -x['score'])


def calculate_duplicate_score(rule1, rule2):
    """Calculate duplicate probability score (1-10)."""
    score = 0

    id1, id2 = rule1['id'], rule2['id']
    desc1, desc2 = rule1.get('description', ''), rule2.get('description', '')

    # Name similarity
    norm1 = normalize_name(id1)
    norm2 = normalize_name(id2)
    name_sim = similarity_score(norm1, norm2)

    if name_sim > 0.9:
        score += 4
    elif name_sim > 0.8:
        score += 3
    elif name_sim > 0.7:
        score += 2
    elif name_sim > 0.6:
        score += 1

    # Description similarity
    if desc1 and desc2:
        desc_sim = similarity_score(desc1[:300], desc2[:300])
        if desc_sim > 0.9:
            score += 4
        elif desc_sim > 0.8:
            score += 3
        elif desc_sim > 0.7:
            score += 2
        elif desc_sim > 0.5:
            score += 1

    # Check for common patterns suggesting duplicates
    patterns = [
        (r'_CHECK$', r'_ENABLED$'),  # check vs enabled
        (r'_ENCRYPTED$', r'_ENCRYPTION_ENABLED$'),
        (r'_TAGGED$', r'_TAGGING$'),
    ]

    for p1, p2 in patterns:
        if (re.search(p1, id1) and re.search(p2, id2)) or \
           (re.search(p2, id1) and re.search(p1, id2)):
            score += 1
            break

    # Same core functionality check
    core1 = re.sub(r'_(CHECK|ENABLED|CONFIGURED|ENCRYPTED|TAGGED)$', '', id1)
    core2 = re.sub(r'_(CHECK|ENABLED|CONFIGURED|ENCRYPTED|TAGGED)$', '', id2)
    if core1 == core2:
        score += 2

    return min(score, 10)


def get_duplicate_reason(rule1, rule2):
    """Get reason for potential duplication."""
    reasons = []

    id1, id2 = rule1['id'], rule2['id']
    desc1, desc2 = rule1.get('description', ''), rule2.get('description', '')

    norm1 = normalize_name(id1)
    norm2 = normalize_name(id2)
    name_sim = similarity_score(norm1, norm2)

    if name_sim > 0.8:
        reasons.append(f"Similar names ({name_sim:.0%})")

    if desc1 and desc2:
        desc_sim = similarity_score(desc1[:300], desc2[:300])
        if desc_sim > 0.7:
            reasons.append(f"Similar descriptions ({desc_sim:.0%})")

    # Check suffix patterns
    if (re.search(r'_CHECK$', id1) and re.search(r'_ENABLED$', id2)) or \
       (re.search(r'_ENABLED$', id1) and re.search(r'_CHECK$', id2)):
        reasons.append("CHECK vs ENABLED suffix")

    core1 = re.sub(r'_(CHECK|ENABLED|CONFIGURED|ENCRYPTED|TAGGED)$', '', id1)
    core2 = re.sub(r'_(CHECK|ENABLED|CONFIGURED|ENCRYPTED|TAGGED)$', '', id2)
    if core1 == core2:
        reasons.append("Same core name")

    return "; ".join(reasons) if reasons else "Similar functionality"


def main():
    print("Loading rules...")
    rules = load_rules()
    print(f"  Loaded {len(rules)} rules")

    print("\nAnalyzing for potential duplicates...")
    duplicates = find_potential_duplicates(rules)
    print(f"  Found {len(duplicates)} potential duplicate pairs")

    # Write CSV
    output_file = 'potential_duplicate_rules.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Rule 1', 'Description 1', 'Rule 2', 'Description 2', 'Score (1-10)', 'Reason'])
        for dup in duplicates:
            writer.writerow([dup['rule1'], dup['desc1'], dup['rule2'], dup['desc2'], dup['score'], dup['reason']])

    print(f"\nResults written to {output_file}")

    print(f"\nTop 30 potential duplicates (score >= 6):")
    print("-" * 100)
    count = 0
    for dup in duplicates:
        if dup['score'] >= 6:
            count += 1
            print(f"[{dup['score']:2d}] {dup['rule1']}")
            print(f"     {dup['rule2']}")
            print(f"     Reason: {dup['reason']}")
            print()
            if count >= 30:
                break

    # Summary by score
    print("\nSummary by score:")
    score_counts = defaultdict(int)
    for dup in duplicates:
        score_counts[dup['score']] += 1
    for score in sorted(score_counts.keys(), reverse=True):
        print(f"  Score {score}: {score_counts[score]} pairs")


if __name__ == "__main__":
    main()
