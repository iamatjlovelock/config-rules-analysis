#!/usr/bin/env python3
"""
Script to generate a Conformance Pack YAML template from an AWS Audit Manager framework.
Extracts all AWS_Config evidence sources from the framework and creates a deployable
conformance pack template.
"""

import argparse
import re
import sys
from collections import OrderedDict
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_control_details(client, control_id: str, cache: dict = None) -> dict:
    """Retrieve full control details including mapping sources."""
    if cache is not None and control_id in cache:
        return cache[control_id]

    response = client.get_control(controlId=control_id)
    control = response.get("control", {})

    if cache is not None:
        cache[control_id] = control

    return control


def get_core_control_evidence_sources(client, source: dict, cache: dict) -> list:
    """Retrieve evidence sources from a Core Control."""
    source_id = source.get("sourceId")
    keyword_value = source.get("sourceKeyword", {}).get("keywordValue")

    core_control = None

    if source_id:
        try:
            core_control = get_control_details(client, source_id, cache)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    if core_control is None and keyword_value:
        try:
            core_control = get_control_details(client, keyword_value, cache)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

    if core_control is None:
        return []

    evidence_sources = []
    for src in core_control.get("controlMappingSources", []):
        evidence_sources.append({
            "sourceType": src.get("sourceType"),
            "sourceKeyword": src.get("sourceKeyword", {})
        })

    return evidence_sources


def extract_config_rules_from_framework(framework_id: str, region: str = None) -> tuple:
    """
    Extract all AWS_Config rule identifiers from a framework.

    Returns:
        Tuple of (framework_name, set of config rule identifiers)
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("auditmanager", **client_kwargs)
    core_control_cache = {}

    print(f"Retrieving framework: {framework_id}...")
    response = client.get_assessment_framework(frameworkId=framework_id)
    framework = response["framework"]
    framework_name = framework.get("name", "Unknown Framework")

    print(f"Framework: {framework_name}")

    config_rules = set()
    total_controls = sum(len(cs.get("controls", [])) for cs in framework.get("controlSets", []))
    processed = 0

    for control_set in framework.get("controlSets", []):
        for control in control_set.get("controls", []):
            control_id = control.get("id")
            processed += 1
            print(f"  Processing control {processed}/{total_controls}: {control.get('name', control_id)[:50]}...", end="\r")

            full_control = get_control_details(client, control_id, core_control_cache)

            for source in full_control.get("controlMappingSources", []):
                source_type = source.get("sourceType")

                # Direct AWS_Config sources
                if source_type == "AWS_Config":
                    keyword_value = source.get("sourceKeyword", {}).get("keywordValue")
                    if keyword_value:
                        config_rules.add(keyword_value)

                # Core Control evidence sources
                if source_type == "Core_Control":
                    evidence_sources = get_core_control_evidence_sources(
                        client, source, core_control_cache
                    )
                    for es in evidence_sources:
                        if es.get("sourceType") == "AWS_Config":
                            keyword_value = es.get("sourceKeyword", {}).get("keywordValue")
                            if keyword_value:
                                config_rules.add(keyword_value)

    print()  # Clear the progress line
    print(f"Found {len(config_rules)} unique Config rule identifiers")

    return framework_name, config_rules


def identifier_to_resource_name(identifier: str) -> str:
    """
    Convert a Config rule identifier to a CloudFormation resource name.

    Example: ACCESS_KEYS_ROTATED -> AccessKeysRotated
    """
    parts = identifier.lower().split("_")
    return "".join(part.capitalize() for part in parts)


def identifier_to_rule_name(identifier: str) -> str:
    """
    Convert a Config rule identifier to a Config rule name.

    Example: ACCESS_KEYS_ROTATED -> access-keys-rotated
    """
    return identifier.lower().replace("_", "-")


def sanitize_framework_name(name: str) -> str:
    """Sanitize framework name for use in file names and comments."""
    # Remove or replace special characters
    sanitized = re.sub(r'[^\w\s-]', '', name)
    # Replace spaces with dashes
    sanitized = re.sub(r'\s+', '-', sanitized)
    return sanitized


def generate_conformance_pack_yaml(framework_name: str, config_rules: set) -> str:
    """
    Generate a Conformance Pack YAML template.

    Args:
        framework_name: Name of the framework
        config_rules: Set of Config rule identifiers

    Returns:
        YAML content as a string
    """
    lines = []

    # Header
    lines.append("################################################################################")
    lines.append("#")
    lines.append(f"#   Conformance Pack:")
    lines.append(f"#     {framework_name}")
    lines.append("#")
    lines.append("#   This conformance pack was generated from an AWS Audit Manager framework.")
    lines.append(f"#   Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"#   Total Config rules: {len(config_rules)}")
    lines.append("#")
    lines.append("################################################################################")
    lines.append("")
    lines.append("Resources:")

    # Sort rules alphabetically for consistent output
    sorted_rules = sorted(config_rules)

    for identifier in sorted_rules:
        resource_name = identifier_to_resource_name(identifier)
        rule_name = identifier_to_rule_name(identifier)

        lines.append(f"  {resource_name}:")
        lines.append("    Type: AWS::Config::ConfigRule")
        lines.append("    Properties:")
        lines.append(f"      ConfigRuleName: {rule_name}")
        lines.append("      Source:")
        lines.append("        Owner: AWS")
        lines.append(f"        SourceIdentifier: {identifier}")

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Conformance Pack YAML template from an AWS Audit Manager framework"
    )
    parser.add_argument(
        "--framework-id",
        required=True,
        help="The ID of the Audit Manager framework"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <framework_name>.yaml)",
        default=None
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout instead of file"
    )

    args = parser.parse_args()

    try:
        framework_name, config_rules = extract_config_rules_from_framework(
            args.framework_id, args.region
        )

        if not config_rules:
            print("Warning: No AWS_Config rules found in this framework.", file=sys.stderr)
            sys.exit(0)

        yaml_content = generate_conformance_pack_yaml(framework_name, config_rules)

        if args.stdout:
            print(yaml_content)
        else:
            output_file = args.output
            if not output_file:
                sanitized_name = sanitize_framework_name(framework_name)
                output_file = f"{sanitized_name}.yaml"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(yaml_content)

            print(f"\nConformance pack template written to: {output_file}")
            print(f"Total Config rules: {len(config_rules)}")

    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        print(f"AWS API Error ({error_code}): {error_message}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
