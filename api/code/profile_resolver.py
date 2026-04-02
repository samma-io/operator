import logging
from kubernetes.client.rest import ApiException


def parse_scanner_spec(spec):
    """Parse a scanner spec string into (scanner, template_or_none) tuple.

    Examples:
        "nmap/http" -> ("nmap", "http")
        "nikto"     -> ("nikto", None)
    """
    parts = spec.strip().split('/', 1)
    scanner = parts[0]
    template = parts[1] if len(parts) > 1 else None
    return (scanner, template)


def resolve_profiles(profile_names, api_client):
    """Resolve profile names to a deduplicated list of (scanner, template_or_none) tuples.

    Reads the scanner-profiles ConfigMap from the samma-io namespace.
    Unknown profiles are logged as warnings and skipped.
    """
    try:
        cm = api_client.read_namespaced_config_map("scanner-profiles", "samma-io")
        profile_data = cm.data or {}
    except ApiException as e:
        logging.warning("Could not read scanner-profiles ConfigMap: %s", e)
        return []

    result = []
    seen = set()

    for profile_name in profile_names:
        profile_name = profile_name.strip()
        if profile_name not in profile_data:
            logging.warning("Unknown scanner profile: %s", profile_name)
            continue

        specs = profile_data[profile_name].split(',')
        for spec in specs:
            parsed = parse_scanner_spec(spec)
            if parsed not in seen:
                seen.add(parsed)
                result.append(parsed)

    return result
