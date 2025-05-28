import urllib.parse
from typing import Any, List, Dict, Optional
import httpx
import base64
import json
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("CatC-MCP")

# Constants
AUTH_TIMEOUT = 60.0
REQUEST_TIMEOUT = 30.0


class CatalystCenterClient:
    """Client for interacting with Cisco Catalyst Center API."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None

    async def authenticate(self) -> bool:
        """Authenticate and get token from Catalyst Center."""
        auth_url = f"{self.base_url}/dna/system/api/v1/auth/token"
        auth_string = f"{self.username}:{self.password}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {encoded_auth}"
        }

        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await client.post(auth_url, headers=headers, timeout=AUTH_TIMEOUT)
                response.raise_for_status()
                self.token = response.json().get("Token")
                return bool(self.token)
            except Exception as e:
                print(f"Authentication error: {str(e)}")
                return False

    async def request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make an API request to Catalyst Center with authentication."""
        if not self.token and not await self.authenticate():
            return None

        url = f"{self.base_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "X-Auth-Token": self.token
        }

        if "headers" in kwargs:
            kwargs["headers"].update(headers)
        else:
            kwargs["headers"] = headers

        kwargs["timeout"] = kwargs.get("timeout", REQUEST_TIMEOUT)

        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await getattr(client, method.lower())(url, **kwargs)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    # Token expired, try to re-authenticate
                    if await self.authenticate():
                        # Update headers with new token and retry
                        if "headers" in kwargs:
                            kwargs["headers"]["X-Auth-Token"] = self.token
                        return await self.request(method, endpoint, **kwargs)
                print(f"API error: {str(e)}")
                return None
            except Exception as e:
                print(f"Request error: {str(e)}")
                return None


# Client instance
client = None


@mcp.tool()
async def connect(base_url: str, username: str, password: str) -> str:
    """Connect to Cisco Catalyst Center.

    Args:
        base_url: Base URL of the Catalyst Center (e.g., https://10.10.10.10)
        username: Username for authentication
        password: Password for authentication
    """
    global client
    client = CatalystCenterClient(base_url, username, password)
    if await client.authenticate():
        return "Successfully connected to Cisco Catalyst Center"
    return "Failed to connect to Cisco Catalyst Center"


@mcp.tool()
async def get_network_devices(limit: int = 10, offset: int = 1) -> str:
    """Get list of network devices.

    Args:
        limit: Maximum number of devices to return (default: 10)
        offset: Pagination offset (default: 1)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/network-device?limit={limit}&offset={offset}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch network devices or no devices found."

    devices = data["response"]
    if not devices:
        return "No network devices found."

    formatted_devices = []
    for device in devices:
        formatted = f"""
Device: {device.get('hostname', 'Unknown')}
IP: {device.get('managementIpAddress', 'Unknown')}
Platform: {device.get('platformId', 'Unknown')}
Serial: {device.get('serialNumber', 'Unknown')}
Status: {device.get('reachabilityStatus', 'Unknown')}
Uptime: {device.get('upTime', 'Unknown')}
Software: {device.get('softwareVersion', 'Unknown')}
Device ID: {device.get('id', 'N/A')}
"""
        formatted_devices.append(formatted)

    return "\n---\n".join(formatted_devices)


@mcp.tool()
async def get_device_details(device_id: str) -> str:
    """Get detailed information about a specific device.

    Args:
        device_id: Device ID or UUID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/network-device/{device_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch details for device {device_id}."

    device = data["response"]

    return f"""
Device Details:
Hostname: {device.get('hostname', 'Unknown')}
Management IP: {device.get('managementIpAddress', 'Unknown')}
Platform: {device.get('platformId', 'Unknown')}
Serial Number: {device.get('serialNumber', 'Unknown')}
Status: {device.get('reachabilityStatus', 'Unknown')}
Uptime: {device.get('upTime', 'Unknown')}
Software Version: {device.get('softwareVersion', 'Unknown')}
Role: {device.get('role', 'Unknown')}
MAC Address: {device.get('macAddress', 'Unknown')}
Location: {device.get('location', 'Unknown')}
Last Updated: {device.get('lastUpdated', 'Unknown')}
Associated WLC: {device.get('associatedWlcIp', 'N/A')}
"""


@mcp.tool()
async def get_sites() -> str:
    """Get list of sites in the network."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/site"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch sites or no sites found."

    sites = data["response"]
    if not sites:
        return "No sites found."

    formatted_sites = []
    for site in sites:
        formatted = f"""
Site Name: {site.get('name', 'Unknown')}
Site ID: {site.get('id', 'Unknown')}
Type: {site.get('siteType', 'Unknown')}
Parent: {site.get('parentName', 'None')}
"""
        formatted_sites.append(formatted)

    return "\n---\n".join(formatted_sites)


@mcp.tool()
async def get_site_health(site_id: str) -> str:
    """Get health information for a specific site.

    Args:
        site_id: Site ID or UUID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/site-health"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch health data for site {site_id}."

    sites_health = data["response"]
    if not sites_health:
        return f"No health data found for site {site_id}."
    formatted_sites = []

    for site in sites_health:
        formatted = f"""
Site Name: {site.get('siteName', 'Unknown')}
Overall Health: {site.get('networkHealthAverage', 'Unknown')}
Total Devices: {site.get('numberOfNetworkDevice', 'Unknown')}
Healthy Devices Percentage: {site.get('healthyNetworkDevicePercentage', 'Unknown')}
Healthy Clients Percentage: {site.get('healthyClientsPercentage', 'Unknown')}
Number of Clients (Wired): {site.get('numberOfWiredClients', 'Unknown')}
Number of Clients (Wireless): {site.get('numberOfWirelessClients', 'Unknown')}
"""
        formatted_sites.append(formatted)

    return "\n---\n".join(formatted_sites)


@mcp.tool()
async def get_network_issues(start_time: str = None, end_time: str = None) -> str:
    """Get network issues.

    Args:
        start_time: Start time in ISO format (optional)
        end_time: End time in ISO format (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/issues"
    params = {}
    if start_time:
        params["startTime"] = start_time
    if end_time:
        params["endTime"] = end_time

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch network issues or no issues found."

    issues = data["response"]
    if not issues:
        return "No network issues found for the specified time period."

    formatted_issues = []
    for issue in issues:
        formatted = f"""
Issue: {issue.get('name', 'Unknown')}
Description: {issue.get('description', 'No description')}
Priority: {issue.get('priority', 'Unknown')}
Category: {issue.get('category', 'Unknown')}
Affected Device Count: {issue.get('deviceCount', 'Unknown')}
First Occurrence: {issue.get('firstOccurrence', 'Unknown')}
Last Occurrence: {issue.get('lastOccurrence', 'Unknown')}
"""
        formatted_issues.append(formatted)

    return "\n---\n".join(formatted_issues)


@mcp.tool()
async def get_client_devices() -> str:
    """Get client devices connected to the network.

    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/data/api/v1/clients"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch client devices or no clients found."

    clients = data["response"]
    if not clients:
        return "No client devices found."

    formatted_clients = []
    for client_device in clients:
        health = client_device.get("health", "Unknown")
        connectedNetworkDevice = client_device.get("connectedNetworkDevice", "Unknown")
        formatted = f"""
Client: {client_device.get('hostName', 'Unknown')}
MAC Address: {client_device.get('macAddress', 'Unknown')}
IPv4 Address: {client_device.get('ipv4Address', 'Unknown')}
IPv6 Address: {client_device.get('ipv6Address', 'Unknown')}
Connection Type: {client_device.get('type', 'Unknown')}
Health Score: {health.get('overallScore', 'Unknown')}
Onboarding Health Score: {health.get('onboardingScore', 'Unknown')}
Client Type: {client_device.get('deviceType', 'Unknown')}
Connected to device : {connectedNetworkDevice.get('connectedNetworkDeviceName', 'Unknown')}
Device type : {connectedNetworkDevice.get('connectedNetworkDeviceType', 'Unknown')}
Device IP : {connectedNetworkDevice.get('connectedNetworkDeviceManagementIp', 'Unknown')}
"""
        formatted_clients.append(formatted)

    return "\n---\n".join(formatted_clients)


# New API paths added below

@mcp.tool()
async def get_device_interfaces(device_id: str) -> str:
    """Get interfaces for a specific device.

    Args:
        device_id: Device ID or UUID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/interface/network-device/{device_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch interfaces for device {device_id}."

    interfaces = data["response"]
    if not interfaces:
        return f"No interfaces found for device {device_id}."

    formatted_interfaces = []
    for interface in interfaces:
        formatted = f"""
Interface: {interface.get('portName', 'Unknown')}
Type: {interface.get('interfaceType', 'Unknown')}
Status: {interface.get('status', 'Unknown')}
Admin Status: {interface.get('adminStatus', 'Unknown')}
MAC Address: {interface.get('macAddress', 'Unknown')}
IP Address: {interface.get('ipv4Address', 'Unknown')}
VLAN: {interface.get('vlanId', 'Unknown')}
Description: {interface.get('description', 'None')}
"""
        formatted_interfaces.append(formatted)

    return "\n---\n".join(formatted_interfaces)


@mcp.tool()
async def get_device_config(device_id: str) -> str:
    """Get configuration for a specific device.

    Args:
        device_id: Device ID or UUID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/network-device/{device_id}/config"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch configuration for device {device_id}."

    config = data.get("response", "No configuration available")
    return f"Configuration for device {device_id}:\n\n{config}"


@mcp.tool()
async def get_physical_topology() -> str:
    """Get the physical topology of the network."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/topology/physical-topology"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch physical topology or no topology found."

    topology = data["response"]

    # Extract nodes and links information
    nodes = topology.get("nodes", [])
    links = topology.get("links", [])

    return f"""
Physical Topology:
Number of Nodes: {len(nodes)}
Number of Links: {len(links)}

Node Types: {", ".join(set(node.get("nodeType", "Unknown") for node in nodes))}
"""


@mcp.tool()
async def run_commands(device_id: str, commands: List[str]) -> str:
    """Run CLI commands on a device.

    Args:
        device_id: Device ID or UUID
        commands: List of commands to run
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/network-device-poller/cli/read-request"
    payload = {
        "deviceUuids": [device_id],
        "commands": commands
    }

    data = await client.request("POST", endpoint, json=payload)

    if not data or "response" not in data:
        return f"Unable to run commands on device {device_id}."

    task_id = data.get("response", {}).get("taskId", "Unknown")
    return f"Commands submitted successfully. Task ID: {task_id}"


@mcp.tool()
async def get_task_result(task_id: str) -> str:
    """Get the result of a task.

    Args:
        task_id: Task ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/task/{task_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch result for task {task_id}."

    task = data["response"]

    return f"""
Task: {task_id}
Status: {task.get('isError', False)}
Progress: {task.get('progress', 'Unknown')}
Detail: {task.get('detail', 'No details')}
"""


@mcp.tool()
async def get_network_health() -> str:
    """Get overall network health."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/network-health"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch network health."

    health = data["response"][0] if data["response"] else {}

    return f"""
 Network Health:
Overall Health Score: {health.get('healthScore', 'Unknown')}
Total Devices: {health.get('totalDevices', 'Unknown')}
Healthy Devices: {health.get('goodDevices', 'Unknown')}
Unhealthy Devices: {health.get('badDevices', 'Unknown')}
Fair Devices: {health.get('fairDevices', 'Unknown')}
Unmonitored Devices: {health.get('unmonitoredDevices', 'Unknown')}
Health Distribution: Good {health.get('goodPercentage', 'Unknown')}%, Fair {health.get('fairPercentage', 'Unknown')}%, Bad {health.get('badPercentage', 'Unknown')}%
"""


@mcp.tool()
async def get_templates() -> str:
    """Get configuration templates."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/template-programmer/template"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch templates or no templates found."

    templates = data
    if not templates:
        return "No templates found."

    formatted_templates = []
    for template in templates:
        formatted = f"""
Template: {template.get('name', 'Unknown')}
ID: {template.get('templateId', 'Unknown')}
Project: {template.get('projectName', 'Unknown')}
Description: {template.get('description', 'None')}
Created By: {template.get('author', 'Unknown')}
"""
        formatted_templates.append(formatted)

    return "\n---\n".join(formatted_templates)


@mcp.tool()
async def get_sda_fabric() -> str:
    """Get SDA fabric information."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/business/sda/fabric"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch SDA fabric information or no fabric found."

    fabrics = data["response"]
    if not fabrics:
        return "No SDA fabrics found."

    formatted_fabrics = []
    for fabric in fabrics:
        formatted = f"""
Fabric: {fabric.get('fabricName', 'Unknown')}
Status: {fabric.get('status', 'Unknown')}
Domain Name: {fabric.get('fabricDomainName', 'Unknown')}
Type: {fabric.get('fabricType', 'Unknown')}
Site Name: {fabric.get('fabricSiteName', 'Unknown')}
"""
        formatted_fabrics.append(formatted)

    return "\n---\n".join(formatted_fabrics)


@mcp.tool()
async def get_virtual_networks() -> str:
    """Get virtual network information."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/business/sda/virtual-network"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch virtual network information or no virtual networks found."

    vnets = data["response"]
    if not vnets:
        return "No virtual networks found."

    formatted_vnets = []
    for vnet in vnets:
        formatted = f"""
Virtual Network: {vnet.get('virtualNetworkName', 'Unknown')}
Type: {vnet.get('virtualNetworkType', 'Unknown')}
Description: {vnet.get('desc', 'None')}
"""
        formatted_vnets.append(formatted)

    return "\n---\n".join(formatted_vnets)


@mcp.tool()
async def get_tags() -> str:
    """Get all tags."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/tag"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch tags or no tags found."

    tags = data["response"]
    if not tags:
        return "No tags found."

    formatted_tags = []
    for tag in tags:
        formatted = f"""
Tag: {tag.get('name', 'Unknown')}
ID: {tag.get('id', 'Unknown')}
Description: {tag.get('description', 'None')}
Number of Elements: {tag.get('numberOfMemberElements', 'Unknown')}
"""
        formatted_tags.append(formatted)

    return "\n---\n".join(formatted_tags)


@mcp.tool()
async def get_tag_members(tag_id: str) -> str:
    """Get members of a specific tag.

    Args:
        tag_id: Tag ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/tag/{tag_id}/member"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch members for tag {tag_id} or no members found."

    members = data["response"]
    if not members:
        return f"No members found for tag {tag_id}."

    formatted_members = []
    for member in members:
        formatted = f"""
Member: {member.get('hostName', 'Unknown')}
Type: {member.get('type', 'Unknown')}
IP: {member.get('ip', 'Unknown')}
"""
        formatted_members.append(formatted)

    return "\n---\n".join(formatted_members)


@mcp.tool()
async def get_pnp_devices() -> str:
    """Get Plug and Play devices."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/onboarding/pnp-device"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch PnP devices or no devices found."

    devices = data
    if not devices:
        return "No PnP devices found."

    formatted_devices = []
    for device in devices:
        formatted = f"""
Device: {device.get('deviceInfo', {}).get('serialNumber', 'Unknown')}
State: {device.get('deviceInfo', {}).get('state', 'Unknown')}
Platform ID: {device.get('deviceInfo', {}).get('pid', 'Unknown')}
Status: {device.get('deviceInfo', {}).get('status', 'Unknown')}
Workflow: {device.get('workflowInfo', {}).get('name', 'None')}
"""
        formatted_devices.append(formatted)

    return "\n---\n".join(formatted_devices)


@mcp.tool()
async def get_software_images() -> str:
    """Get software images."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/image/importation"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch software images or no images found."

    images = data["response"]
    if not images:
        return "No software images found."

    formatted_images = []
    for image in images:
        formatted = f"""
Image: {image.get('name', 'Unknown')}
Version: {image.get('version', 'Unknown')}
Family: {image.get('family', 'Unknown')}
Size: {image.get('fileSize', 'Unknown')} bytes
Import Time: {image.get('importTime', 'Unknown')}
"""
        formatted_images.append(formatted)

    return "\n---\n".join(formatted_images)


@mcp.tool()
async def get_events(tags: str = None, start_time: str = None, end_time: str = None) -> str:
    """Get events.

    Args:
        tags: Event tags (comma-separated)
        start_time: Start time in ISO format (optional)
        end_time: End time in ISO format (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/events"
    params = {}
    if tags:
        params["tags"] = tags
    if start_time:
        params["startTime"] = start_time
    if end_time:
        params["endTime"] = end_time

    data = await client.request("GET", endpoint, params=params)

    if not data:
        return "Unable to fetch events or no events found."

    events = data
    if not events:
        return "No events found for the specified criteria."

    formatted_events = []
    for event in events:
        formatted = f"""
Event: {event.get('name', 'Unknown')}
Description: {event.get('description', 'None')}
Severity: {event.get('severity', 'Unknown')}
Source: {event.get('source', 'Unknown')}
Timestamp: {event.get('timestamp', 'Unknown')}
"""
        formatted_events.append(formatted)

    return "\n---\n".join(formatted_events)


@mcp.tool()
async def get_event_subscriptions() -> str:
    """Get event subscriptions."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/event/subscription"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch event subscriptions or no subscriptions found."

    subscriptions = data
    if not subscriptions:
        return "No event subscriptions found."

    formatted_subscriptions = []
    for subscription in subscriptions:
        formatted = f"""
Subscription: {subscription.get('name', 'Unknown')}
Description: {subscription.get('description', 'None')}
Status: {subscription.get('status', 'Unknown')}
Event IDs: {subscription.get('eventIds', 'None')}
URL: {subscription.get('url', 'Unknown')}
"""
        formatted_subscriptions.append(formatted)

    return "\n---\n".join(formatted_subscriptions)


@mcp.tool()
async def get_application_policy() -> str:
    """Get application policies."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/application-policy"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch application policies or no policies found."

    policies = data["response"]
    if not policies:
        return "No application policies found."

    formatted_policies = []
    for policy in policies:
        formatted = f"""
Policy: {policy.get('id', 'Unknown')}
Name: {policy.get('name', 'Unknown')}
Network Identity: {policy.get('networkIdentity', {}).get('displayName', 'Unknown')}
Consumer: {policy.get('consumer', {}).get('displayName', 'Unknown')}
Producer: {policy.get('producer', {}).get('displayName', 'Unknown')}
"""
        formatted_policies.append(formatted)

    return "\n---\n".join(formatted_policies)


@mcp.tool()
async def get_vlan_info() -> str:
    """Get VLAN information."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/topology/vlan/vlan-names"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch VLAN information or no VLANs found."

    vlans = data["response"]
    if not vlans:
        return "No VLANs found."

    return f"VLANs in the network: {', '.join(str(vlan) for vlan in vlans)}"


@mcp.tool()
async def flow_analysis(source_ip: str, destination_ip: str) -> str:
    """Create a new flow analysis (path trace).

    Args:
        source_ip: Source IP address
        destination_ip: Destination IP address
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/flow-analysis"
    payload = {
        "sourceIP": source_ip,
        "destIP": destination_ip,
        "protocol": "UDP",  # Default to UDP
        "inclusions": ["INTERFACE-STATS", "DEVICE-STATS"]
    }

    data = await client.request("POST", endpoint, json=payload)

    if not data or "response" not in data:
        return f"Unable to create flow analysis from {source_ip} to {destination_ip}."

    flow_id = data["response"].get("flowAnalysisId", "Unknown")
    return f"Flow analysis created successfully. Flow Analysis ID: {flow_id}"


@mcp.tool()
async def get_flow_analysis(flow_id: str) -> str:
    """Get the result of a flow analysis (path trace).

    Args:
        flow_id: Flow Analysis ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/flow-analysis/{flow_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch flow analysis for ID {flow_id}."

    flow = data["response"]

    return f"""
 Flow Analysis ID: {flow_id}
Source IP: {flow.get('sourceIP', 'Unknown')}
Destination IP: {flow.get('destIP', 'Unknown')}
Protocol: {flow.get('protocol', 'Unknown')}
Status: {flow.get('status', 'Unknown')}
Created: {flow.get('createTime', 'Unknown')}
Last Updated: {flow.get('lastUpdateTime', 'Unknown')}
Number of Hops: {len(flow.get('networkElementsInfo', []))}
"""


@mcp.tool()
async def get_device_by_serial(serial_number: str) -> str:
    """Get device by serial number.

    Args:
        serial_number: Device serial number
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/network-device/serial-number/{serial_number}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch device with serial number {serial_number}."

    device = data["response"]

    return f"""
Device Details:
Hostname: {device.get('hostname', 'Unknown')}
Management IP: {device.get('managementIpAddress', 'Unknown')}
Platform: {device.get('platformId', 'Unknown')}
Serial Number: {device.get('serialNumber', 'Unknown')}
Status: {device.get('reachabilityStatus', 'Unknown')}
Software Version: {device.get('softwareVersion', 'Unknown')}
Role: {device.get('role', 'Unknown')}
Device ID: {device.get('id', 'N/A')}
"""


@mcp.tool()
async def get_device_by_ip(ip_address: str) -> str:
    """Get device by IP address.

    Args:
        ip_address: Device IP address
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/network-device/ip-address/{ip_address}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch device with IP address {ip_address}."

    device = data["response"]

    return f"""
Device Details:
Hostname: {device.get('hostname', 'Unknown')}
Management IP: {device.get('managementIpAddress', 'Unknown')}
Platform: {device.get('platformId', 'Unknown')}
Serial Number: {device.get('serialNumber', 'Unknown')}
Status: {device.get('reachabilityStatus', 'Unknown')}
Software Version: {device.get('softwareVersion', 'Unknown')}
Role: {device.get('role', 'Unknown')}
Device ID: {device.get('id', 'N/A')}
"""


@mcp.tool()
async def get_modules(device_id: str = None) -> str:
    """Get modules for a device.

    Args:
        device_id: Device ID (optional - if not provided, returns modules for all devices)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/network-device/module"
    params = {}
    if device_id:
        params["deviceId"] = device_id

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch modules or no modules found."

    modules = data["response"]
    if not modules:
        return "No modules found."

    formatted_modules = []
    for module in modules:
        formatted = f"""
Module: {module.get('name', 'Unknown')}
Part Number: {module.get('partNumber', 'Unknown')}
Serial Number: {module.get('serialNumber', 'Unknown')}
Status: {module.get('operationalStateCode', 'Unknown')}
Description: {module.get('description', 'None')}
Device ID: {module.get('deviceId', 'Unknown')}
"""
        formatted_modules.append(formatted)

    return "\n---\n".join(formatted_modules)


@mcp.tool()
async def get_device_count() -> str:
    """Get the count of network devices."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/network-device/count"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch device count."

    count = data["response"]
    return f"Total number of network devices: {count}"


@mcp.tool()
async def get_version() -> str:
    """Get the version of Cisco Catalyst Center."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/cisco-dna-center-system-version"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch Catalyst Center version."

    version_info = data["response"]
    return f"""
Cisco Catalyst Center Version:
Version: {version_info.get('version', 'Unknown')}
CDN Version: {version_info.get('cdnVersion', 'Unknown')}
CIMC Version: {version_info.get('cimcVersion', 'Unknown')}
Cloud Version: {version_info.get('cloudVersion', 'Unknown')}
"""


# AI Endpoint Analytics Tools

@mcp.tool()
async def get_endpoint_analytics(limit: int = 10, offset: int = 0) -> str:
    """Get endpoint analytics data.

    Args:
        limit: Maximum number of endpoints to return (default: 10)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/endpoint-analytics/endpoints?limit={limit}&offset={offset}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch endpoint analytics or no endpoints found."

    endpoints = data["response"]
    if not endpoints:
        return "No endpoint analytics data found."

    formatted_endpoints = []
    for ep in endpoints:
        formatted = f"""
MAC Address: {ep.get('macAddress', 'Unknown')}
IP Address: {ep.get('ipAddress', 'Unknown')}
Device Type: {ep.get('deviceType', 'Unknown')}
Hardware: {ep.get('hardwareManufacturer', 'Unknown')} {ep.get('hardwareModel', 'Unknown')}
OS: {ep.get('operatingSystem', 'Unknown')}
Trust Score: {ep.get('trustScore', 'Unknown')}
Authentication Method: {ep.get('authMethod', 'Unknown')}
Status: {'Registered' if ep.get('registered', False) else 'Not Registered'}
"""
        formatted_endpoints.append(formatted)

    return "\n---\n".join(formatted_endpoints)


@mcp.tool()
async def get_endpoint_count() -> str:
    """Get count of endpoints with specific status."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/endpoint-analytics/endpoints/count"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch endpoint count."

    return f"Total number of endpoints: {data}"


@mcp.tool()
async def get_anc_policies() -> str:
    """Get ANC (Adaptive Network Control) policies from ISE."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/endpoint-analytics/anc-policies"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch ANC policies or no policies found."

    policies = data["response"]
    if not policies:
        return "No ANC policies found."

    formatted_policies = []
    for policy in policies:
        formatted = f"""
Policy Name: {policy.get('name', 'Unknown')}
Description: {policy.get('description', 'None')}
Actions: {', '.join(policy.get('actions', []))}
"""
        formatted_policies.append(formatted)

    return "\n---\n".join(formatted_policies)


# Site Management Tools

@mcp.tool()
async def get_site_hierarchy() -> str:
    """Get the complete site hierarchy."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/site-hierarchy"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch site hierarchy."

    site_hierarchy = data["response"]

    return f"Site Hierarchy: {json.dumps(site_hierarchy, indent=2)}"


@mcp.tool()
async def get_site_by_id(site_id: str) -> str:
    """Get site details by site ID.

    Args:
        site_id: The ID of the site
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/site/{site_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch details for site ID {site_id}."

    site = data["response"]

    return f"""
Site Details:
Name: {site.get('name', 'Unknown')}
Type: {site.get('siteType', 'Unknown')}
Parent ID: {site.get('parentId', 'None')}
Additional Info: {site.get('additionalInfo', [])}
"""


@mcp.tool()
async def get_membership(site_id: str) -> str:
    """Get network devices assigned to a site.

    Args:
        site_id: The ID of the site
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/membership/{site_id}"
    data = await client.request("GET", endpoint)

    if not data or "site" not in data or "device" not in data["site"]:
        return f"Unable to fetch membership for site ID {site_id}."

    devices = data["site"]["device"]

    if not devices:
        return "No devices assigned to this site."

    formatted_devices = []
    for device in devices:
        formatted = f"""
Device Name: {device.get('name', 'Unknown')}
IP Address: {device.get('ip', 'Unknown')}
Device Type: {device.get('deviceType', 'Unknown')}
Series: {device.get('series', 'Unknown')}
Family: {device.get('family', 'Unknown')}
"""
        formatted_devices.append(formatted)

    return "\n---\n".join(formatted_devices)


# Wireless Tools

@mcp.tool()
async def get_wireless_profiles() -> str:
    """Get wireless network profiles."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/wireless/profile"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch wireless profiles or no profiles found."

    profiles = data
    if not profiles:
        return "No wireless profiles found."

    formatted_profiles = []
    for profile in profiles:
        formatted = f"""
Profile Name: {profile.get('profileName', 'Unknown')}
SSID: {profile.get('ssidDetails', [{}])[0].get('name', 'Unknown') if profile.get('ssidDetails') else 'Unknown'}
Security Level: {profile.get('ssidDetails', [{}])[0].get('securityLevel', 'Unknown') if profile.get('ssidDetails') else 'Unknown'}
Status: {'Enabled' if profile.get('status') == 'ENABLED' else 'Disabled'}
"""
        formatted_profiles.append(formatted)

    return "\n---\n".join(formatted_profiles)


@mcp.tool()
async def get_wireless_clients(limit: int = 10, offset: int = 0) -> str:
    """Get wireless client devices.

    Args:
        limit: Maximum number of clients to return (default: 10)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/client-detail?limit={limit}&offset={offset}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch wireless clients or no clients found."

    clients = data["response"]
    if not clients:
        return "No wireless clients found."

    formatted_clients = []
    for client_device in clients:
        formatted = f"""
Client: {client_device.get('hostName', 'Unknown')}
MAC Address: {client_device.get('macAddress', 'Unknown')}
IP Address: {client_device.get('ipAddress', 'Unknown')}
SSID: {client_device.get('ssid', 'Unknown')}
Connected AP: {client_device.get('apName', 'Unknown')}
Signal Strength: {client_device.get('rssi', 'Unknown')} dBm
Status: {client_device.get('connectionStatus', 'Unknown')}
"""
        formatted_clients.append(formatted)

    return "\n---\n".join(formatted_clients)


@mcp.tool()
async def get_wireless_ap_details(ap_mac: str) -> str:
    """Get detailed information about a specific access point.

    Args:
        ap_mac: MAC address of the access point
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/network-device?macAddress={ap_mac}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch details for access point with MAC {ap_mac}."

    ap = data["response"][0] if data["response"] else None
    if not ap:
        return f"No access point found with MAC {ap_mac}."

    return f"""
Access Point Details:
Name: {ap.get('hostname', 'Unknown')}
MAC Address: {ap.get('macAddress', 'Unknown')}
IP Address: {ap.get('managementIpAddress', 'Unknown')}
Serial: {ap.get('serialNumber', 'Unknown')}
Model: {ap.get('platformId', 'Unknown')}
Software: {ap.get('softwareVersion', 'Unknown')}
Status: {ap.get('reachabilityStatus', 'Unknown')}
Location: {ap.get('location', 'Unknown')}
"""


# Compliance Tools

@mcp.tool()
async def get_compliance_status(device_uuid: str = None) -> str:
    """Get compliance status of network devices.

    Args:
        device_uuid: Device UUID (optional - if not provided, returns status for all devices)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/compliance"
    params = {}
    if device_uuid:
        params["deviceUuid"] = device_uuid

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch compliance status or no devices found."

    devices = data["response"]
    if not devices:
        return "No compliance data found."

    formatted_devices = []
    for device in devices:
        formatted = f"""
Device: {device.get('deviceName', 'Unknown')}
UUID: {device.get('deviceUuid', 'Unknown')}
Status: {device.get('status', 'Unknown')}
Last Checked: {device.get('lastCheckedTime', 'Unknown')}
Compliant Count: {device.get('complianceCount', 'Unknown')}
Non-Compliant Count: {device.get('nonComplianceCount', 'Unknown')}
"""
        formatted_devices.append(formatted)

    return "\n---\n".join(formatted_devices)


@mcp.tool()
async def get_compliance_detail(device_uuid: str) -> str:
    """Get detailed compliance information for a device.

    Args:
        device_uuid: Device UUID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/compliance/{device_uuid}/detail"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch compliance details for device {device_uuid}."

    details = data["response"]
    if not details:
        return f"No compliance details found for device {device_uuid}."

    compliant_items = []
    non_compliant_items = []

    for detail in details:
        if detail.get("complianceStatus") == "COMPLIANT":
            compliant_items.append(detail.get("displayName", "Unknown"))
        else:
            non_compliant_items.append(f"{detail.get('displayName', 'Unknown')}: {detail.get('message', 'No message')}")

    return f"""
Compliance Details for Device {device_uuid}:

Compliant Items:
{chr(10).join(['- ' + item for item in compliant_items]) if compliant_items else "None"}

Non-Compliant Items:
{chr(10).join(['- ' + item for item in non_compliant_items]) if non_compliant_items else "None"}
"""


# Event Management Tools

@mcp.tool()
async def get_event_series(event_id: str = None, start_time: int = None, end_time: int = None) -> str:
    """Get event series by event ID or time range.

    Args:
        event_id: Event ID (optional)
        start_time: Start time in milliseconds since epoch (optional)
        end_time: End time in milliseconds since epoch (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/system/api/v1/event/event-series"
    params = {}

    if event_id:
        params["eventId"] = event_id
    if start_time:
        params["startTime"] = start_time
    if end_time:
        params["endTime"] = end_time

    data = await client.request("GET", endpoint, params=params)

    if not data:
        return "Unable to fetch event series or no events found."

    events = data
    if not events:
        return "No events found for the specified criteria."

    formatted_events = []
    for event in events[:10]:  # Limit to 10 events for readability
        formatted = f"""
Event ID: {event.get('eventId', 'Unknown')}
Description: {event.get('description', 'None')}
Category: {event.get('category', 'Unknown')}
Severity: {event.get('severity', 'Unknown')}
Source: {event.get('source', 'Unknown')}
Timestamp: {event.get('timestamp', 'Unknown')}
Details: {event.get('details', 'None')}
"""
        formatted_events.append(formatted)

    total_events = len(events)
    displayed_events = min(10, total_events)

    return f"Showing {displayed_events} of {total_events} events:\n\n" + "\n---\n".join(formatted_events)


@mcp.tool()
async def get_event_count(tags: str = None, start_time: int = None, end_time: int = None) -> str:
    """Get count of events.

    Args:
        tags: Event tags (comma-separated, optional)
        start_time: Start time in milliseconds since epoch (optional)
        end_time: End time in milliseconds since epoch (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/system/api/v1/event/event-series/count"
    params = {}

    if tags:
        params["tags"] = tags
    if start_time:
        params["startTime"] = start_time
    if end_time:
        params["endTime"] = end_time

    data = await client.request("GET", endpoint, params=params)

    if not data:
        return "Unable to fetch event count."

    return f"Total number of events: {data}"


# Network Discovery Tools

@mcp.tool()
async def get_discovery_jobs(start_index: int = 1, records_to_return: int = 10) -> str:
    """Get network discovery jobs.

    Args:
        start_index: Start index for pagination (default: 1)
        records_to_return: Number of records to return (default: 10)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/discovery?startIndex={start_index}&recordsToReturn={records_to_return}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch discovery jobs or no jobs found."

    jobs = data["response"]
    if not jobs:
        return "No discovery jobs found."

    formatted_jobs = []
    for job in jobs:
        formatted = f"""
Discovery ID: {job.get('id', 'Unknown')}
Name: {job.get('name', 'Unknown')}
Discovery Type: {job.get('discoveryType', 'Unknown')}
IP Range: {job.get('ipAddressList', 'Unknown')}
Status: {job.get('discoveryStatus', 'Unknown')}
Start Time: {job.get('startTime', 'Unknown')}
End Time: {job.get('endTime', 'Unknown')}
Device Count: {job.get('deviceCount', 'Unknown')}
"""
        formatted_jobs.append(formatted)

    return "\n---\n".join(formatted_jobs)


@mcp.tool()
async def get_discovery_job_by_id(id: str) -> str:
    """Get network discovery job by ID.

    Args:
        id: Discovery job ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/discovery/{id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch discovery job with ID {id}."

    job = data["response"]

    return f"""
Discovery Job Detail:
ID: {job.get('id', 'Unknown')}
Name: {job.get('name', 'Unknown')}
Discovery Type: {job.get('discoveryType', 'Unknown')}
IP Address List: {job.get('ipAddressList', 'Unknown')}
Protocol Order: {job.get('protocolOrder', 'Unknown')}
Discovery Status: {job.get('discoveryStatus', 'Unknown')}
Start Time: {job.get('startTime', 'Unknown')}
End Time: {job.get('endTime', 'Unknown')}
Duration: {job.get('duration', 'Unknown')}
Device Count: {job.get('deviceCount', 'Unknown')}
"""


@mcp.tool()
async def get_discovery_job_summary(id: str) -> str:
    """Get network discovery job summary by ID.

    Args:
        id: Discovery job ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/discovery/{id}/summary"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch summary for discovery job with ID {id}."

    summary = data["response"]

    return f"""
Discovery Job Summary:
ID: {summary.get('id', 'Unknown')}
Status: {summary.get('discoveryStatus', 'Unknown')}
Start Time: {summary.get('startTime', 'Unknown')}
End Time: {summary.get('endTime', 'Unknown')}
Reachable Device Count: {summary.get('reachableDeviceCount', 'Unknown')}
Unreachable Device Count: {summary.get('unreachableDeviceCount', 'Unknown')}
Completed Devices: {summary.get('completedDeviceCount', 'Unknown')}
Progress: {summary.get('numDevices', 0) - summary.get('numRemaining', 0)} of {summary.get('numDevices', 0)} devices processed
"""


# Operational Tools

@mcp.tool()
async def get_command_runner_templates() -> str:
    """Get command runner templates."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/network-device-poller/cli/legit-reads"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch command runner templates or no templates found."

    templates = data["response"]
    if not templates:
        return "No command runner templates found."

    return f"Available Command Templates:\n" + "\n".join([f"- {template}" for template in templates])


@mcp.tool()
async def get_user_enrichment(username: str = None, mac_address: str = None, entity_type: str = None) -> str:
    """Get user enrichment information.

    Args:
        username: Username to search for (optional)
        mac_address: MAC address to search for (optional)
        entity_type: Entity type ('USER' or 'CLIENT_DEVICE') (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/user-enrichment-details"
    params = {}

    if username:
        params["username"] = username
    if mac_address:
        params["macAddress"] = mac_address
    if entity_type:
        params["entityType"] = entity_type

    data = await client.request("GET", endpoint, params=params)

    if not data or not data:
        return "Unable to fetch user enrichment details or no details found."

    users = data
    if not users:
        return "No user enrichment details found for the specified criteria."

    formatted_users = []
    for user in users:
        formatted = f"""
Username: {user.get('userDetails', {}).get('username', 'Unknown')}
First Name: {user.get('userDetails', {}).get('firstName', 'Unknown')}
Last Name: {user.get('userDetails', {}).get('lastName', 'Unknown')}
Phone Number: {user.get('userDetails', {}).get('phoneNumber', 'Unknown')}
Email: {user.get('userDetails', {}).get('emailAddress', 'Unknown')}
Connected Device: {user.get('connectedDevice', [{}])[0].get('deviceName', 'Unknown') if user.get('connectedDevice') else 'Unknown'}
Connection Status: {user.get('connectionStatus', 'Unknown')}
Host Type: {user.get('hostType', 'Unknown')}
"""
        formatted_users.append(formatted)

    return "\n---\n".join(formatted_users)


# System Settings Tools

@mcp.tool()
async def get_smart_account_details() -> str:
    """Get Cisco Smart Account details."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/smart-account"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch Smart Account details or no account found."

    account = data["response"]

    return f"""
Smart Account Details:
Domain: {account.get('domain', 'Unknown')}
Is Active: {'Yes' if account.get('isActive', False) else 'No'}
Account Name: {account.get('name', 'Unknown')}
Account Type: {account.get('type', 'Unknown')}
"""


@mcp.tool()
async def get_system_performance() -> str:
    """Get system performance metrics."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/diagnostics/system/health"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch system performance metrics."

    metrics = data["response"]
    health_checks = metrics.get('healthChecks', [])

    formatted_checks = []
    for check in health_checks:
        formatted = f"""
Check: {check.get('name', 'Unknown')}
Status: {check.get('status', 'Unknown')}
Message: {check.get('message', 'None')}
"""
        formatted_checks.append(formatted)

    return f"""
System Health:
Overall Status: {metrics.get('overallHealth', {}).get('status', 'Unknown')}
Host Name: {metrics.get('hostName', 'Unknown')}
CPU Utilization: {metrics.get('cpuUtilization', 'Unknown')}%
Memory Utilization: {metrics.get('memoryUtilization', 'Unknown')}%
Disk Utilization: {metrics.get('diskUtilization', 'Unknown')}%

Health Checks:
{"".join(formatted_checks)}
"""


@mcp.tool()
async def get_dashboard_metrics() -> str:
    """Get network dashboard metrics."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/dashboard"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch dashboard metrics."

    metrics = data["response"]

    return f"""
Dashboard Metrics:
Total Device Count: {metrics.get('totalDeviceCount', 'Unknown')}
Management Status:
  Managed: {metrics.get('managedDeviceCount', 'Unknown')}
  Unmanaged: {metrics.get('unManagedDeviceCount', 'Unknown')}

Reachability Status:
  Reachable: {metrics.get('reachableDeviceCount', 'Unknown')}
  Unreachable: {metrics.get('unreachableDeviceCount', 'Unknown')}

Site Health:
  Total Sites: {metrics.get('sitesCount', 'Unknown')}
  Healthy Sites: {metrics.get('healthySiteCount', 'Unknown')}

Client Health:
  Total Clients: {metrics.get('clientCount', 'Unknown')}
  Healthy Clients: {metrics.get('healthyClientCount', 'Unknown')}
  Unhealthy Clients: {metrics.get('unhealthyClientCount', 'Unknown')}
"""


# System Tools - Disaster Recovery

@mcp.tool()
async def get_disaster_recovery_status() -> str:
    """Get disaster recovery operation status."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/disasterrecovery/system/operationstatus"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch disaster recovery status."

    return f"""
Disaster Recovery Status:
Status: {data.get('status', 'Unknown')}
Details: {data.get('statusMessage', 'No details available')}
Last Updated: {data.get('timestamp', 'Unknown')}
"""


# User Management Tools

@mcp.tool()
async def get_external_authentication_servers() -> str:
    """Get external authentication servers configured on Catalyst Center."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/system/api/v1/users/external-servers"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch external authentication servers or no servers found."

    servers = data["response"]
    if not servers:
        return "No external authentication servers found."

    formatted_servers = []
    for server in servers:
        formatted = f"""
Server Name: {server.get('name', 'Unknown')}
Type: {server.get('type', 'Unknown')}
IP Address: {server.get('ipAddress', 'Unknown')}
Port: {server.get('port', 'Unknown')}
Protocol: {server.get('protocol', 'Unknown')}
Status: {'Active' if server.get('isActive', False) else 'Inactive'}
"""
        formatted_servers.append(formatted)

    return "\n---\n".join(formatted_servers)


@mcp.tool()
async def get_external_authentication_settings() -> str:
    """Get external authentication settings configured on Catalyst Center."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/system/api/v1/users/external-authentication"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch external authentication settings."

    settings = data["response"]

    return f"""
External Authentication Settings:
Status: {'Enabled' if settings.get('externalAuthEnabled', False) else 'Disabled'}
Fallback to Local Authentication: {'Enabled' if settings.get('fallbackToLocal', False) else 'Disabled'}
Authentication Order: {', '.join(settings.get('authenticationOrder', ['None']))}
"""


@mcp.tool()
async def get_aaa_attributes() -> str:
    """Get AAA attributes for external server configuration."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/system/api/v1/users/external-servers/aaa-attribute"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch AAA attributes or no attributes found."

    attributes = data["response"]
    if not attributes:
        return "No AAA attributes found."

    formatted_attr = []
    for attr in attributes:
        formatted = f"""
Attribute Name: {attr.get('name', 'Unknown')}
Type: {attr.get('type', 'Unknown')}
Value: {attr.get('value', 'Unknown')}
Required: {'Yes' if attr.get('required', False) else 'No'}
Default Value: {attr.get('defaultValue', 'None')}
Description: {attr.get('description', 'No description')}
"""
        formatted_attr.append(formatted)

    return "\n---\n".join(formatted_attr)


# License Management Tools

@mcp.tool()
async def get_license_operation_status() -> str:
    """Get the status of the last license operation."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/system/api/v1/license/lastOperationStatus"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch license operation status."

    return f"""
License Operation Status:
Status: {data.get('status', 'Unknown')}
Operation: {data.get('operation', 'Unknown')}
Details: {data.get('statusMessage', 'No details available')}
Start Time: {data.get('startTime', 'Unknown')}
End Time: {data.get('endTime', 'Unknown')}
"""


@mcp.tool()
async def get_license_device_summary() -> str:
    """Get license summary for devices."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/licenses/device/summary"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch license device summary."

    summary = data["response"]

    return f"""
License Device Summary:
Total Devices: {summary.get('totalDeviceCount', 'Unknown')}
Managed Devices: {summary.get('licenseDeviceCount', 'Unknown')}
Unmanaged Devices: {summary.get('unlicenseDeviceCount', 'Unknown')}
DNA Advantage: {summary.get('dnaAdvantageDeviceCount', 'Unknown')}
DNA Essentials: {summary.get('dnaEssentialsDeviceCount', 'Unknown')}
Network Advantage: {summary.get('networkAdvantageDeviceCount', 'Unknown')}
Network Essentials: {summary.get('networkEssentialsDeviceCount', 'Unknown')}
Evaluation Mode Devices: {summary.get('evaluationDeviceCount', 'Unknown')}
"""


@mcp.tool()
async def get_license_usage(smart_account_id: str, virtual_account_name: str) -> str:
    """Get license usage details for a Smart Account and Virtual Account.

    Args:
        smart_account_id: Smart Account ID
        virtual_account_name: Virtual Account name
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/licenses/usage/smartAccount/{smart_account_id}/virtualAccount/{virtual_account_name}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch license usage for Smart Account {smart_account_id} and Virtual Account {virtual_account_name}."

    licenses = data["response"]
    if not licenses:
        return "No license usage data found."

    formatted_licenses = []
    for license in licenses:
        formatted = f"""
License Type: {license.get('licenseType', 'Unknown')}
Total Count: {license.get('totalCount', 'Unknown')}
Used Count: {license.get('usedCount', 'Unknown')}
Available Count: {license.get('availableCount', 'Unknown')}
Status: {license.get('status', 'Unknown')}
"""
        formatted_licenses.append(formatted)

    return "\n---\n".join(formatted_licenses)


# Security Tools

@mcp.tool()
async def get_allowed_mac_addresses(limit: int = 20, offset: int = 0) -> str:
    """Get allowed MAC addresses for security.

    Args:
        limit: Maximum number of MAC addresses to return (default: 20)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/security/threats/rogue/allowed-list?offset={offset}&limit={limit}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch allowed MAC addresses or no addresses found."

    addresses = data["response"]
    if not addresses:
        return "No allowed MAC addresses found."

    formatted_addresses = []
    for address in addresses:
        formatted = f"""
MAC Address: {address.get('macAddress', 'Unknown')}
Added On: {address.get('addedOn', 'Unknown')}
Added By: {address.get('addedBy', 'Unknown')}
Comments: {address.get('comments', 'None')}
"""
        formatted_addresses.append(formatted)

    return "\n---\n".join(formatted_addresses)


@mcp.tool()
async def get_wireless_rogue_ap_containment_status(mac_address: str) -> str:
    """Get wireless rogue access point containment status.

    Args:
        mac_address: MAC address of the rogue access point
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/security/rogue/wireless-containment/status/{mac_address}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch containment status for rogue AP with MAC {mac_address}."

    status = data["response"]

    containment_status = "Contained" if status.get("isContained", False) else "Not Contained"

    return f"""
Rogue AP Containment Status for {mac_address}:
Status: {containment_status}
Controller: {status.get('containedByWlc', 'Unknown')}
BSSIDs: {', '.join(status.get('rogueApBssids', []) or ['None'])}
SSID: {status.get('ssid', 'Unknown')}
Strongest Detecting WLC: {status.get('strongestDetectingWlc', 'Unknown')}
"""


# Profiling Rules Tools

@mcp.tool()
async def get_profiling_rule(rule_id: str) -> str:
    """Get details of a single profiling rule.

    Args:
        rule_id: Rule ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/endpoint-analytics/profiling-rules/{rule_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch profiling rule with ID {rule_id}."

    rule = data["response"]

    return f"""
Rule Details:
Name: {rule.get('name', 'Unknown')}
ID: {rule_id}
Type: {rule.get('ruleType', 'Unknown')}
Description: {rule.get('description', 'None')}
Priority: {rule.get('priority', 'Unknown')}
Source: {rule.get('source', 'Unknown')}
Status: {'Active' if rule.get('status', False) else 'Inactive'}
"""


@mcp.tool()
async def get_profiling_rules(rule_type: str = None, limit: int = 20, offset: int = 0) -> str:
    """Get list of profiling rules.

    Args:
        rule_type: Filter by rule type (optional)
        limit: Maximum number of rules to return (default: 20)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/endpoint-analytics/profiling-rules?limit={limit}&offset={offset}"
    if rule_type:
        endpoint += f"&ruleType={rule_type}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch profiling rules or no rules found."

    rules = data["response"]
    if not rules:
        return "No profiling rules found."

    formatted_rules = []
    for rule in rules:
        formatted = f"""
Rule Name: {rule.get('name', 'Unknown')}
ID: {rule.get('id', 'Unknown')}
Type: {rule.get('ruleType', 'Unknown')}
Priority: {rule.get('priority', 'Unknown')}
Status: {'Active' if rule.get('status', False) else 'Inactive'}
"""
        formatted_rules.append(formatted)

    return "\n---\n".join(formatted_rules)


@mcp.tool()
async def get_profiling_rules_count(rule_type: str = None) -> str:
    """Get count of profiling rules.

    Args:
        rule_type: Filter by rule type (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/endpoint-analytics/profiling-rules/count"
    params = {}
    if rule_type:
        params["ruleType"] = rule_type

    data = await client.request("GET", endpoint, params=params)

    if not data:
        return "Unable to fetch profiling rules count."

    return f"Total number of profiling rules: {data}"


@mcp.tool()
async def get_endpoint_details(endpoint_id: str) -> str:
    """Get details of a specific endpoint.

    Args:
        endpoint_id: Endpoint ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/endpoint-analytics/endpoints/{endpoint_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch endpoint details with ID {endpoint_id}."

    ep = data["response"]

    return f"""
Endpoint Details:
MAC Address: {ep.get('macAddress', 'Unknown')}
IP Address: {ep.get('ipAddress', 'Unknown')}
Hostname: {ep.get('hostName', 'Unknown')}
Device Type: {ep.get('deviceType', 'Unknown')}
Hardware: {ep.get('hardwareManufacturer', 'Unknown')} {ep.get('hardwareModel', 'Unknown')}
OS: {ep.get('operatingSystem', 'Unknown')}
Trust Score: {ep.get('trustScore', 'Unknown')}
Authentication Method: {ep.get('authMethod', 'Unknown')}
Status: {'Registered' if ep.get('registered', False) else 'Not Registered'}
First Seen: {ep.get('firstSeen', 'Unknown')}
Last Seen: {ep.get('lastSeen', 'Unknown')}
"""


@mcp.tool()
async def get_endpoint_dictionaries(include_attributes: bool = False) -> str:
    """Get AI Endpoint Analytics attribute dictionaries.

    Args:
        include_attributes: Whether to include attributes in the response (default: False)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/endpoint-analytics/dictionaries"
    params = {}
    if include_attributes:
        params["includeAttributes"] = "true"

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch endpoint dictionaries or no dictionaries found."

    dictionaries = data["response"]
    if not dictionaries:
        return "No endpoint dictionaries found."

    formatted_dicts = []
    for dictionary in dictionaries:
        attributes_info = ""
        if include_attributes and "attributes" in dictionary:
            attr_count = len(dictionary.get("attributes", []))
            attributes_info = f"\nNumber of Attributes: {attr_count}"

        formatted = f"""
Dictionary: {dictionary.get('dictionaryName', 'Unknown')}
Version: {dictionary.get('version', 'Unknown')}
Namespace: {dictionary.get('namespace', 'Unknown')}{attributes_info}
"""
        formatted_dicts.append(formatted)

    return "\n---\n".join(formatted_dicts)


# Device Replacement Tools

@mcp.tool()
async def get_device_replacements() -> str:
    """Get device replacement workflows."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/device-replacement"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch device replacements or no replacements found."

    replacements = data["response"]
    if not replacements:
        return "No device replacements found."

    formatted_replacements = []
    for replacement in replacements:
        formatted = f"""
Replacement ID: {replacement.get('id', 'Unknown')}
Creation Time: {replacement.get('creationTime', 'Unknown')}
Replaced Device: {replacement.get('replacementDeviceId', 'Unknown')}
Faulty Device: {replacement.get('faultyDeviceId', 'Unknown')}
Replacement Status: {replacement.get('replacementStatus', 'Unknown')}
Workflow Status: {replacement.get('workflowStatus', 'Unknown')}
"""
        formatted_replacements.append(formatted)

    return "\n---\n".join(formatted_replacements)


@mcp.tool()
async def get_device_replacement_count() -> str:
    """Get count of device replacement workflows."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/device-replacement/count"
    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch device replacement count."

    return f"Total device replacements: {data}"


@mcp.tool()
async def get_device_replacement_status(replacement_id: str) -> str:
    """Get status of a specific device replacement workflow.

    Args:
        replacement_id: Replacement ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/device-replacement/{replacement_id}"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch status for device replacement with ID {replacement_id}."

    replacement = data["response"]

    return f"""
Device Replacement Status:
Replacement ID: {replacement.get('id', 'Unknown')}
Creation Time: {replacement.get('creationTime', 'Unknown')}
Replaced Device: {replacement.get('replacementDeviceId', 'Unknown')}
Replaced Device Serial: {replacement.get('replacementDeviceSerialNumber', 'Unknown')}
Faulty Device: {replacement.get('faultyDeviceId', 'Unknown')}
Faulty Device Serial: {replacement.get('faultyDeviceSerialNumber', 'Unknown')}
Replacement Status: {replacement.get('replacementStatus', 'Unknown')}
Workflow Status: {replacement.get('workflowStatus', 'Unknown')}
"""


# Application Visibility Tools (V2)

@mcp.tool()
async def get_application_sets_v2(name: str = None, limit: int = 10, offset: int = 0) -> str:
    """Get application sets (v2 API).

    Args:
        name: Filter by application set name (optional)
        limit: Maximum number of application sets to return (default: 10)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v2/application-policy-application-set?limit={limit}&offset={offset}"
    if name:
        endpoint += f"&name={name}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch application sets or no sets found."

    app_sets = data["response"]
    if not app_sets:
        return "No application sets found."

    formatted_sets = []
    for app_set in app_sets:
        formatted = f"""
Application Set: {app_set.get('name', 'Unknown')}
ID: {app_set.get('id', 'Unknown')}
Status: {'Enabled' if app_set.get('isEnabled', False) else 'Disabled'}
Description: {app_set.get('description', 'None')}
Type: {app_set.get('type', 'Unknown')}
"""
        formatted_sets.append(formatted)

    return "\n---\n".join(formatted_sets)


@mcp.tool()
async def get_applications_v2(name: str = None, limit: int = 10, offset: int = 0) -> str:
    """Get applications (v2 API).

    Args:
        name: Filter by application name (optional)
        limit: Maximum number of applications to return (default: 10)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v2/applications?limit={limit}&offset={offset}"
    if name:
        endpoint += f"&name={name}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch applications or no applications found."

    applications = data["response"]
    if not applications:
        return "No applications found."

    formatted_apps = []
    for app in applications:
        formatted = f"""
Application: {app.get('name', 'Unknown')}
ID: {app.get('id', 'Unknown')}
Category: {app.get('category', 'Unknown')}
Status: {'Enabled' if app.get('isEnabled', False) else 'Disabled'}
Traffic Class: {app.get('trafficClass', 'Unknown')}
Application Set: {app.get('applicationSet', {}).get('idRef', 'Unknown')}
"""
        formatted_apps.append(formatted)

    return "\n---\n".join(formatted_apps)


@mcp.tool()
async def get_application_set_count(scalable_group_type: str = None) -> str:
    """Get count of application sets.

    Args:
        scalable_group_type: Filter by scalable group type (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v2/application-policy-application-set-count"
    params = {}
    if scalable_group_type:
        params["scalableGroupType"] = scalable_group_type

    data = await client.request("GET", endpoint, params=params)

    if not data:
        return "Unable to fetch application set count."

    return f"Total application sets: {data}"


@mcp.tool()
async def get_application_count_v2(scalable_group_type: str = None) -> str:
    """Get count of applications (v2 API).

    Args:
        scalable_group_type: Filter by scalable group type (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v2/applications-count"
    params = {}
    if scalable_group_type:
        params["scalableGroupType"] = scalable_group_type

    data = await client.request("GET", endpoint, params=params)

    if not data:
        return "Unable to fetch application count."

    return f"Total applications: {data}"


@mcp.tool()
async def get_qos_device_interface_info(network_device_id: str = None) -> str:
    """Get QoS device interface information.

    Args:
        network_device_id: Network device ID (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/qos-device-interface-info"
    params = {}
    if network_device_id:
        params["networkDeviceId"] = network_device_id

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch QoS device interface information or no information found."

    interfaces = data["response"]
    if not interfaces:
        return "No QoS device interface information found."

    formatted_interfaces = []
    for interface in interfaces:
        formatted = f"""
Device ID: {interface.get('id', 'Unknown')}
Device Name: {interface.get('name', 'Unknown')}
Type: {interface.get('type', 'Unknown')}
QoS Status: {interface.get('qosStatus', 'Unknown')}
Interface Count: {interface.get('interfaceCount', 'Unknown')}
"""
        formatted_interfaces.append(formatted)

    return "\n---\n".join(formatted_interfaces)


@mcp.tool()
async def get_qos_device_interface_info_count() -> str:
    """Get count of QoS device interface information."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/qos-device-interface-info-count"
    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch QoS device interface information count."

    count_data = data["response"]

    formatted_counts = []
    for count in count_data:
        formatted = f"""
Device ID: {count.get('id', 'Unknown')}
Device Name: {count.get('name', 'Unknown')}
Interface Count: {count.get('interfaceCount', 'Unknown')}
"""
        formatted_counts.append(formatted)

    return "\n---\n".join(formatted_counts)


@mcp.tool()
async def get_application_policy_queuing_profile(name: str = None) -> str:
    """Get application policy queuing profile.

    Args:
        name: Filter by profile name (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/app-policy-queuing-profile"
    params = {}
    if name:
        params["name"] = name

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch application policy queuing profiles or no profiles found."

    profiles = data["response"]
    if not profiles:
        return "No application policy queuing profiles found."

    formatted_profiles = []
    for profile in profiles:
        formatted = f"""
Profile Name: {profile.get('name', 'Unknown')}
ID: {profile.get('id', 'Unknown')}
Description: {profile.get('description', 'None')}
Status: {'Enabled' if profile.get('status', False) else 'Disabled'}
"""
        formatted_profiles.append(formatted)

    return "\n---\n".join(formatted_profiles)


# Network Topology Tools

@mcp.tool()
async def get_l2_topology(vlan_id: str = None) -> str:
    """Get layer 2 network topology.

    Args:
        vlan_id: VLAN ID to filter the topology (optional)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/topology/l2"
    params = {}
    if vlan_id:
        params["vlanID"] = vlan_id

    data = await client.request("GET", endpoint, params=params)

    if not data or "response" not in data:
        return "Unable to fetch layer 2 topology or no topology found."

    topology = data["response"]

    # Extract nodes and links information
    nodes = topology.get("nodes", [])
    links = topology.get("links", [])

    return f"""
Layer 2 Topology:
Number of Nodes: {len(nodes)}
Number of Links: {len(links)}

Node Types: {", ".join(set(node.get("role", "Unknown") for node in nodes if "role" in node))}
"""


@mcp.tool()
async def get_l3_topology(topology_type: str = "OSPF") -> str:
    """Get layer 3 network topology.

    Args:
        topology_type: Type of topology (default: OSPF, options: OSPF, ISIS, StaticRoute, BGP, EIGRP, LISP)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/topology/l3/{topology_type}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch layer 3 {topology_type} topology or no topology found."

    topology = data["response"]

    # Extract nodes and links information
    nodes = topology.get("nodes", [])
    links = topology.get("links", [])

    return f"""
Layer 3 {topology_type} Topology:
Number of Nodes: {len(nodes)}
Number of Links: {len(links)}

Node Types: {", ".join(set(node.get("nodeType", "Unknown") for node in nodes if "nodeType" in node))}
"""


@mcp.tool()
async def get_site_topology() -> str:
    """Get site topology."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/topology/site-topology"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch site topology or no topology found."

    topology = data["response"]

    # Extract sites information
    sites = topology.get("sites", [])

    formatted_sites = []
    for site in sites[:10]:  # Limit to 10 sites for readability
        formatted = f"""
Site ID: {site.get('id', 'Unknown')}
Name: {site.get('name', 'Unknown')}
Parent ID: {site.get('parentId', 'None')}
Group Type: {site.get('groupTypeId', 'Unknown')}
Additional Info: {site.get('additionalInfo', [])}
"""
        formatted_sites.append(formatted)

    total_sites = len(sites)
    displayed_sites = min(10, total_sites)

    return f"Site Topology (showing {displayed_sites} of {total_sites} sites):\n\n" + "\n---\n".join(formatted_sites)


@mcp.tool()
async def get_topology_details() -> str:
    """Get details about network topology."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/topology/details"

    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch topology details or no details found."

    return f"""
Network Topology Details:
L2 Topology: {'Available' if data.get('isL2TopologyEnabled', False) else 'Not Available'}
L3 Topology: {'Available' if data.get('isL3TopologyEnabled', False) else 'Not Available'}
Last Updated: {data.get('lastUpdatedTime', 'Unknown')}
"""


@mcp.tool()
async def get_vlan_topology() -> str:
    """Get VLAN topology."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/topology/vlan/details"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch VLAN topology or no topology found."

    vlans = data["response"]
    if not vlans:
        return "No VLAN topology found."

    formatted_vlans = []
    for vlan in vlans[:10]:  # Limit to 10 VLANs for readability
        formatted = f"""
VLAN ID: {vlan.get('vlanId', 'Unknown')}
VLAN Name: {vlan.get('vlanName', 'Unknown')}
Device Count: {vlan.get('deviceCount', 'Unknown')}
Link Count: {vlan.get('linkCount', 'Unknown')}
"""
        formatted_vlans.append(formatted)

    total_vlans = len(vlans)
    displayed_vlans = min(10, total_vlans)

    return f"VLAN Topology (showing {displayed_vlans} of {total_vlans} VLANs):\n\n" + "\n---\n".join(formatted_vlans)


# File Management Tools

@mcp.tool()
async def get_file_namespaces() -> str:
    """Get available file namespaces."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/file/namespace"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch file namespaces or no namespaces found."

    namespaces = data["response"]

    formatted_namespaces = []
    for namespace in namespaces:
        formatted = f"""
Namespace: {namespace.get('nameSpace', 'Unknown')}
Permission: {namespace.get('permission', 'Unknown')}
"""
        formatted_namespaces.append(formatted)

    return "\n---\n".join(formatted_namespaces)


@mcp.tool()
async def get_files(namespace: str, limit: int = 10, offset: int = 0) -> str:
    """Get files from a specific namespace.

    Args:
        namespace: File namespace
        limit: Maximum number of files to return (default: 10)
        offset: Pagination offset (default: 0)
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/file/{namespace}?limit={limit}&offset={offset}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch files from namespace '{namespace}' or no files found."

    files = data["response"]
    if not files:
        return f"No files found in namespace '{namespace}'."

    formatted_files = []
    for file in files:
        formatted = f"""
ID: {file.get('id', 'Unknown')}
Name: {file.get('name', 'Unknown')}
Namespace: {file.get('nameSpace', 'Unknown')}
File Size: {file.get('fileSize', 'Unknown')} bytes
File Format: {file.get('fileFormat', 'Unknown')}
Created At: {file.get('createdTime', 'Unknown')}
"""
        formatted_files.append(formatted)

    return "\n---\n".join(formatted_files)


@mcp.tool()
async def get_file_by_id(file_id: str) -> str:
    """Get file details by ID.

    Args:
        file_id: File ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/file/{file_id}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch file with ID {file_id}."

    file = data["response"]

    return f"""
File Details:
ID: {file.get('id', 'Unknown')}
Name: {file.get('name', 'Unknown')}
Namespace: {file.get('nameSpace', 'Unknown')}
File Size: {file.get('fileSize', 'Unknown')} bytes
File Format: {file.get('fileFormat', 'Unknown')}
MD5 Checksum: {file.get('md5Checksum', 'Unknown')}
SHA1 Checksum: {file.get('sha1Checksum', 'Unknown')}
Created At: {file.get('createdTime', 'Unknown')}
"""


# Language Management Tools

@mcp.tool()
async def get_languages() -> str:
    """Get available languages in Catalyst Center."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/languages"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch languages or no languages found."

    languages = data["response"]
    if not languages:
        return "No languages found."

    formatted_languages = []
    for language in languages:
        formatted = f"""
Language: {language.get('languageName', 'Unknown')}
Code: {language.get('code', 'Unknown')}
Version: {language.get('version', 'Unknown')}
Status: {language.get('status', 'Unknown')}
"""
        formatted_languages.append(formatted)

    return "\n---\n".join(formatted_languages)


@mcp.tool()
async def get_default_language() -> str:
    """Get the default language in Catalyst Center."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/languages/default"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch default language."

    language = data["response"]

    return f"""
Default Language:
Language: {language.get('languageName', 'Unknown')}
Code: {language.get('code', 'Unknown')}
Version: {language.get('version', 'Unknown')}
Status: {language.get('status', 'Unknown')}
"""


# IoT Tools

@mcp.tool()
async def get_iot_sensors() -> str:
    """Get IoT sensors."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/iot/sensor"

    data = await client.request("GET", endpoint)

    if not data:
        return "Unable to fetch IoT sensors or no sensors found."

    sensors = data
    if not sensors:
        return "No IoT sensors found."

    formatted_sensors = []
    for sensor in sensors[:10]:  # Limit to 10 sensors for readability
        formatted = f"""
Name: {sensor.get('name', 'Unknown')}
Type: {sensor.get('type', 'Unknown')}
Location: {sensor.get('location', 'Unknown')}
MAC Address: {sensor.get('macAddress', 'Unknown')}
Status: {sensor.get('status', 'Unknown')}
"""
        formatted_sensors.append(formatted)

    total_sensors = len(sensors)
    displayed_sensors = min(10, total_sensors)

    return f"IoT Sensors (showing {displayed_sensors} of {total_sensors}):\n\n" + "\n---\n".join(formatted_sensors)


@mcp.tool()
async def get_sensor_details(sensor_id: str) -> str:
    """Get IoT sensor details.

    Args:
        sensor_id: Sensor ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/iot/sensor/{sensor_id}"

    data = await client.request("GET", endpoint)

    if not data:
        return f"Unable to fetch details for sensor with ID {sensor_id}."

    sensor = data

    return f"""
Sensor Details:
Name: {sensor.get('name', 'Unknown')}
Type: {sensor.get('type', 'Unknown')}
Location: {sensor.get('location', 'Unknown')}
MAC Address: {sensor.get('macAddress', 'Unknown')}
IP Address: {sensor.get('ipAddress', 'Unknown')}
Status: {sensor.get('status', 'Unknown')}
Last Seen: {sensor.get('lastSeen', 'Unknown')}
Battery Level: {sensor.get('batteryLevel', 'Unknown')}
Signal Strength: {sensor.get('signalStrength', 'Unknown')}
"""


# Backup and Restore Tools

@mcp.tool()
async def get_backup_history() -> str:
    """Get backup history of Catalyst Center."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/backup"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return "Unable to fetch backup history or no backups found."

    backups = data["response"]
    if not backups:
        return "No backup history found."

    formatted_backups = []
    for backup in backups:
        formatted = f"""
Backup ID: {backup.get('id', 'Unknown')}
Name: {backup.get('name', 'Unknown')}
Status: {backup.get('status', 'Unknown')}
Created At: {backup.get('createdTime', 'Unknown')}
File Size: {backup.get('fileSize', 'Unknown')}
Tags: {', '.join(backup.get('tags', []) or ['None'])}
"""
        formatted_backups.append(formatted)

    return "\n---\n".join(formatted_backups)


@mcp.tool()
async def get_backup_details(backup_id: str) -> str:
    """Get details of a specific backup.

    Args:
        backup_id: Backup ID
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = f"/dna/intent/api/v1/backup/{backup_id}"

    data = await client.request("GET", endpoint)

    if not data or "response" not in data:
        return f"Unable to fetch details for backup with ID {backup_id}."

    backup = data["response"]

    return f"""
Backup Details:
ID: {backup.get('id', 'Unknown')}
Name: {backup.get('name', 'Unknown')}
Description: {backup.get('description', 'None')}
Status: {backup.get('status', 'Unknown')}
Created At: {backup.get('createdTime', 'Unknown')}
File Size: {backup.get('fileSize', 'Unknown')} bytes
Encryption Key: {'Yes' if backup.get('encryptionKey', '') else 'No'}
Tags: {', '.join(backup.get('tags', []) or ['None'])}
"""