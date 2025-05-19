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

    endpoint = "/dna/intent/api/v1/dnac-release"
    data = await client.request("GET", endpoint)
    version = data["response"]
    if not data:
        return "Unable to fetch Catalyst Center version."
    
    return f"""
Catalyst Center Version Information:
Maglev API Version: {data.get('version', 'Unknown')}
Installed Version: {version.get('installedVersion', 'Unknown')}
Maglev Version: {version.get('systemVersion', 'Unknown')}

"""


@mcp.tool()
async def get_client_detail(mac_address: str) -> str:
    """Get detailed information about a specific client.

    Args:
        mac_address: Client MAC address
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/client-detail"
    params = {
        "macAddress": mac_address
    }
    
    data = await client.request("GET", endpoint, params=params)
    
    if not data or "detail" not in data:
        return f"Unable to fetch details for client with MAC address {mac_address}."
    
    client_detail = data["detail"]
    
    return f"""
Client Details:
MAC Address: {client_detail.get('hostMac', 'Unknown')}
IP Address: {client_detail.get('hostIpV4', 'Unknown')}
Host Name: {client_detail.get('hostName', 'Unknown')}
Connected Device: {client_detail.get('connectedDevice', {})[0].get("name", "Unknown")}
Connection Status: {client_detail.get('connectionStatus', 'Unknown')}
Connection Type: {client_detail.get('hostType', 'Unknown')}
SSID: {client_detail.get('ssid', 'N/A')}
Frequency: {client_detail.get('frequency', 'N/A')}
Onboarding Time: {client_detail.get('onboardingTime', 'Unknown')}
Last Updated Time: {client_detail.get('lastUpdated', 'Unknown')}
Issues: {client_detail.get("issueCount", "Unknown")}
"""


@mcp.tool()
async def get_client_enrichment(mac_address: str) -> str:
    """Get enrichment information about a specific client.

    Args:
        mac_address: Client MAC address
    """
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/client-enrichment-details"
    headers = {
        "entity_type": "mac_address",
        "entity_value": mac_address
    }
    
    data = await client.request("GET", endpoint, headers=headers)
    
    if not data or not data[0]:
        return f"Unable to fetch enrichment details for client with MAC address {mac_address}."
    
    enrichment = data[0]["userDetails"]
    
    return f"""
Client Enrichment Details:
User ID: {enrichment.get('userId', 'Unknown')}
Host Mac: {enrichment.get('hostMac', 'Unknown')}
Host Name: {enrichment.get('hostName', 'Unknown')}
Host Type: {enrichment.get('hostType', 'Unknown')}
Host OS: {enrichment.get('hostOs', 'Unknown')}
Host Version: {enrichment.get('hostVersion', 'Unknown')}
Host Vendor: {enrichment.get('deviceVendor', 'Unknown')}
Auth Type: {enrichment.get('authType', 'Unknown')}
SSID: {enrichment.get('ssid', 'Unknown')}
Location: {enrichment.get('location', 'Unknown')}
Connected Device: {enrichment.get('clientConnection', "Unknown")}
Last Updated Time: {enrichment.get('lastUpdated', 'Unknown')}
"""


@mcp.tool()
async def get_discovery_jobs() -> str:
    """Get all discovery jobs."""
    if not client:
        return "Not connected to Catalyst Center. Use connect() first."

    endpoint = "/dna/intent/api/v1/discovery"
    data = await client.request("GET", endpoint)
    
    if not data or "response" not in data:
        return "Unable to fetch discovery jobs or no jobs found."
    
    jobs = data["response"]
    if not jobs:
        return "No discovery jobs found."
    
    formatted_jobs = []
    for job in jobs:
        formatted = f"""
Discovery Job: {job.get('name', 'Unknown')}
ID: {job.get('id', 'Unknown')}
Status: {job.get('discoveryStatus', 'Unknown')}
Progress: {job.get('discoveryStep', 'Unknown')}
IP Range: {job.get('ipAddressList', 'Unknown')}
Protocol Order: {job.get('protocolOrder', 'Unknown')}
Discovery Type: {job.get('discoveryType', 'Unknown')}
Number of Devices: {job.get('numDevices', 'Unknown')}
"""
        formatted_jobs.append(formatted)
    
    return "\n---\n".join(formatted_jobs)


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')