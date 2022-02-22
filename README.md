## About the connector

Provides JunOS REST API Integration covering Juniper MX, PTX, QFX, T and SRX Series platforms
<p>This document provides information about the Juniper JunOS Connector, which facilitates automated interactions, with a Juniper JunOS server using FortiSOAR&trade; playbooks. Add the Juniper JunOS Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Juniper JunOS.</p>

### Version information
Connector Version: 1.0.0


Authored By: Fortinet CSE

Certified: No

## Installing the connector
<p>From FortiSOAR&trade; 5.0.0 onwards, use the <strong>Connector Store</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.<br>You can also use the following <code>yum</code> command as a root user to install connectors from an SSH session:</p>
`yum install cyops-connector-juniper-junos`

## Prerequisites to configuring the connector
- You must have the URL of Juniper JunOS server to which you will connect and perform automated operations and username/password credentials to access that appliance.
- The FortiSOAR&trade; server should have outbound connectivity to port 3443 (or the configured port) on the Juniper JunOS Appliance.

## Minimum Permissions Required
- `System` for operational mode actions (get)
- `System-control` for configuration mode (add/delete)

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)

### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Juniper JunOS</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations&nbsp;</strong> tab enter the required configuration details:&nbsp;</p>
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody>
<tr><td>Device URL<br></td><td>Management IP address or FQDN of the JunOS appliance<br>
<tr><td>Port<br></td><td>JunOS REST API TCP port, default is 3443<br>
<tr><td>Username<br></td><td>JunOS Username<br>
<tr><td>Password<br></td><td>JunOS Password<br>
<tr><td>Verify SSL<br></td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set as True.<br></td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function<br></th><th>Description<br></th><th>Annotation and Category<br></th></tr></thead><tbody><tr><td>Run Operation Command<br></td><td>Run JunOS CLI in operation mode to fetch data such as routing table, interfaces system info...etc<br></td><td>op_action <br/>Information<br></td></tr>
<tr><td>Run Configuration Command<br></td><td>Update JunOS Configuration<br></td><td>config_action <br/>Configuration<br></td></tr>
<tr><td>Get Address Set<br></td><td>Get Address Set entries from global address book<br></td><td>get_address_set <br/>Configuration<br></td></tr>
<tr><td>Add an Object to Global Address Set<br></td><td>Add and IP address, an FQDN or a whildcard to an address set on the Global address book. 1024 entries Max<br></td><td>add_to_address_book <br/>Configuration<br></td></tr>
<tr><td>Delete Object from Global Address Set<br></td><td>Deletes and IP address, an FQDN or a whildcard from the Global address book<br></td><td>delete_from_address_set <br/>Configuration<br></td></tr>
<tr><td>Get Prefix List<br></td><td>Get Prefix List entries<br></td><td>get_prefix_list <br/>Configuration<br></td></tr>
<tr><td>Add Address(es) to a Prefix List<br></td><td>Add IP address(es) to a prefix-list. 85325 entries Max<br></td><td>add_to_prefix_list <br/>Configuration<br></td></tr>
<tr><td>Delete Address(es) from a Prefix List<br></td><td>Delete IP address(es) from a prefix-list<br></td><td>delete_from_prefix_list <br/>Configuration<br></td></tr>
</tbody></table>

### operation: Run Operation Command
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody>
<tr><td>Method<br></td><td>RPC Command to run<br></td>
</tr><tr><td>Custom Method<br></td><td>if the command is not in the list above (Method) you can use a custom one as a Custom method. To get the exact command syntax refer to this example on JunOS: **show route|display xml rpc** <br>
</td></tr><tr><td>Method Parameters<br></td><td>Method parameters in JSON. For example, if the action is get-interface-information the parameter(s) could be **{'interface-name':'ge-0/0/0'}**<br>
</td></tr></tbody></table>


#### Output
The output contains the following populated JSON schema: <JSON Output>

### operation: Run Configuration Command
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody>
<tr><td>Request Payload<br></td><td>HTTP/POST XML Payload as documented here [https://www.juniper.net/documentation/us/en/software/junos/rest-api/rest-api.pdf](https://www.juniper.net/documentation/us/en/software/junos/rest-api/rest-api.pdf)<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>

### operation: Get Address Set
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Address Set<br></td><td>Name of the address set<br>
</td></tr><tr><td>Get Entries Count<br></td><td>If checked, returns only entries count instead of the entries data<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>


### operation: Add an Object to Global Address Set
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Address Set<br></td><td>Name of the address set<br>
</td></tr><tr><td>Object Types<br></td><td>Type of the object(s) to add, only one type is supported at a time. Wildcard format is: A.B.C.D/E.F.G.H<br>
</td></tr><tr><td>Object(s) To Add<br></td><td>IP address, an FQDN or a wildcard to add, for multiple entries use CSV format such as host1.domain.com,host2.domain.com if the type is dns-name<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>


### operation: Delete Object from Global Address Set
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Address set<br></td><td>Name of the address set<br>
</td></tr><tr><td>Object Types<br></td><td>Type of the object(s) to delete, only one type is supported at a time<br>
</td></tr><tr><td>Object(s) To Delete<br></td><td>IP address, an FQDN or a wildcard to delete, for multiple entries use CSV format such as host1.domain.com,host2.domain.com if the type is dns-name<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>


### operation: Get Prefix List
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Prefix List<br></td><td>Name of the Prefix List<br>
</td></tr><tr><td>Get Entries Count<br></td><td>If checked, returns only entries count instead of the entries data<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>


### operation: Add Address(es) to a Prefix List
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Prefix List<br></td><td>Name of the Prefix List<br>
</td></tr><tr><td>Address(es) To Add<br></td><td>IPv4 or IPv6 Address or Addresses (in CSV) to add to the prefix list<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>


### operation: Delete Address(es) from a Prefix List
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Prefix List<br></td><td>Name of the Prefix List<br>
</td></tr><tr><td>Address(es) To Delete<br></td><td>IPv4 or IPv6 Address or Addresses (in CSV) to delete from the prefix list<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema: <JSON Output>


## Included playbooks
The `Sample - juniper-junos - 1.0.0` playbook collection comes bundled with the Juniper JunOS connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR<sup>TM</sup> after importing the Juniper JunOS connector.

