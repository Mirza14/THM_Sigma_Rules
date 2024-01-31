Sigma

GitHub Repo: https://github.com/SigmaHQ/sigma
YAML Guide: https://www.tutorialspoint.com/yaml/yaml_quick_guide.htm
Sigma Docs: https://sigmahq.io/docs/guide/getting-started.html

==============
What is Sigma?

SOC analysts are tasked with collecting, analysing and extracting as much usable information from logs and using it to build detection queries and searches for their environments. However, on most occasions, it becomes challenging to standardise investigations and have the ability to share them with other analysts for detection enrichment. Sharing Indicators of compromise (IOC) and signatures may not be enough, as log events are often left unattended. Here is where Sigma seeks to bridge the gap.
==============

==============
Sigma Use Cases

* To make detection methods and signatures shareable alongside IOCs and Yara rules.
* To write SIEM searches that avoid vendor lock-in.
* To share signatures with threat intelligence communities.
* To write custom detection rules for malicious behaviour based on specific conditions.
==============

==============
Sigma Development Process

As a SOC analyst, the process of using Sigma to write up your detection rules will involve understanding the elements mentioned below:

* Sigma Rule Format: Generic structured log descriptions written in YAML.
* Sigma Converter: A set of python scripts that will process the rules on the backend and perform custom field matching based on specified SIEM query language.
* Machine Query: Resulting search query to filter out alerts during investigations. The query will be based on the specified SIEM.
==============

==============
Sigma Rule Syntax

YAML, a data serialisation language that is human-readable and useful for managing data. It's often used as a format for configuration files, but its object serialisation abilities make it a substitute for languages like JSON.
Common factors to note about YAML files are:
* YAML is case-sensitive.
* Files should have the .yml extension.
* Spaces are used for indentation and not tabs.
* Comments are attributed using the # character.
* Key-value pairs are denoted using the colon : character.
* Array elements are denoted using the dash - character.

Sigma Syntax

Following the understanding of using YAML for Sigma rules, the syntax defines various mandatory and optional fields that go into every rule.

> Title: Names the rule based on what it is supposed to detect. This should be short and clear.

> ID: A globally unique identifier mainly used by the developers of Sigma to maintain the order of identification for the rules submitted to the public repository, found in UUID format. > Related: You may also add references to related rule IDs using the related attribute, making it easier to form relationships between detections. These relations would fall under the following types:
    * Derived: This will describe that the rule has sprung from another rule, which may still be active.
    * Obsolete: This will indicate that the listed rule is no longer being used.
    * Merged: This will indicate that the rule combines linked rules.
    * Renamed: This indicates the rule was previously identified under a different ID but has now been changed due to changes in naming schemes or avoiding collisions. 
    * Similar: This attribute points to corresponding rules, such as indicating the same detection content applied to different log sources.
> Status: Describes the stage in which the rule maturity is at while in use. There are five declared statuses that you can use:
    * Stable: The rule may be used in production environments and dashboards.
    * Test: Trials are being done to the rule and could require fine-tuning.
    * Experimental: The rule is very generic and is being tested. It could lead to false results, be noisy, and identify interesting events.
    * Deprecated: The rule has been replaced and would no longer yield accurate results. The related field is used to create associations between the current rule and one that has been deprecated.
    * Unsupported: The rule is not usable in its current state (unique correlation log, homemade fields).

> Description: Provides more context about the rule and its intended purpose. With the rule, you can be as verbose as possible on the malicious activity you intend to detect.

> Logsource: Describes the log data to be used for the detection. It consists of other optional attributes:
* Product: Selects all log outputs of a particular product. Examples are Windows, Apache.
* Category: Selects the log files written by the selected product. Examples are firewall, web, and antivirus.
* Service: Selects only a subset of the logs from the selected product. Examples are sshd on Linux or Security on Windows.
* Definition: Describes the log source and any applied configurations.

> Detection: A required field in the detection rule describes the parameters of the malicious activity we need an alert for. The parameters are divided into two main parts: the search identifiers - the fields and values that the detection should be searching for -  and condition expression - which sets the action to be taken on the detection, such as selection or filtering.

> FalsePositives: A list of known false positive outputs based on log data that may occur.

> Level: Describes the severity with which the activity should be taken under the written rule. The attribute comprises five levels: Informational -> Low -> Medium -> High -> Critical

> Tags: Adds information that may be used to categorise the rule. Tags may include values for CVE numbers and tactics and techniques from the MITRE ATT&CK framework.
==============

==============
Search Identifiers and Condition Expressions - Detection Condition to alert on Malicious/Suspicious Activity:

Detection section of the rule describes what you intend to search for within the log data and how the selection and filters are to be evaluated. The definition of the search identifiers can comprise two data structures - lists and maps - which dictate the order in which the detection would be processed.

When the identifiers are provided using lists, they will be presented using strings linked with a logical 'OR' operation. Mainly, they will be listed using hyphens (-).

On the other hand, maps comprise key/value pairs where the key matches up to a field in the log data while the value presented is a string or numeral value to be searched for within the log. Maps follow a logical 'AND' operation.

Example 1:
The selection term forms the map, and the rule intends to match on Image|endswith either of the values listed, AND CommandLine contains either value listed. This example shows how maps and lists can be used together when developing detections. 

It should be noted that endswith and contains are value modifiers, and two lists are used for the search values, where one of each group has to match for the rule to initiate an alert. 

detection:
  selection:
    Image|endswith:
         - '/rm' # covers /rmdir as well
         - '/shred'
    CommandLine|contains:
         - '/var/log'
         - '/var/spool/mail'
  condition: selection

The value modifier, it is worth noting that they are appended after the field name with a pipe character (|), and there are two types of value modifiers:
* Transformation modifiers: These change the values provided into different values and can modify the logical operations between values. They include:
    * contains: The value would be matched anywhere in the field.
    * all: This changes the OR operation of lists into an AND operation. This means that the search conditions has to match all listed values.
    * base64: This looks at values encoded with Base64.
    * endswith: With this modifier, the value is expected to be at the end of the field. For example, this is representative of *\cmd.exe.
    * startswith: This modifier will match the value at the beginning of the field. For example, power*.
* Type modifiers: These change the type of the value or sometimes even the value itself. Currently, the only usable type modifier is re, which is supported by Elasticsearch queries to handle the value as a regular expression.

For conditions, this is based on the names set for your detections, such as selection and filter, and will determine the specification of the rule based on a selected expression. Some of the terms supported include:
* Logical AND/OR
* 1/all of search-identifier
* 1/all of them
* not

Example 2:
An example of these conditional values can be seen in the extract below from the Remote File Copy rule, where the detection seeks to look for either of the tools: scp, rsync or sftp and with either filter values @ or :

detection:
  tools:
         - 'scp'
         - 'rsync'
         - 'sftp'
  filter:
         - '@'
         - ':'
  condition: tools and filter

Example 3:
To showcase a combination of the conditional expressions can be seen in the extract below from the Run Once Persistence Registry Event rule, where the detection seeks to look for values on the map that start and end with various registry values while filtering out Google Chrome and Microsoft Edge entries that would raise false positive alerts.

detection:
  selection:
    TargetObject|startswith: 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components'
    TargetObject|endswith: '\StubPath'
  filter_chrome:
    Details|startswith: '"C:\Program Files\Google\Chrome\Application\'
    Details|endswith: '\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level'
  filter_edge:
    Details|startswith:
    - '"C:\Program Files (x86)\Microsoft\Edge\Application\'
    - '"C:\Program Files\Microsoft\Edge\Application\'
    Details|endswith: '\Installer\setup.exe" --configure-user-settings --verbose-logging --system-level --msedge 
    --channel=stable'
  condition: selection and not 1 of filter_*
==============
