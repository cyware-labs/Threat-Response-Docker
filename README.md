# Cyware Threat Response Docker - All in one docker image for Threat Intelligence Analysts

**Table of contents**
------------
- Introduction
- Threat Intelligence Life Cycle
- Tool Categories in the Cyware Threat Response Docker
- Tool List
- Cyware Contributed Tools
- Docker Installation
    -   Supported Operating Systems
    -   Prerequisites
    -   Docker Installation Procedure
    -   Cyware Threat Response Docker Installation Procedure
- API References
- Additional Tool References and Credits
- Contribution
- License

# Introduction

Cyber Threat Intelligence (CTI) has become an important concept in the rapidly evolving cyber threat landscape. With organizations continuously facing complex and malicious cyber threats, CTI gets used widely to counter the rise of cyberattacks. There are many tools and standards proposed and underdevelopment in CTI. While some of them overlap with each other, many of them were used for a specific objective. As a result, an organization ends up combining more than one tool and standards in their CTI program to make it fit with their specific requirement.

CTI tools have grown exponentially over the last decade. But there has been no way to aggregate all these tools into a singular, lightweight platform that is easy to set up, requirement friendly, and scalable.

Cyware&#39;s Threat Response Docker provides a solution by solving what is required. It contains a collection of top-notch tools revolving around automation focused on automating the threat intelligence lifecycle.

# Threat Intelligence Life Cycle

Threat Intelligence often follows a series of steps that can be referred to as its lifecycle [originally developed by the CIA] which often helps security analysts to efficiently analyze and investigate threats. The threat response docker is mapped to this Threat Intelligence Lifecycle with categories mapped to the different phases.

The various phases of the Threat Intelligence Lifecycle are:

**Direction and Planning:** In this phase, the user/ organization/ enterprise defines objectives and plans for collecting and analyzing threat intelligence.

**Collection:** After defining objectives, we begin the process of collecting the intelligence data. We can either collect this data from internal sources, open-source feeds or proprietary feeds from companies such as Kaspersky, FireEye, Alienvault, etc. This is the data that the security analyst will analyze and act upon.

**Processing:** Not all data collected would be of the same format or machine ingestible. In this phase, we convert all data that is received into a standard, machine ingestible format for easier use.

**Analysis and production:** After collecting and processing this data, we further move on to analyze and act on this information. The above said analysis may include but is not limited to indicator validation, indicator enrichment, indicator de duplication, indicator verification, and indicator actioning.

**Dissemination:** After analyzing various threats and indicators, organizations can share this information with other companies for the benefit of the community.

**Feedback:** After completing the above life cycle, the organization reflects on performed actions and reaffirms/ modify procedures implemented.

# Tool Categories in the Cyware Threat Response Docker

The tools in the threat response docker are categorized into 5 important categories based on their role in the Threat Intelligence Lifecycle.

**Collect:** This category relates to the collection phase of the threat intelligence lifecycle and is aimed at providing a method to connect and collect intelligence data from various sources, both open source and freemium.

**Extract:** This category relates to the processing phase of the threat intelligence lifecycle, where we take data collected such as reports, indicators, etc, and extract and standardize them into ingestible formats.

**Analyze:** This category relates to the analysis phase of the threat intelligence lifecycle, providing tools and methods to analyze the above collected and standardized indicators.

**OSINT:** This category of tools provides analysts with further investigative capabilities by allowing them to analyze data using open source intelligence tools and techniques.

**STIX:** This category relates to the dissemination stage of the intelligence lifecycle, allowing an analyst to create, modify, standardize, and share intelligence via STIX objects. Further reference to STIX can be found [here](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html).

# Tool List

| **Category** | **Tool** | **Description** |
| --- | --- | --- |
| **Analyze** | Sooty | All-in-one Command Line Interface (CLI) tool to automate and speed up SOC workflow |
| **Analyze** | malware-analysis-scripts | Collection of scripts for different malware analysis tasks |
| **Analyze** | QRadio | For combining different enrichment sources and reporting matches |
| **Analyze** | automater | For automating Indicator enrichment |
| **Analyze** | Volatility | Volatility is a memory forensics framework |
| **Analyze** | IOC enricher | Local script developed by us to check an IP or a series of IPs against common blacklists |
| **Analyze** | Icewater | Collection of 12500 yara rules |
| **Analyze** | harpoon | Tool to interface with multiple enrichment sources |
| **Collect** | combine | To get threat intel data from different sources and save it to a csv file |
| **Collect** | threatingestor | To collect data from multiple threat intelligence feeds |
| **Collect** | APT notes | A file containing links to APT reports |
| **Collect** | ConnectorBox | a set of scripts to connect to common sources |
| **Extract** | ioc-finder | For parsing indicators of compromise from text |
| **Extract** | bro-intel-generator | For generating bro intel reports from pdf reports |
| **Extract** | Hachoir | Hachoir is a Python library to view and edit a binary stream field by field |
| **Extract** | OSSEM | Facilitates the normalization of data sets by providing a standard way to parse security event logs |
| **Extract** | FOCA | FOCA is a tool used mainly to scan documents and find metadata and hidden information from them |
| **OSINT** | Ghunt | A tool to enumerate and find more details regarding google accounts |
| **OSINT** | OnionScan | A tool to perform analysis on the darkweb |
| **STIX** | openioc-to-stix | Tool to generate STIX Indicator Output from an OpenIOC v1.0 XML File |
| **STIX** | stix-validator | A Python tool and API that validates STIX and CybOX XML instance documents |
| **STIX** | cti-python-stix2 | Python Library for STIX 2 |
| **STIX** | cti-stix-elevator | Tool to convert STIX 1.x XML to STIX 2.0 or 2.1 JSON |
| **STIX** | cti-stix-slider | Tool to convert STIX 2.x JSON to STIX 1.x XML |
| **STIX** | cti-pattern-matcher | tool for matching STIX Observed Data content against patterns used in STIX Indicators |
| **STIX** | STIXOps | A script offering multiple STIX conversion and interaction functionalities |
| **STIX** | Stix generator | A tool to generate STIX objects |

## Cyware Contributed Tools

1. **STIXOps.** A script offering multiple STIX conversion and interaction functionalities
2. **ConnectorBox.** A set of scripts to connect to common sources
3. **IOC enricher.** A local script developed to check an IP or a series of IPs against common blacklists

# Docker Installation

## Supported Operating Systems

- Windows
- MAC
- Linux

## Prerequisites

The following prerequisites are required for successful installation and functioning of the Docker application.

- Storage Required: 2.5 GB
- Storage Recommended: 2.5 GB

## Docker Installation Procedure

We recommend to download the latest version of Docker as it stays updated with the latest features and security patches. The installation package can be downloaded from the below link.

[https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)

## Cyware Threat Response Docker Installation Procedure?

You can either run the build.sh file to automatically fetch the image for you or follow the steps below

1. docker run -dit --name trd -p 8081:80 cyware/threatresponsedocker
2. docker exec -it trd bash

**Note:** This docker exposes port 8081 as a HTTP server for allowing easy transfer of files from inside the docker to outside. Do note that this is 1 way and does not allow data transfer from outside the docker to inside.

# API Reference

While the Threat ResponseDocker works without any additional API keys, to harness the full potential of the Threat Response Docker, it is recommended that you paste in the required keys. The list of API services being used and links to register the keys are given below

- [AlienVault OTX](https://otx.alienvault.com/)
- [BinaryEdge](https://www.binaryedge.io/)
- [Censys](https://censys.io/register)
- [CertSpotter](https://sslmate.com/certspotter/pricing)
- [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/)
- [Farsight Dnsdb](https://www.farsightsecurity.com/dnsdb-community-edition/)
- [FullContact](https://dashboard.fullcontact.com/register)
- [GreyNoise](https://greynoise.io/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Hunter](https://hunter.io/users/sign_up)
- [Hybrid Analysis](https://www.hybrid-analysis.com/apikeys/info)
- [IBM Xforce Exchange](https://exchange.xforce.ibmcloud.com/settings/api)
- [ipinfo.io](https://ipinfo.io/)
- [MalShare](https://malshare.com/register.php)
- [NumVerify](https://numverify.com/)
- [OpenCage](https://opencagedata.com/)
- [PassiveTotal](https://community.riskiq.com/registration)
- [Permacc](https://perma.cc/)
- [Security Trails](https://securitytrails.com/)
- [Shodan](https://account.shodan.io/register)
- [SpyOnWeb](https://api.spyonweb.com/)
- Telegram
- [Total Hash](https://totalhash.cymru.com/contact-us/)
- [Twitter](https://developer.twitter.com/en/docs/ads/general/guides/getting-started)
- [UrlHaus](https://urlhaus.abuse.ch/api/#account)
- Virus Total
- [Zetalytics](https://zetalytics.com/)
- Emerging Threat Compromised IP Feed
- Emerging Threat Blocked IP feed
- Project HoneyNet IP feed
- SANS IP feed
- [BlockList.de](http://blocklist.de/) IP feed
- AlienVault IP reputation feed
- [Abuse.ch](http://abuse.ch/) Zeus Tracker IP feed
- Malc0de Blacklist IP feed
- Malware Domain List C&amp;C IPs
- Talos Blacklist IP feed
- CI Army IP feed
- [Nothink.org](http://nothink.org/) Honeypot DNS IPs
- [Nothink.org](http://nothink.org/) Http CC IPs
- [Nothink.org](http://nothink.org/) IRC boINVESTIGATEt IPs
- [Nothink.org](http://nothink.org/) SSH bruteforce IPs
- TOR Exit node IP&quot;: tor\_exit\_nodes
- Korean &amp; Chinese Spam IP feed
- Bad-IPs DB for last 1000 hours
- [Botvrij.eu](https://botvrij.eu/)
- [myip.ms](https://myip.ms/)
- [Firehol](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/nixspam.ipset)
- [URLScan.io API Key](https://urlscan.io/about-api/)
- [AbuseIPDB API Key](https://www.abuseipdb.com/api)
- [PhishTank API Key](https://www.phishtank.com/api_info.php)
- C[ookies](https://get.google.com/albumarchive/)

# Additional Tool References

Below you can find further reference to various tools used in the Threat Response Docker.

| **Tool** | **Link** |
| --- | --- |
| Sooty | [https://github.com/TheresAFewConors/Sooty](https://github.com/TheresAFewConors/Sooty) |
| malware-analysis-scripts | [https://github.com/deadbits/malware-analysis-scripts](https://github.com/deadbits/malware-analysis-scripts) |
| QRadio | [https://github.com/QTek/QRadio](https://github.com/QTek/QRadio) |
| automater | [https://github.com/1aN0rmus/TekDefense-Automater](https://github.com/1aN0rmus/TekDefense-Automater) |
| Volatility | [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) |
| IOC enricher | [https://github.com/cyware-labs/IOC-Enricher] |
| Icewater | [https://github.com/SupportIntelligence/Icewater](https://github.com/SupportIntelligence/Icewater) |
| harpoon | [https://github.com/Te-k/harpoon](https://github.com/Te-k/harpoon) |
| combine | [https://github.com/mlsecproject/combine](https://github.com/mlsecproject/combine) |
| threatingestor | [https://github.com/InQuest/ThreatIngestor](https://github.com/InQuest/ThreatIngestor) |
| APT notes | [https://github.com/aptnotes](https://github.com/aptnotes) |
| ConnectorBox | [https://github.com/cyware-labs/ConnectorBox] |
| ioc-finder | [https://github.com/fhightower/ioc-finder](https://github.com/fhightower/ioc-finder) |
| bro-intel-generator | [https://github.com/exp0se/bro-intel-generator](https://github.com/exp0se/bro-intel-generator) |
| Hachoir | [https://github.com/vstinner/hachoir](https://github.com/vstinner/hachoir) |
| OSSEM | [https://github.com/OTRF/OSSEM](https://github.com/OTRF/OSSEM) |
| FOCA | [https://github.com/ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA) |
| Ghunt | [https://github.com/mxrch/GHunt](https://github.com/mxrch/GHunt) |
| OnionScan | [https://github.com/s-rah/onionscan](https://github.com/s-rah/onionscan) |
| openioc-to-stix | [https://github.com/STIXProject/openioc-to-stix](https://github.com/STIXProject/openioc-to-stix) |
| stix-validator | [https://github.com/STIXProject/stix-validator](https://github.com/STIXProject/stix-validator) |
| cti-python-stix2 | [https://github.com/oasis-open/cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) |
| cti-stix-elevator | [https://github.com/oasis-open/cti-stix-elevator](https://github.com/oasis-open/cti-stix-elevator) |
| cti-stix-slider | [https://github.com/oasis-open/cti-stix-slider](https://github.com/oasis-open/cti-stix-slider) |
| cti-pattern-matcher | [https://github.com/oasis-open/cti-pattern-matcher](https://github.com/oasis-open/cti-pattern-matcher) |
| STIXOps | [https://github.com/cyware-labs/STIXOps] |
| Stix generator | [https://pypi.org/project/stix2-generator/](https://pypi.org/project/stix2-generator/) |
| HTTPD | [https://hub.docker.com/_/httpd](https://hub.docker.com/_/httpd) |

**Note:** Some tools will not work in their full functionality till the API keys have been updated in its respective areas of origin. Refer to the ReadMe link above for tutorials on each of the tools used.

# Contribution

We are always on the lookout for new tools and welcome all suggestions! In particular we are looking for open source tool suggestions which you think will extend the functionality of the Threat Response Docker.

The best way to do so is open an issue. We have a template for tool suggestions and would love to hear your thoughts on it!

# Licensing Details

MIT LICENSE

Copyright (c) <2021> <Cyware Labs, inc.>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice (including the next paragraph) shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL CYWARE LABS, INC. OR ITS AFFILIATES BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
