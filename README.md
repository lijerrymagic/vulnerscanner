# vulnerscanner
A chrome extension to scan vulnerabilities

Problem / Motivation

Nowadays, websites are vulnerable. Attackers can easily exploit the vulnerabilities existing on the websites and do potential harm to users. However, there are no ways for ordinary users to detect those potential threats instantly. On the other hand, for advanced users, such as developers, when they are developing their own websites, they want to know if their websites are under threat.

Proposed method

Therefore, our tool will help users to identify those vulnerabilities and potential risks that those websites may have. There will be two use cases. For ordinary users, it can warn them with the detected threats. And for developers, they can use this tool as an integration tool to either scan the website without running any scanners themselves, or check the security information of the website, such as if the website has the threats of SQL injection or the official DNS information.

Process / Design

To have a working chrome extension, we will have a frontend user interface handling and displaying security information, and a backend server that deals with requests coming from the extension.

Frontend
Taking advantage of the React framework, we can quickly build a frontend application that fetches responses from the backend and displays them on the page.

Backend
ZAP

The OWASP Zed Attack Proxy (ZAP) is one the most popular open source tools for web application security testing. ZAP offers the functionality ‘Active Scan’, which actually acts like a real attack, actual damage can be done to a site’s functionality, data, etc. It can be used to test if a website has the risks of SQL injection and Cross Site Scripting. ZAP supports a powerful API and command line functionality, so we run ZAP on the server as one of the function modules of the backend.

Nmap

Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing. It supports the tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, and dozens of other characteristics. Nmap will provide our tool the capability to check the open ports on the server of the website, which will be concerned by the developers. Nmap will also 
FastAPI

FastAPI is a modern, fast (high-performance), web framework for quickly building  and exposing APIs

Using FastAPI, within each of the endpoints we are exposing, desired responses are fetched in different ways by using tools stated above. Take one of the APIs “<server_domain_name>/scan” as an example. We internally used the built-in Python API of ZAP to do the actual vulnerabilities scan for us. After the scan is finished and the report generated, the report is then parsed as the response to the API itself and asynchronously returned to the frontend.


Exposed apis


Results
