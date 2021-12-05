from fastapi import FastAPI
import time
from pprint import pprint
from zapv2 import ZAPv2
from nmap3 import Nmap
from urllib import parse
from pydantic import BaseModel
import requests

class ScanRequest(BaseModel):
    url: str

class PortScanRequest(BaseModel):
    url: str
    start_port: int
    end_port: int

# zap api global object
zap_apis = None
############# CONFIGURATIONS AREA STARTS ###############

api_key = 'changemelater'
# target = 'http://173.82.151.22/vulnerabilities/sqli_blind/'
local_proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
zap = ZAPv2(apikey=api_key, proxies=local_proxies)

# only scanning SQL injection and XSS for now
scan_policy_name = 'VulnerScanner'

# SQL injection scanner ids and XSS scanner ids
sql_injection_ids = [40018, 40019, 40020, 40021, 40022, 40024, 90018]
xss_ids = [40012, 40014, 40016, 40017]
ascan_ids = sql_injection_ids + xss_ids

# Set the alert Threshold and the attack strength of enabled active scans
# From documentation: Currently, possible values are:
# Low, Medium and High for alert Threshold
# Low, Medium, High and Insane for attack strength
alert_threshold = 'Low'
attack_strength = 'High'
define_new_context = True
new_context_name = "Inject_context"

# if website using authentication
auth_method = "formBasedAuthentication"
auth_params = ('loginUrl=http://173.82.151.22:8000/login.php&'
            'loginRequestData=login%253D%257B%25username%2525%257D%2526password%253D%257B%2525password%2525%257D')
auth_params_dvwa = ('loginUrl=http://173.82.151.22/login.php&'
'loginRequestData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D%26Login%3DLogin%26user_token%3Da796a7ef61434aab17413a72e9bc7b2d')

############# CONFIGURATIONS AREA ENDS ###############


def server_init():   
    # zap apis variable
    context = zap.context
    core = zap.core
    spider = zap.spider
    ascan = zap.ascan
    pscan = zap.pscan

    # global var for authentication
    global context_id 
    global user_id
    global user_name

    # Disable passive scanner to increase the speed of active scan using API
    pprint('Disable all passive scanners : ' + pscan.disable_all_scanners(apikey=api_key))

    # remove and re-add in case of duplicate context
    context.remove_context(contextname=new_context_name)
    
    context_id = context.new_context(contextname=new_context_name)
    pprint('New context added : ' + new_context_name + ' Context ID is : ' + context_id)

    # Include URL in the newly created context
    print('Include URL in context : ' + context.include_in_context(contextname=new_context_name, regex='http://173.82.151.22.*'))
    

    # Define an authentication method with parameters for the context
    auth = zap.authentication
    pprint('Set authentication method: ' + auth_method + ' : ' +
            auth.set_authentication_method(contextid=context_id,
                                        authmethodname=auth_method,
                                        authmethodconfigparams=auth_params))

    
    # Define either a loggedin indicator or a loggedout indicator regexp
    # It allows ZAP to see if the user is always authenticated during scans
    pprint('Define Loggedin indicator: ' + ' : ' +
            auth.set_logged_in_indicator(contextid=context_id,
                                    loggedinindicatorregex='Login'))
    pprint('Define Loggedout indicator: ' + ' : ' +
            auth.set_logged_out_indicator(contextid=context_id,
                                    loggedoutindicatorregex='Logout'))
    
    # define new user in new context
    users = zap.users
    user_name = "bee"
    print('Create user ' + user_name + ':')

    user_id = users.new_user(contextid=context_id, name=user_name)
    print("User")
    pprint('User ID: ' + user_id + '; username -> ' +
            users.set_user_name(contextid=context_id, userid=user_id,
                                name=user_name) +
            '; credentials -> ' +
            users.set_authentication_credentials(contextid=context_id,
                userid=user_id,
                authcredentialsconfigparams='username=bee&password=bug1') +
            '; enabled -> ' +
            users.set_user_enabled(contextid=context_id, userid=user_id,
                                    enabled=True))
    forced_user = zap.forcedUser

    # remove scan policy and add again
    ascan.remove_scan_policy(scanpolicyname=scan_policy_name, apikey=api_key)
    pprint('Add scan policy ' + scan_policy_name + ' : ' + ascan.add_scan_policy(scanpolicyname=scan_policy_name, apikey=api_key))
    time.sleep(2)

    # Disable all active scanners in order to enable only what we need
    pprint('Disable all scanners : ' +
            ascan.disable_all_scanners(scanpolicyname=scan_policy_name))
    # Enable all active scanners
    pprint('Enable given scanner IDs : ' +
            ascan.enable_scanners(ids=ascan_ids, scanpolicyname=scan_policy_name))

    for policy_id in range(0, 5):
        # Set alert threshold for all scans
        ascan.set_policy_alert_threshold(id=policy_id,
                                            alertthreshold=alert_threshold,
                                            scanpolicyname=scan_policy_name)
        # Set attack strength for all scans
        ascan.set_policy_attack_strength(id=policy_id,
                                            attackstrength=attack_strength,
                                            scanpolicyname=scan_policy_name)
    # sleep to wait it add successfully
    time.sleep(10)
    pprint(ascan.scanners(scanpolicyname=scan_policy_name))
    print("Enable all policies : "+ ascan.set_enabled_policies(ids=list(range(5)), scanpolicyname=scan_policy_name, apikey=api_key))
    print("All polices of scan policy" + scan_policy_name + " : " + str(ascan.policies(scanpolicyname=scan_policy_name)))

    zap_apis = {}
    zap_apis["spider"] = spider
    zap_apis["core"] = core
    zap_apis["ascan"] = ascan
    zap_apis["pscan"] = pscan
    zap_apis["context"] = context
    zap_apis["forced_user"] = forced_user
    return zap_apis

app = FastAPI()
zap_apis = server_init()

@app.post("/scan")
def scan(scan_request: ScanRequest):
    target = scan_request.url

    # enable forced user
    pprint('Set forced user mode enabled : ' +
                zap_apis["forced_user"].set_forced_user_mode_enabled(boolean=True))
    pprint('Set user name: ' + user_name + ' for forced user mode : ' +
                zap_apis["forced_user"].set_forced_user(contextid=context_id, userid=user_id))
    # Spider scan starts
    print('Spidering target {}'.format(target))
    
    # The spider scan returns a scan id to support concurrent scanning'
    # spider_scan_id = zap_apis["spider"].scan_as_user(contextid=context_id, userid=user_id, url=target, recurse=True, apikey=api_key)
    spider_scan_id = zap_apis["spider"].scan(url=target, recurse=True, apikey=api_key)
    print("Spider scan starts. Scan ID equals: " + spider_scan_id)
    time.sleep(1)
    while int(zap_apis["spider"].status(spider_scan_id)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(spider_scan_id)))
        time.sleep(1)
    print('Spider scan has completed!')
    # Prints the URLs the spider has crawled
    print('\n'.join(map(str, zap.spider.results(spider_scan_id))))

    pprint('Set forced user mode disabled : ' +
                    zap_apis["forced_user"].set_forced_user_mode_enabled(boolean=False))
    # Active scan starts
    print('Active Scanning target {}'.format(target))

    # active_scan_id = zap_apis["ascan"].scan_as_user(url=target, contextid=context_id, userid=user_id, recurse=True, scanpolicyname=scan_policy_name, apikey=api_key, method=None, postdata=True)
    active_scan_id = zap_apis["ascan"].scan(url=target, recurse=True, apikey=api_key, scanpolicyname=scan_policy_name)
    print("Active scan starts. Scan ID equals: " + active_scan_id)
    time.sleep(2)
    while int(zap_apis["ascan"].status(active_scan_id)) < 100:
        # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap_apis["ascan"].status(active_scan_id)))
        time.sleep(2)

    print('Active Scan completed.')
    alerts_ids = zap_apis["ascan"].alerts_ids(active_scan_id)
    print(alerts_ids)

    # Print and return vulnerabilities found by the scanning
    res = {}
    for id in alerts_ids:
        alert_detail = zap_apis["core"].alert(id)
        res[id] = alert_detail
        pprint(alert_detail)
        
        # messages_ids = ascan.messages_ids(active_scan_id)
        # print(messages_ids)
        # for id in messages_ids:
        #     pprint(core.message(id))

        print('XML report: ')
        xml_report = zap_apis["core"].xmlreport()

        html_report = zap_apis["core"].htmlreport()
    return res

@app.post("/dns-scan")
def port_scan(scan_request: ScanRequest):
    nmap = Nmap()
    parsed_url = parse.urlsplit(scan_request.url)

    # extract host name from url for port scanning
    host_name = parsed_url.hostname
    results = nmap.nmap_dns_brute_script(host_name)
    print(results)
    return results

@app.post("/port-scan")
def port_scan(scan_request: PortScanRequest):
    nmap = Nmap()
    start_port = scan_request.start_port
    end_port = scan_request.end_port
    parsed_url = parse.urlsplit(scan_request.url)
    host_name = parsed_url.hostname 
    if not start_port and not end_port:
        results = nmap.scan_top_ports(target=host_name)
    # extrac host name from url for port scanning
    else:
        arg_string = " -p {start}-{end} ".format(start=str(start_port), end=str(end_port))
        results = nmap.scan_command(target=host_name, arg=arg_string)
    print(results)
    return results

@app.post("/os-scan")
def port_scan(scan_request: ScanRequest):
    nmap = Nmap()
    parsed_url = parse.urlsplit(scan_request.url)
    host_name = parsed_url.hostname 

    os_results = nmap.nmap_os_detection(target=host_name)
    print(os_results)
    return os_results

def cert_scan(scan_request: ScanRequest):
    cert_target = "https://www.digicert.com/api/check-host.php"
    target = scan_request.url
    payload = {'somekey': 'somevalue'}

    results = requests.post(cert_target, data = payload)

    print(results.text)