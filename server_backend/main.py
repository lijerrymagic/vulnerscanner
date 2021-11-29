from fastapi import FastAPI
import time
from pprint import pprint
from zapv2 import ZAPv2

app = FastAPI()


@app.get("/scan")
async def root():
    #################################
    ### START OF CONFIGURATION AREA ###
    #################################   

    apiKey = 'changemelater'
    target = 'http://www.zeyuli.me'
    local_proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    zap = ZAPv2(apikey=apiKey, proxies=local_proxies)
    core = zap.core

    # set scan policies
    use_scan_policy = True
    # only scanning SQL injection and XSS
    scan_policy_name = 'SQL Injection and XSS'
    # whilelisting list of scan plicies
    is_white_list_policy = True
    # first line SQL injecttion, second line XSS
    ascan_ids = [40018, 40019, 40020, 40021, 40022, 40024, 90018,
                40012, 40014, 40016, 40017]
    # from documentation: Set the alert Threshold and the attack strength of enabled active scans
    # Currently, possible values are:
    # Low, Medium and High for alert Threshold
    # Low, Medium, High and Insane for attack strength
    alert_threshold = 'Medium'
    attack_strength = 'Low'

    # not shutting down zap once finished
    shutdownOnceFinished = False

    #################################
    ### END OF CONFIGURATION AREA ###
    #################################
    ascan = zap.ascan
    if use_scan_policy:
        # remove and add again
        ascan.remove_scan_policy(scanpolicyname=scan_policy_name, apikey=apiKey)
        pprint('Add scan policy ' + scan_policy_name + ' -> ' + ascan.add_scan_policy(scanpolicyname=scan_policy_name, apikey=apiKey))
        print(ascan.policies())
        for policy_id in range(0, 6):
            # Set alert threshold for all scans
            ascan.set_policy_alert_threshold(id=policy_id,
                                             alertthreshold=alert_threshold,
                                             scanpolicyname=scan_policy_name)
            # Set attack strength for all scans
            ascan.set_policy_attack_strength(id=policy_id,
                                             attackstrength=attack_strength,
                                             scanpolicyname=scan_policy_name)
        if is_white_list_policy:
            # Disable all active scanners in order to enable only what we need
            pprint('Disable all scanners -> ' +
                    ascan.disable_all_scanners(scanpolicyname=scan_policy_name))
            # Enable some active scanners
            pprint('Enable given scan IDs -> ' +
                    ascan.enable_scanners(ids=ascan_ids,
                                          scanpolicyname=scan_policy_name))
        else:
            # Enable all active scanners
            pprint('Enable all scanners -> ' +
                    ascan.enable_all_scanners(scanpolicyname=scan_policy_name))
            # Disable some active scanners
            pprint('Disable given scan IDs -> ' +
                    ascan.disable_scanners(ids=ascan_ids,
                                           scanpolicyname=scan_policy_name))
        print("Policeis" + str(ascan.policies()))
        # Spider scan
        print('Spidering target {}'.format(target))
        # The scan returns a scan id to support concurrent scanning
        spider_scan_id = zap.spider.scan(target)
        print("Spider starts. Scan ID equals: " + spider_scan_id)
        time.sleep(1)
        while int(zap.spider.status(spider_scan_id)) < 100:
            # Poll the status until it completes
            print('Spider progress %: {}'.format(zap.spider.status(spider_scan_id)))
            time.sleep(1)
        print('Spider has completed!')
        # Prints the URLs the spider has crawled
        print('\n'.join(map(str, zap.spider.results(spider_scan_id))))

        # Active scan
        print('Active Scanning target {}'.format(target))
        active_scan_id = ascan.scan(url=target, recurse=False, scanpolicyname="Injection")
        print("Active scan starts. Scan ID equals: " + active_scan_id)
        time.sleep(2)
        while int(ascan.status(active_scan_id)) < 100:
            # Loop until the scanner has finished
            print('Scan progress %: {}'.format(ascan.status(active_scan_id)))
            time.sleep(2)

        print('Active Scan completed.')
        # Print vulnerabilities found by the scanning
        alerts = core.alerts(baseurl=target)
        #pprint(alerts)

        print('XML report: ')
        xml_report = core.xmlreport()

        html_report = core.htmlreport()
    return ""
