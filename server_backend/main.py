from fastapi import FastAPI
import time
from zapv2 import ZAPv2

app = FastAPI()


@app.get("/scan")
async def root():
    apiKey = 'changemelater'
    target = 'http://www.zeyuli.me'
    zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    # TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
    print('Spidering target {}'.format(target))
    # The scan returns a scan id to support concurrent scanning
    spider_scanID = zap.spider.scan(target)
    while int(zap.spider.status(spider_scanID)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(spider_scanID)))
        time.sleep(1)

    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    print('\n'.join(map(str, zap.spider.results(spider_scanID))))
    print('Active Scanning target {}'.format(target))
    scanID = zap.ascan.scan(url=target)
    print(scanID)
    while int(zap.ascan.status(scanID)) < 100:
        # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
        time.sleep(5)

    print('Active Scan completed')
    # Print vulnerabilities found by the scanning
    alerts = zap.core.alerts(baseurl=target)
    print(alerts)
   
    return {"message": alerts}
