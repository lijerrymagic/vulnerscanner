import React, { useState, useCallback, useEffect, useRef } from 'react';

const BackBtn = ({ onClick }) => {
  return (
    <span className="btn-back ms-2" onClick={onClick}>
    </span>
  );
};

const DnsCard = ({ dnsRecords, error, loading, showDns, setShowDns }) => {
  if (loading) {
    return (
      <div className="mb-3">
        <h5 style={{ fontSize: '1.17rem' }}>
          DNS Information
        </h5>
        <div className="card mb-3 justify-content-center align-items-center" style={{ height: '60px' }}>
          <div className="spinner-border text-primary" role="status"/>
        </div>
      </div>
    );
  }

  const renderComponent = () => {
    if (showDns) {
      return (
        <div className="card-body">
          {
            (dnsRecords || []).map((el, idx) => (
              <div key={idx} className={idx !== dnsRecords.length - 1 ? 'mb-2' : ''}>
                <div className="d-flex justify-content-between align-items-center">
                  <div>
                    { el.name }
                  </div>
                  <div>
                    TTL { el.ttl }
                  </div>
                </div>
                <div className="d-flex justify-content-between align-items-center">
                  <div>
                    { el.dnsType }
                  </div>
                  <div>
                    { el.address || el.alias || el.additionalName }
                  </div>
                </div>
              </div>
            ))
          }
        </div>
      );
    }
    return (
      error ? 
        (<span>Oops! Something goes wrong.</span>) :
        (
          <div className="card-body">
            {
              (dnsRecords || []).filter((_, idx) => idx < 4).map((el, idx) => (
                <div 
                  key={`${idx}_${el.address}`}
                  className="d-flex justify-content-between align-items-center"
                >
                  <div className="text-truncate" style={{ maxWidth: '50%' }}>
                    { el.name }
                  </div>
                  <div>
                    { el.address || el.dnsType }
                  </div>
                </div>
              ))
            }
          </div>
        )
    );
  };

  return (
    <div className="mb-2">
      <h5 className="d-flex align-items-center" style={{ fontSize: '1.17rem' }}>
        DNS Information
        {
          !showDns ? (
            error ? null : (
              <span
                className="btn btn-sm btn-link"
                onClick={() => setShowDns(true)}
              >
                {
                  (dnsRecords || []).length < 4 ? '(See Details)' : `(Only showing first 4 records, see more)`
                }
              </span>
            )
          ) : (
            <BackBtn onClick={() => setShowDns(false)}/>
          )
        }
      </h5>
      <div
        className={`card ${error ? 'justify-content-center align-items-center' : ''}`}
        style={{ minHeight: '60px' }}
      >
        {
          renderComponent()
        }
      </div>
    </div>
  );
};

const SslCertCard = ({ cert, showCert, setShowCert }) => {
  const getStatusClass = (el) => {
    if (el.label !== 'Status') return '';
    if (el.value === 'Valid') return 'text-success fw-bold';
    return 'text-danger fw-bold';
  };
  if (cert.loading) {
    return (
      <div className="mb-3">
        <h5 style={{ fontSize: '1.17rem' }}>
          SSL Certificate Information
        </h5>
        <div className="card mb-3 justify-content-center align-items-center" style={{ height: '60px' }}>
          <div className="spinner-border text-primary" role="status">
            <span className="sr-only"></span>
          </div>
        </div>
      </div>
    );
  }
  if (cert.error) {
    return (
      <div className="mb-3">
        <h5 style={{ fontSize: '1.17rem' }}>
          SSL Certificate Information
        </h5>
        <div className="card mb-3 justify-content-center align-items-center" style={{ height: '60px' }}>
          { cert.notSecure ? 'This is not a secure connection.' : 'Oops! Something goes wrong.' }
        </div>
      </div>
    );
  }
  const hideSet = new Set(['Serial Number', 'SHA1 Thumbprint', 'Key Length']);
  return (
    <div className="mb-3">
      <h5 className="d-flex justify-content-start align-items-center" style={{ fontSize: '1.17rem' }}>
        SSL Certificate Information
        {
          !showCert ? (
            <span className="btn btn-sm btn-link" onClick={() => setShowCert(true)}> (See Details)</span>
          ) : (
            <BackBtn onClick={() => setShowCert(false)}/>
          )
        }
      </h5>
      <div className="card">
        <div className="card-body">
          {
            showCert ? (
              <>
                {
                  (cert.details || []).map((el, idx) => (
                    <div key={`${idx}_${el.label}`}>
                      <div className="d-flex justify-content-start align-items-center fw-bold">
                        { el.label }
                      </div>
                      <div className={`d-flex justify-content-start align-items-center ${getStatusClass(el)}`}>
                        { el.value }
                      </div>
                    </div>
                  ))
                }
                <div className="fw-bold">
                  Trust status
                </div>
                <div className={`fw-bold text-capitalize ${cert.isTrusted ? 'text-success' : 'text-danger'}`}>
                  {
                    cert.trustInfo
                  }
                </div>
                <div className={`text-capitalize ${cert.isTrusted ? 'text-success' : 'text-danger'}`}>
                  {
                    cert.trustDetail
                  }
                </div>
                <div className="fw-bold text-capitalize">
                  { `${cert.isExpired ? '' : 'Expired on '}${cert?.expiredInfo}` }
                </div>
              </>
            ) : (
              <>
                {
                  (cert.details || []).filter(el => !hideSet.has(el.label)).map((el, idx) => (
                    <div 
                      key={`${idx}_${el.label}`}
                      className="d-flex justify-content-between align-items-center">
                      <div className="fw-bold">
                        { el.label }
                      </div>
                      <div className={`text-truncate ${getStatusClass(el)}`} style={{ maxWidth: '50%' }}>
                        { el.value }
                      </div>
                    </div>
                  ))
                }
                <div className="d-flex justify-content-between">
                  <div className="fw-bold">
                    Trust status
                  </div>
                  <div className={`fw-bold text-capitalize ${cert.isTrusted ? 'text-success' : 'text-danger'}`}>
                    {
                      cert.trustInfo
                    }
                  </div>
                </div>
                <div className="fw-bold text-capitalize">
                  { `${cert.isExpired ? '' : 'Expired on '}${cert?.expiredInfo}` }
                </div>
              </>
            )
          }
        </div>
      </div>
    </div>
  );
};

const VulnerabilitiesCard = ({ loading, error, showVul, setShowVul, ...info }) => {
  return (
    <div className="mb-3">
      <h5 className="d-flex justify-content-start align-items-center" style={{ fontSize: '1.17rem' }}>
        Possible Vulnerabilities
        {
          !showVul ? (
            error || loading || !Object.keys(info).length ? null : (
              <span
                className="btn btn-sm btn-link"
                onClick={() => setShowVul(true)}
              >
                (See Details)
              </span>
            )
          ) : (
            <BackBtn onClick={() => setShowVul(false)}/>
          )
        }
      </h5>
      {
        loading ? (
          <div className="card mb-3 justify-content-center align-items-center" style={{ height: '60px' }}>
            <div className="spinner-border text-primary" role="status">
              <span className="sr-only"></span>
            </div>
          </div>
        ) : (
          <div 
            className={`card ${error ? 'justify-content-center align-items-center' : ''}`}
            style={error ? { height: '60px' } : null}
          >
            {
              error ? 
                (<span>Oops! Something goes wrong.</span>) :
                (
                  <div className="card-body">
                    {
                      !showVul ? (
                        !Object.keys(info).length ? (
                          <div>
                            { 'No vulnerabilities found.' }
                          </div>
                        ) : (
                          Object.keys(info).map(key => (
                            <div key={key} className="d-flex justify-content-between align-items-center">
                              <div className="text-truncate" style={{ maxWidth: '75%' }}>
                                Found <span className="fw-bold text-danger">{info[key].alert}</span>
                              </div>
                            </div>
                          ))
                        )
                      ) : (
                        Object.keys(info).map(key => (
                          <div key={key} className="mt-2">
                            <div className="d-flex justify-content-start align-items-center fw-bold">
                              { info[key].alert }
                            </div>
                            <div>
                              <span className="fw-bold" style={{ width: '60px' }}>Evidence: </span>
                              <span className="text-break">{ info[key].attack }</span>
                            </div>
                            <div>
                              <span className="fw-bold" style={{ width: '60px' }}>Url: </span>
                              <span className="text-break">{ info[key].url }</span>
                            </div>
                          </div>
                        ))
                      )
                    }
                  </div>
                )
            }
          </div>
        )
      }
    </div>
  );
};

const PortScanCard = ({ host }) => {
  const [portScan, setPortScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [valid, setValid] = useState(true);
  const inputRef = useRef(null);
  const portRegex = /^([\d]+)(-[\d]+)?$/g;

  const handlePortScan = async () => {
    const portVal = inputRef.current.value;
    const match = portRegex.exec(portVal);
    if (!match) {
      setValid(false);
      return;
    }
    const from = Number(match[1]);
    const to = Number(match[2]?.substr(1) || from);
    if (from > to) {
      setValid(false);
      return;
    }
    setValid(true);
    try {
      setLoading(true);
      setPortScan({});
      const resp = await fetch(`${HOST}port-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: host,
          start_port: from,
          end_port: to
        }),
      });
      const data = await resp.json();
      setPortScan(data.scan[Object.keys(data.scan)[0]]);
    } catch (err) {
      setPortScan({
        error: err.message
      });
    } finally {
      setLoading(false);
    }
  };

  const renderComponent = () => {
    if (!portScan && !loading) return null;
    const getPortStateClass = (str) => {
      if (str === 'open') return ' text-success';
      if (str === 'closed') return ' text-danger';
      return '';
    };
    return (
      loading ? (
        null
      ) : (
        <div className="card justify-content-center align-items-center mt-3">
          {
            portScan?.error ? 
              (<span>Oops! Something goes wrong.</span>) :
              (
                <div className="w-100 card-body">
                  <h6 className="d-flex justify-content-between align-items-center fw-bold">
                    <div>Hostnames</div>
                    <div>{ portScan?.addresses.ipv4 } { portScan?.addresses.ipv6 }</div>
                  </h6>
                  {
                    (portScan.hostnames || []).map((el, idx) => (
                      <div key={idx} className="d-flex justify-content-between align-items-center">
                        <div>{ el.name }</div>
                        <div>{ el.type }</div>
                      </div>
                    ))
                  }
                  <h6 className="mt-3 fw-bold">Port Status</h6>
                  {
                    Object.keys(portScan.tcp || {}).map(key => (
                      <div key={key}>
                        <div className="d-flex justify-content-between align-items-center">
                          <div className="fw-bold">
                            Port { key } { (portScan.tcp || {})[key].name }
                          </div>
                          <div className={`fw-bold${getPortStateClass((portScan.tcp || {})[key].state)}`}>
                            { (portScan.tcp || {})[key].state }
                          </div>
                        </div>
                        {
                          (portScan.tcp || {})[key].product ? (
                            <div className="d-flex justify-content-between align-items-center">
                              <div>{ (portScan.tcp || {})[key].product }</div>
                              <div>{ (portScan.tcp || {})[key].version }</div>
                              <div>{ (portScan.tcp || {})[key].extrainfo }</div>
                            </div>
                          ) : null
                        }
                      </div>
                    ))
                  }
                </div>
              )
          }
        </div>
      )
    )
  };
  return (
    <>
      <div className="row align-items-center">
        <div className="col-8">
          <div className="input-group">
            <input
              ref={inputRef}
              type="text"
              className={`form-control ${!valid ? 'border-danger' : ''}`}
              placeholder="Port to be scanned (Ex: 1000-2000)"
              disabled={loading}
            />
            {
              loading ? (
                <div className="ms-2">
                  <div className="spinner-border text-primary" role="status" />
                </div>
              ) : null
            }
          </div>
        </div>
        <div className="col-4 d-flex justify-content-end">
          <button
            className="btn btn-primary"
            onClick={handlePortScan}
            disabled={loading}
          >
            Port Scan
          </button>
        </div>
      </div>
      { renderComponent() }
    </>
  );
};

const HOST = 'http://vulnerscanner.live/';
const App = () => {
  const [dns, setDns] = useState({ loading: true });
  const [cert, setCert] = useState({ loading: true });
  const [vul, setVul] = useState({ loading: true });
  const [showDns, setShowDns] = useState(false);
  const [showCert, setShowCert] = useState(false);
  const [showVul, setShowVul] = useState(false);
  const [currUrl, setCurrUrl] = useState('');

  const fetchDnsInfo = useCallback(async (host) => {
    try {
      const resp = await fetch(`${HOST}dns-scan`, { 
        method: 'POST', 
        headers: {
          'content-type': "application/json"
        },
        body: JSON.stringify({
          url: host
        })
      });
      const x = JSON.parse(await resp.json());
      if (x.ErrorMessage) {
        setDns({
          error: x.ErrorMessage
        });
      } else {
        setDns(x.DNSData);
      }
    } catch (err) {
      setDns({
        error: err.message
      });
    }
  }, [setDns]);
  const fetchCertInfo = useCallback(async (host) => {
    try {
      const resp = await fetch(`${HOST}cert-scan/${host}`);
      const respData = (await resp.json()).result;
      if (resp.ok) {
        const div = document.createElement('div');
        div.innerHTML = respData;
        const details = [].map.call(div.querySelector('#CertDetails').children, el => {
          const line = el.innerText;
          const words = line.split(' = ');
          if (words.length < 2) return null;
          return {
            label: words[0],
            value: words[1],
          }
        }).filter(el => el !== null);
        const isRevoked = div.querySelectorAll('h2')[2].classList.contains('error');
        const revokeStatus = div.querySelectorAll('h2')[2].innerText;
        const isExpired = div.querySelectorAll('h2')[3].classList.contains('error');
        const expiredInfo = div.querySelectorAll('h2')[3].nextSibling.innerText.split(' ').filter((el, idx) => idx > 2).join(' ');
        const trustInfo = div.querySelectorAll('h2')[5].innerText;
        const trustDetail = div.querySelectorAll('p')[div.querySelectorAll('p').length - 1].innerHTML
        const isTrusted = div.querySelectorAll('h2')[5].classList.contains('ok');
        const constructValidStr = () => {
          const val = [];
          if (isRevoked) val.push('Revoked');
          if (isExpired) val.push('Expired');
          if (!val.length) return 'Valid';
          return val.join(', ');
        };
        details.push({
          label: 'Status',
          value: constructValidStr(),
        });
        setCert({
          details,
          isRevoked,
          revokeStatus,
          isExpired,
          expiredInfo,
          trustInfo,
          trustDetail,
          isTrusted,
        });
      }
    } catch (err) {
      setCert({
        error: err.message,
      });
    }
  }, [setCert]);
  const fetchVulInfo = useCallback(async (host) => {
    try {
      const resp = await fetch(`${HOST}scan`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          url: host
        })
      });
      const respData = await resp.json();
      setVul(respData);
    } catch (err) {
      setVul({
        error: err.message
      });
    }
  }, [setVul]);

  useEffect(() => {
    window.chrome.tabs.query({ 
      active: true, 
      currentWindow: true 
    }, (tabs) => {
      const url = new URL(tabs[0].url);
      setCurrUrl(tabs[0].url);
      fetchDnsInfo(url.host);
      if (url.protocol === 'https:') {
        fetchCertInfo(url.host);
      } else {
        setCert({
          notSecure: true,
          error: 'Not HTTPS'
        });
      }
      fetchVulInfo(url.href);
    });
  }, [fetchDnsInfo, fetchCertInfo, fetchVulInfo]);

  const renderComponent = () => {
    if (showDns) {
      return (
        <DnsCard {...dns} showDns={showDns} setShowDns={setShowDns} />
      );
    }
    if (showCert) {
      return (
        <SslCertCard cert={cert} showCert={showCert} setShowCert={setShowCert} />
      );
    }
    if (showVul) {
      return (
        <VulnerabilitiesCard {...vul} showVul={showVul} setShowVul={setShowVul} />
      );
    }
    return (
      <>
        <DnsCard {...dns} showDns={showDns} setShowDns={setShowDns} />
        <SslCertCard cert={cert} showCert={showCert} setShowCert={setShowCert} />
        <VulnerabilitiesCard {...vul} showVul={showVul} setShowVul={setShowVul} />
        <PortScanCard host={currUrl}/>
      </>
    );
  };

  return (
    <div className="card" style={{ width: '400px', maxHeight: '500px', backgroundColor: '#fcfcfc', paddingTop: '1rem', overflowY: 'auto' }}>
      <div className="card-body">
        <h6 className="text-uppercase fs-6 fw-bolder" style={{ color: '4A4A4A', letterSpacing: '0.5px' }}>
          Analysis Report
        </h6>
        {renderComponent()}
      </div>
    </div>
  );
}

export default App;
