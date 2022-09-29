# NSEC(3) Walker 🚶

DNS zones that use DNSSEC must use NSEC or NSEC3 records as a means of authenticated denial-of-existence. NSEC allows for fully extracting DNS zones akin to an AXFR zone transfer or a "zone dump". NSEC3 adds hashes to this process which must be cracked, but offline cracking is faster than online brute-forcing. NSEC(3) Walker automates this extraction process.

For more technical information see: LINK

For a whitepaper analysing NSEC3 recovery see: LINK

### Dependencies

* Python 3
* `pip install dnspython`

### Usage

**`python3 nsec-walker.py example.com`**

Or for NSEC3 dumping post hash cracking:

`python3 nsec-walker.py example.com nsec3.map nsec3.cracked`

### Example (NSEC / NSEC3 post crack)

```
$ python3 nsec-walker.py youth.gov

youth.gov
	A	52.191.39.218
	AAAA	2001:550:1200:3::81:131
	NS	rh202ns1.355.dhhs.gov.
	NS	rh120ns2.368.dhhs.gov.
	NS	rh120ns1.368.dhhs.gov.
	NS	rh202ns2.355.dhhs.gov.
	SOA	rh120ns1.368.dhhs.gov. hostmaster.psc.hhs.gov. 5524 600 60 604800 60
	SPF	"v=spf1" "-all"
	TXT	"v=spf1 -all"
	TXT	"khfllujpa7ksn8nn6un25ios2s"
_dmarc.youth.gov
	TXT	"v=DMARC1; p=reject; fo=1; ri=3600; rua=mailto:8idhoybh@ag.us.dmarcian.com,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:8idhoybh@fr.us.dmarcian.com;"
engage.youth.gov
	A	52.191.39.218
evidence-innovation.youth.gov
	CNAME	youth.gov.
tppevidencereview.youth.gov
	A	52.191.39.218
	AAAA	2001:550:1200:3::81:125
www.youth.gov
	CNAME	youth.gov.
```

### Example (NSEC3)

```
$ python3 nsec-walker.py id.au

Found: (oseei5iaovl40d3pjl7d27b9smtii1g0, p353soq76jhvb6mdo3c5nm246g3nokp7)
Found: (ji76fqses9dl31dee9cttvv0ck5llrt9, jk9mojps45834jkctbq2epnh3or22p2s)
Found: (ulr4htn3b64un2liuqum28aappv8r33j, uugcg47l46hkl0sk83vsou10khiu7u9i)
FOUND 4; DONE 1%; LEFT 399
```

### Example (crawling the DNS root zone)

```
$ python3 nsec-walker.py .

.
	NS	h.root-servers.net.
	NS	j.root-servers.net.
	NS	b.root-servers.net.
	NS	l.root-servers.net.
	NS	g.root-servers.net.
	NS	c.root-servers.net.
	NS	i.root-servers.net.
	NS	f.root-servers.net.
	NS	d.root-servers.net.
	NS	a.root-servers.net.
	NS	m.root-servers.net.
	NS	e.root-servers.net.
	NS	k.root-servers.net.
	SOA	a.root-servers.net. nstld.verisign-grs.com. 2022092700 1800 900 604800 86400
aaa
	DS	23185 8 2 b18d0ec8791d98e167ca4d9745a0c27a6377e099d8f6a16a09567492ab16b7de
	NS	23185 8 2 b18d0ec8791d98e167ca4d9745a0c27a6377e099d8f6a16a09567492ab16b7de
aarp
	DS	5751 8 2 7e8a14ab8f85009b9f19859815fa695954233fd9daa6ab359044d12621a77e9f
	NS	5751 8 2 7e8a14ab8f85009b9f19859815fa695954233fd9daa6ab359044d12621a77e9f
abarth
	DS	62281 8 2 8be9e8b680bc10289ea71a8b7c34fe0cdbaa86242b2c38541de454526df041a4
	NS	62281 8 2 8be9e8b680bc10289ea71a8b7c34fe0cdbaa86242b2c38541de454526df041a4
```

### Example (crawling all .mom domains)

```
$ python3 nsec-walker.py mom

.mom
	NS	a.nic.mom.
	NS	b.nic.mom.
	NS	c.nic.mom.
	NS	d.nic.mom.
	SOA	ns0.centralnic.net. hostmaster.centralnic.net. 1664283884 900 1800 6048000 3600
00554.mom
	NS	ns0.centralnic.net. hostmaster.centralnic.net. 1664283884 900 1800 6048000 3600
007k.mom
	NS	ns0.centralnic.net. hostmaster.centralnic.net. 1664283884 900 1800 6048000 3600
0088.mom
	NS	ns0.centralnic.net. hostmaster.centralnic.net. 1664283884 900 1800 6048000 3600
```
