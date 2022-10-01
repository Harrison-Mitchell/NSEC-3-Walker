import re
import uuid
import dns.resolver
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
from sys import argv
from time import sleep
from random import choice
from dns.dnssec import nsec3_hash

transformations = [
	# Send the hostname as-is
	lambda preDot, postDot: f"{preDot}.{postDot}",
	# Prepend a zero as a subdomain
	lambda preDot, postDot: f"0.{preDot}.{postDot}",
	# Append a hyphen to the subdomain
	lambda preDot, postDot: f"{preDot}-.{postDot}",
	# Double the last character of the subdomain
	lambda preDot, postDot: f"{preDot}{preDot[-1]}.{postDot}"
]

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 3

def dnssecQuery (target, record="NSEC"):
	"""Wrapper to DNS resolve with DNSSEC options"""

	if record == "NSEC":
		record = dns.rdatatype.NSEC
	if record == "A":
		record = dns.rdatatype.A
	if record == "NSEC3PARAM":
		record = dns.rdatatype.NSEC3PARAM

	query_name = dns.name.from_text(target)
	query = dns.message.make_query(
		query_name,
		record,
		want_dnssec=True
	)

	# Some records are corrupt/too long over UDP, so fallback to TCP if need be
	return dns.query.udp_with_fallback(
		query,
		choice(resolver.nameservers),
		timeout=3.0
	)[0]

def nsec (hostname):
	"""Linearly walk a domain's records with NSEC crawling"""

	# Init helper vars
	origHostname = hostname
	pending = {hostname}
	finished = set()
	records = []
	recordTypes = {}
	nextRecFudge = False

	try:
		# Whilst we're yet to finish the crawl, grab the next pending hostname
		while pending:
			hostname = pending.pop()
			targetRecordTypes = []

			# Bold print the target
			print(f"\033[1m{hostname}\033[0m")

			# Split the hostname into parts for lexicological transformation
			params = [hostname.split(".")[0], ".".join(hostname.split(".")[1:])]

			# Some NS servers gratuitously provide the next hostname even if you
			# request an existing record, so try the hostname as is, otherwise
			# append a "0." subdomain, append a dash "-" or add an extra char
			for transformation in transformations:
				# If a previous transformation has found the next record, no need
				# to continue transforming the name
				if targetRecordTypes:
					break

				# Transform the target
				target = transformation(*params)

				# Setup the query, and make 3 attempts to resolve the NSEC record
				response = None
				for i in range(3):
					try:
						response = dnssecQuery(target)
						break
					except dns.exception.Timeout:
						pass
				if not response:
					continue

				# For each NSEC DNS answer in authority + answer sections
				for answer in [*response.authority, *response.answer]:
					if answer.rdtype != 47: # NSEC
						continue

					# Answer order is sometimes random, only pick applicable
					if not nextRecFudge and hostname.strip() not in str(answer).split()[0]:
						continue

					# There should only ever be one NSEC record per RRSET,
					# so grab the first
					record = answer[0]

					# Some providers implement white/black lies and can't be
					# crawled: https://blog.cloudflare.com/black-lies/
					if record.next.to_text()[:5] == '\\000.':
						exit("Tarpit by CloudFlare: https://blog.cloudflare.com/black-lies/")
						continue

					# Extract the next hostname and current DNS record types from
					# the NSEC record
					nextRec = record.next.to_text()[:-1]
					targetRecordTypes = record.to_text().split(" ")[1:]

					# Some domains are misconfigured and have loops in the linked
					# list (here's looking at you P@yPal), so sanity check to see
					# if we've seen this record before, and if so, append an "a"
					# to break out of the local loop. Additionally, clear the
					# pending record types to resolve to avoid "NoAnswer" errors.
					# However, if we've seen it before because it's the root, 
					# we've completed the crawl, can wipe pending, and finish up
					nextRecFudge = False
					if nextRec != origHostname and nextRec in finished:
						nextRec = nextRec.split(".")[0] + "a" + "." + ".".join(nextRec.split(".")[1:])
						nextRecFudge = True
						targetRecordTypes = []

					# Add the next record to the buffer and escape the answer loop
					finished.add(hostname)
					pending.add(nextRec)
					break

			# We've crawled the next hostname, but now it's time to kindly ask for
			# all the records (e.g A, TXT...) for the current hostname besides
			# DNSSEC-y answers because they're dynamic and boring. Attempt thrice
			for recordType in sorted(targetRecordTypes):
				if recordType in ["RRSIG", "NSEC"]:
					continue
				for i in range(3):
					try:
						resolvedRecords = resolver.resolve(hostname, recordType)
						if resolvedRecords:
							break
					except:
						pass
				for answer in resolvedRecords:
						print(f"\t{recordType}\t{answer.to_text()}")

			# Pop this off the stack and off we are to the next one
			pending -= finished

	except KeyboardInterrupt:
		print("Caught Ctrl + C")

def nsec3 (hostname):
	"""~Linearly walk a domain's records with NSEC3 crawling"""

	# Tracks hash ranges e.g [abcd..., adff...]
	ranges = []
	# Tracks average range sizes for time left estimates
	rangeLens = []
	# Tracks records associated with ranges e.g abcd...: [A, MX, TXT]
	recordTypes = {}
	# Tracks the size of covered ranges for completion estimates
	coverage = 0
	# Calculates the total size of the integer representation of the range:
	# [0000, zzzz]. We trim hashes to the first 4 characters, while rough, it's
	# sufficient for our statistics (raw hashes are retained for cracking)
	most = int("zzzz", 36)
	# Collect the zone's salt and hash iterations (SHA1 is assumed and ignored)
	params = dnssecQuery(hostname, "NSEC3PARAM").answer
	params = [i.to_text() for i in params if i.rdtype == 51][0]
	itersparam, saltparam = int(params.split(" ")[-2]), params.split(" ")[-1]

	# Wipe any stale hashes
	with open("nsec3.hashes", "w") as hashFile:
		hashFile.write("")

	try:
		# Perform 90% coverage for large domains, 99% coverage for small domains
		# or 10000 requests; whichever of the three come first. Adjustable ;)
		for i in range(9999):
			if (coverage / most > 0.9 and i < 1000) or coverage / most > 0.99:
				break

			# Unlike NSEC walking where we know the plaintext value of the next
			# target, NSEC3 "walking" is not possible. Instead we locally hash
			# candidates searching for a hash nestled in a range we're yet to
			# collect. This candidate is sent to the nameserver and the
			# encompassing range is collected. This is repeated until most, if
			# not all ranges, and thus hashes are collected.
			while True:
				# Generate a random query candidate and calculate it's NSEC3 hash
				target = str(uuid.uuid4()) + "." + hostname
				h = nsec3_hash(target, saltparam, itersparam, "SHA1").lower()
				discovered = False
				for r in ranges:
					# If this hash is in a range we've already seen, generate new
					if (r[0] < h < r[1] or
						(r[1] > r[0] and r[0] < h and r[1] < target)):
						discovered = True
						break
				# If this hash range is not yet discovered, send it to the NS
				if not discovered:
					break

			# Attempt to DNSSEC query the A record of our target thrice
			for n in range(3):
				try:
					response = dnssecQuery(target, "A")
					break
				except dns.exception.Timeout:
					pass

			# Pull each NSEC3 record out of the noisy results
			for answer in [*response.authority, *response.answer]:
				if answer.rdtype != 50: # NSEC3
					continue

				# Split the NSEC3 record to its' pieces and normalise them
				splitAnswers = answer.to_text().split(" ")
				r1, _, _, _, alg, opt, iters, salt, r2, *recs = splitAnswers
				r1 = r1.split(".")[0].lower()
				salt = salt.upper()

				# If this is a new range to us
				if [r1, r2] not in ranges:
					# Save it for cracking later
					ranges.append([r1, r2])
					print(f"Found: ({r1}, {r2})")
					# Calculate the range size via its integer representation
					r1n = int(r1[:4], 36)
					r2n = int(r2[:4], 36)
					r = r2n - r1n
					# If it's the wrap edge case, normalise (e.g [fffe,0003])
					if r < 0:
						r += most
					# Update stats
					rangeLens.append(r)
					coverage += r
					# Record the hashed hostnames' associated records e.g A, MX
					recordTypes[r1] = recs

					# Append the hash to our file in hashcat format
					with open("nsec3.hashes", "a") as hashFile:
						hashFile.write(f"{r1}:.{hostname}:{salt}:{iters}\n")

			# Calculate and print stats
			# Estimated coverage is over-inflated due to probability. Future
			# work: implement https://doi.org/10.1007/978-3-030-15986-3_15
			avg = sum(rangeLens) / len(rangeLens)
			left = int((most - coverage) / avg)
			print(f"FOUND {len(rangeLens)}; DONE {(coverage / most):.0%}; LEFT {left}", end="    \r", flush=True)

	# Gracefully catch Ctrl + C so we can save the record maps to disk
	except KeyboardInterrupt:
		print("Caught Ctrl + C")

	# Write the hash:recs (e.g abcd:[A,MX]) dict to disk for post-crack-dump
	with open("nsec3.map", "w") as mapFile:
		mapFile.write(str(recordTypes))
		mapFile.write(str(recordTypes))

def nsec3align ():
	"""Requests records of cracked NSEC3 hostname hashes"""
	
	mapFileName, crackedFileName = argv[2], argv[3]

	# Eval the hash:recs dict file, insecure, but local, so I don't care...
	with open(mapFileName, "r") as mapFile:
		recordTypes = eval(mapFile.read())
	
	# Grab the hash:cracked values from the hashcat output
	with open(crackedFileName, "r") as crackedFile:
		cracked = crackedFile.read()
		crackedMap = []
		for line in cracked.split("\n"):
			if ":" in line:
				crackedMap.append([line.split(":")[4], line.split(":")[0]])
		
	# For each cracked hostname, dump its records
	for subdomain, ref in crackedMap:
		# Bold print the target
		target = f"{subdomain}.{hostname}"
		print(f"\033[1m{target}\033[0m")

		# For each non-DNSSEC record, attempt to resolve thrice and print RRSETs
		for recordType in sorted(recordTypes[ref]):
			resolvedRecords = []
			if recordType in ["RRSIG", "NSEC"]:
				continue
			for i in range(3):
				try:
					resolvedRecords = resolver.resolve(target, recordType)
					if resolvedRecords:
						break
				except:
					pass
			for answer in resolvedRecords:
					print(f"\t{recordType}\t{answer.to_text()}")

# Help / Usage
if len(argv) == 1 or "-h" in argv or "--help" in argv:
	exit(f"""          🚶
\033[1mNSEC(3) Walker\033[0m - https://harrisonm.com/blog/nsec-walking
Recovers DNS zone data for most DNSSEC zones

Crawl: (NSEC / NSEC3 auto-detected)
	python3 {argv[0]} example.com
		NSEC: Results written to STDOUT
		NSEC3: Results written to nsec3.hashes & nsec3.map

Crack nsec3.hashes: (requires hashcat and wordlist)
	hashcat -m 8300 nsec3.hashes -o nsec3.cracked wordlist.txt

Crawl NSEC3 zone post crack: (prints to STDOUT)
	python3 {argv[0]} example.com nsec3.map nsec3.cracked\n""")

# Call post NSEC3 cracking function and die
if len(argv) > 2:
	nsec3align()
	exit()

# Otherwise, setup the resolver to use the domain's nameservers
hostname = argv[1]
resolver.nameservers = [
	str(resolver.resolve(str(i).strip("."), "A")[0]) for i in resolver.resolve(hostname, "NS")
]

# Let the user know we've initalised ok
print(f"Crawling {hostname} using NS(s): " + ", ".join(resolver.nameservers))

# Query a non-existent record, and auto select NSEC or NSEC3 walking
if hostname == ".":
	nsec(hostname)
	exit()
response = dnssecQuery(f"nsec-walker-says-hi.{hostname}", "A")
for answer in [*response.authority, *response.answer]:
	if answer.rdtype == 47: # NSEC
		nsec(hostname)
		break
	if answer.rdtype == 50: # NSEC3
		nsec3(hostname)
		break
