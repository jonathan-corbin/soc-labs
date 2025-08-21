# SOC Lab Notes - Day 1
**Date:** 2025-08-20

## Objective
Review Linux authentication logs and identify suspicious activity.

## Findings
- Multiple failed SSH login attempts observed in `/var/log/auth.log`.
- Source IPs: repeated attempts from `185.220.x.x` targeting the `root` account.
- Pattern: >100 failed attempts in under 5 minutes.
- Indicates a brute force attempt.

## Actions Taken
- Extracted source IPs with:

```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

- Documented frequency distribution of offending IPs.
- Drafted detection query (Splunk-style):

```splunk
index=auth "Failed password"
| stats count by src_ip
| where count > 50
```

## Next Steps
- Enrich IPs with GeoIP lookups.
- Add detection logic for failed logins followed by a successful login.
