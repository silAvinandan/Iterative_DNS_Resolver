# End-to-end validation log (Member A)

> Fill this in from real runs. Do not record results you have not observed.

## Environment
- Date: 
- OS / JDK / Maven versions: 
- Network (home / campus / VPN; is outbound UDP+TCP 53 open?): 
- `dig -v`: 
- Commit hash tested: 

## 1. Build and unit tests
```
mvn clean package      # paste the summary line (Tests run: .., Failures: ..)
```

## 2. Resolver vs `dig +trace`
```
validation/validate.sh
```
Paste `validation/results-<timestamp>/summary.md` here, then list every row that is not MATCH:

| domain | type | what differed | cause | fix / decision |
|---|---|---|---|---|
|  |  |  |  |  |

## 3. Behaviour checks
| Check | How | Observed |
|---|---|---|
| Glue used (no extra lookups) | `example.com A -v`, read path | |
| Glue-less NS resolved | a domain with out-of-bailiwick NS | |
| CNAME chain followed | `www.github.com A` | |
| NXDOMAIN + SOA | non-existent name | |
| Failover | block one root IP in firewall, re-run | |
| Timeout path | block outbound 53, `--stats` | |
| TCP fallback | a name with a large response; `-v` shows TC=1 fallback | |

## 4. OS-resolver / browser test (needs the caching server mode, Week 6)
- [ ] Server started on (address:port): 
- [ ] OS resolver pointed at it (how): 
- [ ] Sites browsed successfully: 
- [ ] Sites that failed and why: 
- [ ] `dig @<server> example.com` output: 

## 5. Issues found and fixed
| # | Symptom | Root cause | Fix (commit) |
|---|---|---|---|
|  |  |  |  |
