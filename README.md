# YARA Rules & Detection Toolkit

YARA detection rules for phishing campaigns, financial scam landers, and common malware families. Organized by threat category with MITRE ATT&CK mappings.

Rules are based on patterns observed while working in threat detection and from analysing public samples on MalwareBazaar and ANY.RUN.


### Phishing:

**credential_harvesting.yar** - Generic credential harvesting pages with suspicious POST forms, and pages that prompt for passwords twice (common in 2FA interception kits).

**brand_impersonation.yar** - Pages impersonating Microsoft, PayPal, and DHL. Each rule checks for brand indicators combined with login forms, then negates legitimate domains to reduce false positives.

**financial_scam_landers.yar** - Investment scam landing pages that harvest PII through phone number fields and hidden affiliate tracking parameters. Also covers fake news article templates with dynamic dates and fake comment sections.

**phishing_kit_indicators.yar** - Anti-bot evasion techniques (canvas fingerprinting, WebGL fingerprinting, anti-debug checks) and kits that exfiltrate stolen credentials via Telegram Bot API.

**betting_platform_phish.yar** - Fake betting and gambling platforms impersonating bet365, 1xbet, betway, etc. Includes Chinese-language betting clones.

**ecommerce_brand_phish.yar** - Fake Shopify storefronts impersonating fashion and retail brands, plus domain parking pages with fake seller ratings.

**crypto_scam_landers.yar** - Cryptocurrency investment scams with wallet connection prompts, seed phrase harvesting, and fake exchange interfaces.

**banking_fintech_phish.yar** - Generic online banking phishing with anti-debugging, plus specific detection for Singapore banks (DBS, OCBC, UOB, POSB).

### Malware:

**agenttesla.yar** - Credential theft behaviour (browser password paths, SMTP exfiltration, keylogging APIs) and persistence mechanisms.

**asyncrat.yar** - AsyncRAT client configuration patterns, .NET crypto functions, and TCP/SSL C2 communication.

**remcos.yar** - Remcos RAT settings strings, registry persistence, keylogging artifacts, and mutex patterns.

## Sample Hashes

All public, from MalwareBazaar.

| Family | SHA256 | Source |
|--------|--------|--------|
| AgentTesla | 1c1c67cd994eed0ea906dc8e7f4128b9db756035e356a7f37fc1112b84bb46e2 | [MalwareBazaar](https://bazaar.abuse.ch/browse/signature/AgentTesla/) |
| AgentTesla | 4a2b467d823861199497178aa9c39088b91bcb3fcb3c164238ffa039fdc0a1a0 | [MalwareBazaar](https://bazaar.abuse.ch/browse/signature/AgentTesla/) |
| RedLine | 781a0c21bb36928f67bd9f66939643e57c5c35e9f3ccd1c2a01b5c9edc2e2659 | [MalwareBazaar](https://bazaar.abuse.ch/browse/signature/RedLineStealer/) |
| AsyncRAT | 103bf7cda93749567f7e16e48cd205fd059fdda7f7396a781c6e4a096a3b47d7 | [MalwareBazaar](https://bazaar.abuse.ch/browse/signature/AsyncRAT/) |
| AsyncRAT | 8a87aae368cd9817f313ece0e4bb52568017c01e245b7883b03db4bb03d80a1a | [MalwareBazaar](https://bazaar.abuse.ch/browse/signature/AsyncRAT/) |

## ATT&CK Coverage

| Rule Category | Techniques |
|--------------|-----------|
| Credential harvesting | T1556, T1111 |
| Brand impersonation | T1566.002 |
| Financial scam landers | T1566.002 |
| Phishing kit evasion | T1497, T1041 |
| Betting phishing | T1566.002 |
| E-commerce phishing | T1566.002 |
| Crypto scams | T1566.002 |
| Banking phishing | T1566.002 |
| AgentTesla | T1555, T1056.001, T1547.001 |
| AsyncRAT | T1059, T1095 |
| Remcos | T1112, T1056.001 |

## References

- [MalwareBazaar](https://bazaar.abuse.ch/)
- [ANY.RUN](https://app.any.run/submissions)
- [PhishTank](https://www.phishtank.org/)
- [OpenPhish](https://openphish.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
