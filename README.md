# Analyzing the Netgear EX6100

A few weeks ago, I purchased a Netgear EX6100 for $5 at a local garage sale. Score!

The device has reached end of life, and as such has not received any software updates since July, 2020 - uh oh!

I decided it likely wasn't smart to add it to my home network, so instead, it became a new toy for security research! :)

**Note:** This repository will likely be a continual work-in-progress, as this is something I'm only poking at in my free time. Feel free to reach out directly or open an issue if you have any questions or comments!

## Current TODO List

- Research device specs and architecture
- Disassemble device for hardware analysis/testing
- Have fun!

## Known Public CVEs

To check for known public CVEs, I used the NIST National Vulnerability Database's [CVE Search](https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=ex6100&results_type=overview&form_type=Basic&search_type=all&startIndex=0).

In total, I found **41 CVEs** that affect the Netgear EX6100, stretching from 2017 to 2024. To make things easier to parse, I've split them out into a separate file, [EX6100_CVEs.md](EX6100_CVEs.md).

To provide some rough analysis, the CVSS 3.1 rating counts are as follows:

- 9 CRITICAL
- 9 HIGH
- 22 MEDIUM
- 1 LOW

(CVSS ratings are taken from the NIST National Vulnerability Database)

### Outdated Firmware Woes...

Being that the last firmware update available for this device is dated July 2020, it seems like the lastest firmware revision (1.0.2.28) is likely still vulnerable to **11 different CVEs** that were published **after** July 2020:

- CVE-2020-35796
    - Dated: 2020-12-29
    - CVSS 3.1 Score: **9.8 - CRITICAL**
- CVE-2020-35799
    - Dated: 2020-12-29
    - CVSS 3.1 Score: **9.8 - CRITICAL**
- CVE-2020-35800
    - Dated: 2020-12-29
    - CVSS 3.1 Score: **9.4 - CRITICAL**
- CVE-2021-38514
    - Dated: 2021-08-10
    - CVSS 3.1 Score: 2.4 - LOW
- CVE-2021-38527
    - Dated: 2021-08-10
    - CVSS 3.1 Score: **9.8 - CRITICAL**
- CVE-2021-45618
    - Dated: 2021-12-25
    - CVSS 3.1 Score: **9.8 - CRITICAL**
- CVE-2021-45619
    - Dated: 2021-12-25
    - CVSS 3.1 Score: **9.8 - CRITICAL**
- CVE-2021-45648
    - Dated: 2021-12-25
    - CVSS 3.1 Score: **7.5 - HIGH**
- CVE-2021-45658
    - Dated: 2021-12-25
    - CVSS 3.1 Score: **9.8 - CRITICAL**
- CVE-2022-24655
    - Dated: 2022-03-18
    - CVSS 3.1 Score: **7.8 - HIGH**
- CVE-2024-35519
    - Dated: 2024-10-14
    - CVSS 3.1 Score: **8.4 - HIGH**

## Sourcing Device Firmware

There are a number of firmware binaries available for the EX6100 on the [NETGEAR website](https://www.netgear.com/support/product/ex6100/#download):

- [1.0.2.28](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.2.28_1.1.138.zip) (newest)
- [1.0.2.24](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.2.24_1.1.134.zip)
- [1.0.2.18](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.2.18_1.1.131.zip)
- [1.0.2.16](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.2.16_1.1.130.zip)
- [1.0.2.6](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.2.6_1.1.120.zip)
- [1.0.1.36](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.1.36_1.0.114_07311820.zip)
- [1.0.0.28](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100_V1.0.0.28_1.0.66.zip)
- [1.0.0.22](https://www.downloads.netgear.com/files/GDC/EX6100/EX6100_V1.0.0.22_1.0.51.zip) (initial release)

For this analysis I'll be focused on the newest available version, 1.0.2.28, released on 2020-07-29

## Completed Research Tasks

Just to keep track of what I've already completed, I'll throw each step into a bullet point below.

- Research public CVEs
- Download firmware for static analysis