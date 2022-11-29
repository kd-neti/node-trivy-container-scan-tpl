{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "fullName": "Trivy Vulnerability Scanner",
          "informationUri": "https://github.com/aquasecurity/trivy",
          "name": "Trivy",
          "version": "0.34.0",
          "rules": [
            {
              "id": "CVE-2022-28391",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "busybox: remote attackers may execute arbitrary code if netstat is used."
              },
              "fullDescription": {
                "text": "BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record&#39;s value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal&#39;s colors."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-28391",
              "help": {
                "text": "Vulnerability CVE-2022-28391\nSeverity: HIGH\nPackage: busybox\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r8\nLink: [CVE-2022-28391](https://avd.aquasec.com/nvd/cve-2022-28391)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-28391**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|busybox|1.32.1-r8|[CVE-2022-28391](https://avd.aquasec.com/nvd/cve-2022-28391), [CVE-2022-28391](https://cve.report/CVE-2022-28391)|\n\nBusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record&#39;s value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal&#39;s colors."
              },
              "properties": {
                "security-severity": "8.8",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "busybox"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-30065",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "busybox: A use-after-free in Busybox&#39;s awk applet leads to denial of service."
              },
              "fullDescription": {
                "text": "A use-after-free in Busybox 1.35-x&#39;s awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-30065",
              "help": {
                "text": "Vulnerability CVE-2022-30065\nSeverity: HIGH\nPackage: busybox\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r9\nLink: [CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-30065**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|busybox|1.32.1-r9|[CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065), [CVE-2022-30065](https://cve.report/CVE-2022-30065)|\n\nA use-after-free in Busybox 1.35-x&#39;s awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function."
              },
              "properties": {
                "security-severity": "7.8",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "busybox"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-0778",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates."
              },
              "fullDescription": {
                "text": "The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc)."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-0778",
              "help": {
                "text": "Vulnerability CVE-2022-0778\nSeverity: HIGH\nPackage: libcrypto1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1n-r0\nLink: [CVE-2022-0778](https://avd.aquasec.com/nvd/cve-2022-0778)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-0778**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|libcrypto1.1|1.1.1n-r0|[CVE-2022-0778](https://avd.aquasec.com/nvd/cve-2022-0778), [CVE-2022-0778](https://cve.report/CVE-2022-0778)|\n\nThe BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc)."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "libcrypto1.1"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-2097",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "openssl: AES OCB fails to encrypt some bytes."
              },
              "fullDescription": {
                "text": "AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn&#39;t written. In the special case of &#34;in place&#34; encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p)."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-2097",
              "help": {
                "text": "Vulnerability CVE-2022-2097\nSeverity: MEDIUM\nPackage: libcrypto1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1q-r0\nLink: [CVE-2022-2097](https://avd.aquasec.com/nvd/cve-2022-2097)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-2097**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|MEDIUM|libcrypto1.1|1.1.1q-r0|[CVE-2022-2097](https://avd.aquasec.com/nvd/cve-2022-2097), [CVE-2022-2097](https://cve.report/CVE-2022-2097)|\n\nAES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn&#39;t written. In the special case of &#34;in place&#34; encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p)."
              },
              "properties": {
                "security-severity": "5.3",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "MEDIUM",
                  "alpine",
                  "libcrypto1.1"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-0778",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates."
              },
              "fullDescription": {
                "text": "The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc)."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-0778",
              "help": {
                "text": "Vulnerability CVE-2022-0778\nSeverity: HIGH\nPackage: libssl1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1n-r0\nLink: [CVE-2022-0778](https://avd.aquasec.com/nvd/cve-2022-0778)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-0778**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|libssl1.1|1.1.1n-r0|[CVE-2022-0778](https://avd.aquasec.com/nvd/cve-2022-0778), [CVE-2022-0778](https://cve.report/CVE-2022-0778)|\n\nThe BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc)."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "libssl1.1"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-2097",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "openssl: AES OCB fails to encrypt some bytes."
              },
              "fullDescription": {
                "text": "AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn&#39;t written. In the special case of &#34;in place&#34; encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p)."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-2097",
              "help": {
                "text": "Vulnerability CVE-2022-2097\nSeverity: MEDIUM\nPackage: libssl1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1q-r0\nLink: [CVE-2022-2097](https://avd.aquasec.com/nvd/cve-2022-2097)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-2097**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|MEDIUM|libssl1.1|1.1.1q-r0|[CVE-2022-2097](https://avd.aquasec.com/nvd/cve-2022-2097), [CVE-2022-2097](https://cve.report/CVE-2022-2097)|\n\nAES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn&#39;t written. In the special case of &#34;in place&#34; encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p)."
              },
              "properties": {
                "security-severity": "5.3",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "MEDIUM",
                  "alpine",
                  "libssl1.1"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-28391",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "busybox: remote attackers may execute arbitrary code if netstat is used."
              },
              "fullDescription": {
                "text": "BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record&#39;s value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal&#39;s colors."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-28391",
              "help": {
                "text": "Vulnerability CVE-2022-28391\nSeverity: HIGH\nPackage: ssl_client\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r8\nLink: [CVE-2022-28391](https://avd.aquasec.com/nvd/cve-2022-28391)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-28391**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|ssl_client|1.32.1-r8|[CVE-2022-28391](https://avd.aquasec.com/nvd/cve-2022-28391), [CVE-2022-28391](https://cve.report/CVE-2022-28391)|\n\nBusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record&#39;s value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal&#39;s colors."
              },
              "properties": {
                "security-severity": "8.8",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "ssl_client"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-30065",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "busybox: A use-after-free in Busybox&#39;s awk applet leads to denial of service."
              },
              "fullDescription": {
                "text": "A use-after-free in Busybox 1.35-x&#39;s awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-30065",
              "help": {
                "text": "Vulnerability CVE-2022-30065\nSeverity: HIGH\nPackage: ssl_client\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r9\nLink: [CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-30065**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|ssl_client|1.32.1-r9|[CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065), [CVE-2022-30065](https://cve.report/CVE-2022-30065)|\n\nA use-after-free in Busybox 1.35-x&#39;s awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function."
              },
              "properties": {
                "security-severity": "7.8",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "ssl_client"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-37434",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "zlib: heap-based buffer over-read and overflow in inflate() in inflate.c via a large gzip header extra field."
              },
              "fullDescription": {
                "text": "zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference)."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-37434",
              "help": {
                "text": "Vulnerability CVE-2022-37434\nSeverity: CRITICAL\nPackage: zlib\nInstalled Version: 1.2.11-r3\nFixed Version: 1.2.12-r2\nLink: [CVE-2022-37434](https://avd.aquasec.com/nvd/cve-2022-37434)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2022-37434**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|CRITICAL|zlib|1.2.12-r2|[CVE-2022-37434](https://avd.aquasec.com/nvd/cve-2022-37434), [CVE-2022-37434](https://cve.report/CVE-2022-37434)|\n\nzlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference)."
              },
              "properties": {
                "security-severity": "9.8",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "CRITICAL",
                  "alpine",
                  "zlib"
                ]
                
                
              }
            },
            {
              "id": "CVE-2018-25032",
              "name": "OsPackageVulnerability",
              "shortDescription": {
                "text": "zlib: A flaw found in zlib when compressing (not decompressing) certain inputs."
              },
              "fullDescription": {
                "text": "zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2018-25032",
              "help": {
                "text": "Vulnerability CVE-2018-25032\nSeverity: HIGH\nPackage: zlib\nInstalled Version: 1.2.11-r3\nFixed Version: 1.2.12-r0\nLink: [CVE-2018-25032](https://avd.aquasec.com/nvd/cve-2018-25032)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)",
                "markdown": "**Vulnerability CVE-2018-25032**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|zlib|1.2.12-r0|[CVE-2018-25032](https://avd.aquasec.com/nvd/cve-2018-25032), [CVE-2018-25032](https://cve.report/CVE-2018-25032)|\n\nzlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "alpine",
                  "zlib"
                ]
                
                
              }
            },
            {
              "id": "CVE-2021-3807",
              "name": "LanguageSpecificPackageVulnerability",
              "shortDescription": {
                "text": "nodejs-ansi-regex: Regular expression denial of service (ReDoS) matching ANSI escape codes."
              },
              "fullDescription": {
                "text": "ansi-regex is vulnerable to Inefficient Regular Expression Complexity."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2021-3807",
              "help": {
                "text": "Vulnerability CVE-2021-3807\nSeverity: HIGH\nPackage: ansi-regex\nInstalled Version: 3.0.0\nFixed Version: 3.0.1, 4.1.1, 5.0.1, 6.0.1\nLink: [CVE-2021-3807](https://avd.aquasec.com/nvd/cve-2021-3807)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)",
                "markdown": "**Vulnerability CVE-2021-3807**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|ansi-regex|3.0.1, 4.1.1, 5.0.1, 6.0.1|[CVE-2021-3807](https://avd.aquasec.com/nvd/cve-2021-3807), [CVE-2021-3807](https://cve.report/CVE-2021-3807)|\n\nansi-regex is vulnerable to Inefficient Regular Expression Complexity."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "node-pkg",
                  "ansi-regex"
                ]
                
                
              }
            },
            {
              "id": "CVE-2021-3807",
              "name": "LanguageSpecificPackageVulnerability",
              "shortDescription": {
                "text": "nodejs-ansi-regex: Regular expression denial of service (ReDoS) matching ANSI escape codes."
              },
              "fullDescription": {
                "text": "ansi-regex is vulnerable to Inefficient Regular Expression Complexity."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2021-3807",
              "help": {
                "text": "Vulnerability CVE-2021-3807\nSeverity: HIGH\nPackage: ansi-regex\nInstalled Version: 5.0.0\nFixed Version: 3.0.1, 4.1.1, 5.0.1, 6.0.1\nLink: [CVE-2021-3807](https://avd.aquasec.com/nvd/cve-2021-3807)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)",
                "markdown": "**Vulnerability CVE-2021-3807**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|ansi-regex|3.0.1, 4.1.1, 5.0.1, 6.0.1|[CVE-2021-3807](https://avd.aquasec.com/nvd/cve-2021-3807), [CVE-2021-3807](https://cve.report/CVE-2021-3807)|\n\nansi-regex is vulnerable to Inefficient Regular Expression Complexity."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "node-pkg",
                  "ansi-regex"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-41919",
              "name": "LanguageSpecificPackageVulnerability",
              "shortDescription": {
                "text": "Fastify: Incorrect Content-Type parsing can lead to CSRF attack ."
              },
              "fullDescription": {
                "text": "Fastify is a web framework with minimal overhead and plugin architecture. The attacker can use the incorrect `Content-Type` to bypass the `Pre-Flight` checking of `fetch`. `fetch()` requests with Content-Type’s essence as &#34;application/x-www-form-urlencoded&#34;, &#34;multipart/form-data&#34;, or &#34;text/plain&#34;, could potentially be used to invoke routes that only accepts `application/json` content type, thus bypassing any CORS protection, and therefore they could lead to a Cross-Site Request Forgery attack. This issue has been patched in version 4.10.2 and 3.29.4. As a workaround, implement Cross-Site Request Forgery protection using `@fastify/csrf&#39;."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-41919",
              "help": {
                "text": "Vulnerability CVE-2022-41919\nSeverity: MEDIUM\nPackage: fastify\nInstalled Version: 4.10.0\nFixed Version: 3.29.4, 4.10.2\nLink: [CVE-2022-41919](https://avd.aquasec.com/nvd/cve-2022-41919)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)",
                "markdown": "**Vulnerability CVE-2022-41919**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|MEDIUM|fastify|3.29.4, 4.10.2|[CVE-2022-41919](https://avd.aquasec.com/nvd/cve-2022-41919), [CVE-2022-41919](https://cve.report/CVE-2022-41919)|\n\nFastify is a web framework with minimal overhead and plugin architecture. The attacker can use the incorrect `Content-Type` to bypass the `Pre-Flight` checking of `fetch`. `fetch()` requests with Content-Type’s essence as &#34;application/x-www-form-urlencoded&#34;, &#34;multipart/form-data&#34;, or &#34;text/plain&#34;, could potentially be used to invoke routes that only accepts `application/json` content type, thus bypassing any CORS protection, and therefore they could lead to a Cross-Site Request Forgery attack. This issue has been patched in version 4.10.2 and 3.29.4. As a workaround, implement Cross-Site Request Forgery protection using `@fastify/csrf&#39;."
              },
              "properties": {
                "security-severity": "8.8",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "MEDIUM",
                  "node-pkg",
                  "fastify"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-3517",
              "name": "LanguageSpecificPackageVulnerability",
              "shortDescription": {
                "text": "nodejs-minimatch: ReDoS via the braceExpand function."
              },
              "fullDescription": {
                "text": "A vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of Service."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-3517",
              "help": {
                "text": "Vulnerability CVE-2022-3517\nSeverity: HIGH\nPackage: minimatch\nInstalled Version: 3.0.4\nFixed Version: 3.0.5\nLink: [CVE-2022-3517](https://avd.aquasec.com/nvd/cve-2022-3517)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)",
                "markdown": "**Vulnerability CVE-2022-3517**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|minimatch|3.0.5|[CVE-2022-3517](https://avd.aquasec.com/nvd/cve-2022-3517), [CVE-2022-3517](https://cve.report/CVE-2022-3517)|\n\nA vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of Service."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "node-pkg",
                  "minimatch"
                ]
                
                
              }
            },
            {
              "id": "CVE-2022-29244",
              "name": "LanguageSpecificPackageVulnerability",
              "shortDescription": {
                "text": "nodejs: npm pack ignores root-level .gitignore and .npmignore file exclusion directives when run in a workspace."
              },
              "fullDescription": {
                "text": "npm pack ignores root-level .gitignore and .npmignore file exclusion directives when run in a workspace or with a workspace flag (ie. `--workspaces`, `--workspace=&lt;name&gt;`). Anyone who has run `npm pack` or `npm publish` inside a workspace, as of v7.9.0 and v7.13.0 respectively, may be affected and have published files into the npm registry they did not intend to include. Users should upgrade to the latest, patched version of npm v8.11.0, run: npm i -g npm@latest . Node.js versions v16.15.1, v17.19.1, and v18.3.0 include the patched v8.11.0 version of npm."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-2022-29244",
              "help": {
                "text": "Vulnerability CVE-2022-29244\nSeverity: HIGH\nPackage: npm\nInstalled Version: 8.1.2\nFixed Version: 8.11.0\nLink: [CVE-2022-29244](https://avd.aquasec.com/nvd/cve-2022-29244)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)",
                "markdown": "**Vulnerability CVE-2022-29244**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|npm|8.11.0|[CVE-2022-29244](https://avd.aquasec.com/nvd/cve-2022-29244), [CVE-2022-29244](https://cve.report/CVE-2022-29244)|\n\nnpm pack ignores root-level .gitignore and .npmignore file exclusion directives when run in a workspace or with a workspace flag (ie. `--workspaces`, `--workspace=&lt;name&gt;`). Anyone who has run `npm pack` or `npm publish` inside a workspace, as of v7.9.0 and v7.13.0 respectively, may be affected and have published files into the npm registry they did not intend to include. Users should upgrade to the latest, patched version of npm v8.11.0, run: npm i -g npm@latest . Node.js versions v16.15.1, v17.19.1, and v18.3.0 include the patched v8.11.0 version of npm."
              },
              "properties": {
                "security-severity": "7.5",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "HIGH",
                  "node-pkg",
                  "npm"
                ]
                
                
              }
            }]
        }
      },
      "results": [
        {
          "ruleId": "CVE-2022-28391",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-28391\nSeverity: HIGH\nPackage: busybox\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r8\nLink: [CVE-2022-28391](https://avd.aquasec.com/nvd/cve-2022-28391)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-30065",
          "ruleIndex": 1,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-30065\nSeverity: HIGH\nPackage: busybox\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r9\nLink: [CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-0778",
          "ruleIndex": 2,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-0778\nSeverity: HIGH\nPackage: libcrypto1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1n-r0\nLink: [CVE-2022-0778](https://avd.aquasec.com/nvd/cve-2022-0778)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-2097",
          "ruleIndex": 3,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-2097\nSeverity: MEDIUM\nPackage: libcrypto1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1q-r0\nLink: [CVE-2022-2097](https://avd.aquasec.com/nvd/cve-2022-2097)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-0778",
          "ruleIndex": 4,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-0778\nSeverity: HIGH\nPackage: libssl1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1n-r0\nLink: [CVE-2022-0778](https://avd.aquasec.com/nvd/cve-2022-0778)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-2097",
          "ruleIndex": 5,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-2097\nSeverity: MEDIUM\nPackage: libssl1.1\nInstalled Version: 1.1.1l-r0\nFixed Version: 1.1.1q-r0\nLink: [CVE-2022-2097](https://avd.aquasec.com/nvd/cve-2022-2097)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-28391",
          "ruleIndex": 6,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-28391\nSeverity: HIGH\nPackage: ssl_client\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r8\nLink: [CVE-2022-28391](https://avd.aquasec.com/nvd/cve-2022-28391)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-30065",
          "ruleIndex": 7,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-30065\nSeverity: HIGH\nPackage: ssl_client\nInstalled Version: 1.32.1-r7\nFixed Version: 1.32.1-r9\nLink: [CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-37434",
          "ruleIndex": 8,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-37434\nSeverity: CRITICAL\nPackage: zlib\nInstalled Version: 1.2.11-r3\nFixed Version: 1.2.12-r2\nLink: [CVE-2022-37434](https://avd.aquasec.com/nvd/cve-2022-37434)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2018-25032",
          "ruleIndex": 9,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2018-25032\nSeverity: HIGH\nPackage: zlib\nInstalled Version: 1.2.11-r3\nFixed Version: 1.2.12-r0\nLink: [CVE-2018-25032](https://avd.aquasec.com/nvd/cve-2018-25032)\nDataSource: [Alpine Secdb](https://secdb.alpinelinux.org/)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "test-trivy",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2021-3807",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2021-3807\nSeverity: HIGH\nPackage: ansi-regex\nInstalled Version: 3.0.0\nFixed Version: 3.0.1, 4.1.1, 5.0.1, 6.0.1\nLink: [CVE-2021-3807](https://avd.aquasec.com/nvd/cve-2021-3807)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "usr/local/lib/node_modules/npm/node_modules/string-width/node_modules/ansi-regex/package.json",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2021-3807",
          "ruleIndex": 1,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2021-3807\nSeverity: HIGH\nPackage: ansi-regex\nInstalled Version: 5.0.0\nFixed Version: 3.0.1, 4.1.1, 5.0.1, 6.0.1\nLink: [CVE-2021-3807](https://avd.aquasec.com/nvd/cve-2021-3807)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "usr/local/lib/node_modules/npm/node_modules/cli-table3/node_modules/ansi-regex/package.json",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-41919",
          "ruleIndex": 2,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-41919\nSeverity: MEDIUM\nPackage: fastify\nInstalled Version: 4.10.0\nFixed Version: 3.29.4, 4.10.2\nLink: [CVE-2022-41919](https://avd.aquasec.com/nvd/cve-2022-41919)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "app/node_modules/fastify/package.json",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-3517",
          "ruleIndex": 3,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-3517\nSeverity: HIGH\nPackage: minimatch\nInstalled Version: 3.0.4\nFixed Version: 3.0.5\nLink: [CVE-2022-3517](https://avd.aquasec.com/nvd/cve-2022-3517)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "usr/local/lib/node_modules/npm/node_modules/minimatch/package.json",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        },
        {
          "ruleId": "CVE-2022-29244",
          "ruleIndex": 4,
          "level": "error",
          "message": {
            "text": "Vulnerability CVE-2022-29244\nSeverity: HIGH\nPackage: npm\nInstalled Version: 8.1.2\nFixed Version: 8.11.0\nLink: [CVE-2022-29244](https://avd.aquasec.com/nvd/cve-2022-29244)\nDataSource: [GitHub Security Advisory Npm](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)"
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "usr/local/lib/node_modules/npm/package.json",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        }],
      "columnKind": "utf16CodeUnits",
      "originalUriBaseIds": {
        "ROOTPATH": {
          "uri": "file:///"
        }
      }
    }
  ]
}
