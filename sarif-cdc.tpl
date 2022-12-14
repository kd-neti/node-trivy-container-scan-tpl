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
        {{- $t_first := true }}
        {{- range . }}
            {{- $ruleName := "OsPackageVulnerability" -}}
            {{- $ruleType := .Type -}}
            {{- if ne .Class "os-pkgs" -}}
            {{- $ruleName = "LanguageSpecificPackageVulnerability" -}}
            {{- end -}}

            {{- range .Vulnerabilities -}}
              {{- if $t_first -}}
                {{- $t_first = false -}}
              {{ else -}}
                ,
              {{- end }}
            {
              "id": "{{ .VulnerabilityID }}",
              "name": "{{ $ruleName }}",
              "shortDescription": {
                "text": {{ endWithPeriod (.Title) | printf "%q" }}
              },
              "fullDescription": {
                "text": {{ endWithPeriod (.Description) | printf "%q" }}
              },
              "helpUri": "{{ .PrimaryURL }}",
              "help": {
                "text": {{ printf "Vulnerability %v\nSeverity: %v\nPackage: %v\nInstalled Version: %v\nFixed Version: %v\nLink: [%v](%v)\nDataSource: [%v](%v)" .VulnerabilityID .Vulnerability.Severity .PkgName .InstalledVersion .FixedVersion .VulnerabilityID .PrimaryURL (index .DataSource).Name (index .DataSource).URL | printf "%q"}},
                "markdown": {{ printf "**Vulnerability %v**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|%v|%v|%v|[%v](%v), <a href='https://cve.report/%v' target='_blank'>%v</a>|\n\n%v" .VulnerabilityID .Vulnerability.Severity .PkgName .FixedVersion .VulnerabilityID .PrimaryURL .VulnerabilityID .VulnerabilityID  (endWithPeriod (.Description)) | printf "%q"}}
              },
              "properties": {
                "security-severity": "{{ (index .CVSS (sourceID "nvd")).V3Score }}",
                "precision": "very-high",
                "tags": [
                  "vulnerability",
                  "security",
                  "{{ .Vulnerability.Severity }}",
                  "{{ $ruleType }}",
                  {{ .PkgName | printf "%q" }}
                ]
                
                
              }
            }
            {{- end -}}
         {{- end -}}
          ]
        }
      },
      "results": [
    {{- $t_first := true }}
    {{- range . }}
        {{- $target := .Target -}}
        {{- $image := split " " $target -}}
        {{- $location := split ":" $image._0 -}}
        
        {{- range $index, $vulnerability := .Vulnerabilities -}}
          {{- if $t_first -}}
            {{- $t_first = false -}}
          {{ else -}}
            ,
          {{- end }}
          
          {{- $artifactLocation := .PkgPath -}} 
          {{- if empty .PkgPath -}}
              {{ $artifactLocation = print "library/" $location._0 }}
          {{- end}}
        {
          "ruleId": "{{ $vulnerability.VulnerabilityID }}",
          "ruleIndex": {{ $index }},
          "level": "error",
          "message": {
            "text": {{ printf "Package: %v\nInstalled Version: %v\nVulnerability %v\nSeverity: %v\nFixed Version: %v\nLink: [%v](%v)\nDataSource: [%v](%v)" .PkgName .InstalledVersion .VulnerabilityID .Vulnerability.Severity .FixedVersion .VulnerabilityID .PrimaryURL (index .DataSource).Name (index .DataSource).URL | printf "%q"}}
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "{{ $artifactLocation }}",
                "uriBaseId": "ROOTPATH"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        }
        {{- end -}}
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits",
      "originalUriBaseIds": {
        "ROOTPATH": {
          "uri": "file:///"
        }
      }
    }
  ]
}
