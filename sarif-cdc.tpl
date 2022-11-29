{
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "informationUri": "https://github.com/aquasecurity/trivy",
          "fullName": "Trivy Vulnerability Scanner",
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
                "text": {{ printf "%v Package: %v" .VulnerabilityID .PkgName | printf "%q" }}
              },
              "fullDescription": {
                "text": {{ endWithPeriod (escapeString .Title) | printf "%q" }}
              },
              "helpUri": "{{ .PrimaryURL }}",
              "help": {
                "text": {{ printf "Vulnerability %v\nSeverity: %v\nPackage: %v\nInstalled Version: %v\nFixed Version: %v\nLink: [%v](%v)\nDataSource: [%v](%v)" .VulnerabilityID .Vulnerability.Severity .PkgName .InstalledVersion .FixedVersion .VulnerabilityID .PrimaryURL (index .DataSource).Name (index .DataSource).URL | printf "%q"}},
                "markdown": {{ printf "**Vulnerability %v**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|%v|%v|%v|%v|[%v](%v)\n[%v](https://cve.report/%v)|\n" .VulnerabilityID .Vulnerability.Severity .PkgName .InstalledVersion .FixedVersion .VulnerabilityID .PrimaryURL .VulnerabilityID .VulnerabilityID | printf "%q"}}
              },
              "properties": {
                "tags": [
                  "vulnerability",
                  "{{ .Vulnerability.Severity }}",
                  "{{ $ruleType }}",
                  {{ .PkgName | printf "%q" }}
                ],
                "precision": "very-high"
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
            {{- $artifactLocation = $location._0 -}}
          {{- end}}
        {
          "ruleId": "{{ $vulnerability.VulnerabilityID }}",
          "ruleIndex": {{ $index }},
          "level": "error",
          "message": {
            "text": {{ endWithPeriod (escapeString $vulnerability.Description) | printf "%q" }}
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
