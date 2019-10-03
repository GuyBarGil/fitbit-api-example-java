import os
import json


def get_libraries():
    if jscan_report.get("libraries"):
        return jscan_report.get("libraries")
    exit()


class WsLibrary:
    def __init__(self, library):
        vars(self).update(library)


class WsVulnerability:
    def __init__(self, vulnerability, library):
        vars(self).update(vulnerability)
        self.library_name = library.groupId
        self.library_version = library.version
        self.top_fix = self.get_attribute('topFix')

    def get_attribute(self, attribute):
        if hasattr(self, attribute):
            return self.__getattribute__(attribute)
        return {}

    def jsonify_for_gitlab(self):
        return {"category": "dependency_scanning",
                "name": str(self.get_attribute('name')),
                "message": str(self.get_attribute('name')) + " - Detected by WhiteSource",
                "description": str(self.get_attribute('description')),
                "cve": str(self.get_attribute('name')),
                "severity": (str(self.get_attribute('severity'))).title(),
                "confidence": "Confirmed",
                "scanner": {
                    "id": "WhiteSource",
                    "name": "WhiteSource"
                            },
                "location": {
                    "file": "package.json",
                    "dependency": {
                        "package": {
                        "name": str(self.get_attribute('library_name'))
                                    },
                    "version": str(self.get_attribute('library_version'))
                                    }
                            },
                "identifiers": [{
                    "type": "WhiteSource",
                    "name": str(self.get_attribute('name')),
                    "value": str(self.get_attribute('name')),
                    "url": str(self.get_attribute('topFix').get('url'))
                }],
                "links": [{
                    "url": str(self.get_attribute('url'))
                            }],
                "remediations": [{
                    "fixes": [
                        {
                            "cve": str(self.get_attribute('name'))
                        }
                    ],
                    "summary": str(self.top_fix.get('fixResolution'))
                }]
    }


print("Formatting WS scan report to GitLab JSON")
ws_scan_report = "scan_report.json"
gl_report = "gl-dependency-scanning-report-ws.json"
report_header_json = '{ \n \
  "version": "2.1", \n \
  "vulnerabilities": [\n'
report_footer_json = ']}'

if os.path.exists(gl_report):
    os.remove(gl_report)

with open(gl_report, 'a') as report:
    report.write(report_header_json)

with open(ws_scan_report) as scan_report:
    jscan_report = json.load(scan_report)
    libraries = get_libraries()
    for library in libraries:
        ws_library = WsLibrary(library)
        print("Parsing vulnerabilities for {}...".format(ws_library.name[:-4]))
        for vulnerability in ws_library.vulnerabilities:
            vuln = WsVulnerability(vulnerability, ws_library)
            with open(gl_report, 'a') as report:
                json.dump(vuln.jsonify_for_gitlab(), report, indent=2)
                report.write(',')

with open(gl_report, 'ab+') as report:
    report.seek(-1, os.SEEK_END)
    report.truncate()

with open(gl_report, 'a') as report:
    report.write(report_footer_json)

print("Finished formatting")
