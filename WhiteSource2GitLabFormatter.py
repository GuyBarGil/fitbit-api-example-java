import os
import json


def get_libraries():
    """
    Extracts all of the libraries from the WhiteSource scan report.

    :return: A list of the libraries WhiteSource scanned.
    """
    if jscan_report.get("libraries"):
        return jscan_report.get("libraries")
    exit()


class WsLibrary:
    """
    Creates a WsLibrary object and maps the JSON from each library to it.
    """
    def __init__(self, library):
        self.vulnerabilities = None
        self.name = None
        self.groupId = None
        self.version = None
        vars(self).update(library)


class WsVulnerability:
    """
    Creates a WsVulnerability object and maps the relevant vulnearbility JSON from the WS scan to the object.
    """
    def __init__(self, vulnerability, library):
        vars(self).update(vulnerability)
        self.library_name = library.groupId
        self.library_version = library.version
        self.top_fix = self.get_attribute('topFix')

    def get_attribute(self, attribute):
        """
        Ensures that the returned attribute is valid, and if not returns an empty dictionary so as not to fail any get methods.
        :param attribute: The requested attribute from the object.

        :return: The requested attribute from the object or an empty dict.
        """
        if hasattr(self, attribute):
            return self.__getattribute__(attribute)
        return {}

    def jsonify_for_gitlab(self):
        """
        Creates a JSON file compatible with GitLab's security dashboard from attributes of a WsVulnerability object.

        :return: A JSON file which can be uploaded as an artifact and displayed in GitLab's security dashboard.
        """
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
                    "name": str(self.get_attribute('topFix').get('origin')),
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
ws_scan_report = "scan_report.json"  # The WS scan report's file name
gl_report = "gl-dependency-scanning-report-ws.json"  # The GitLab JSON file name
# The GitLab report's header indicating the report version and opens the vulnerabilities list
report_header_json = '{ \n \
  "version": "2.1", \n \
  "vulnerabilities": [\n'
# Closes the vulnerabilities list
report_footer_json = ']}'

# Removes any old reports if they exist
if os.path.exists(gl_report):
    os.remove(gl_report)

# Adds a header to the JSON file with the report version and opens the vulnerabilities list.
with open(gl_report, 'a') as report:
    report.write(report_header_json)


with open(ws_scan_report) as scan_report:
    # Loads the scan report and retrieves the libraries from the report.
    jscan_report = json.load(scan_report)
    libraries = get_libraries()
    # Creates a WsLibrary object for each library.
    for library in libraries:
        ws_library = WsLibrary(library)
        print("Parsing vulnerabilities for {}...".format(ws_library.name[:-4]))
        # Creates a WsVulnerability object for each found vulnerability and appends it to the end of the GitLab JSON.
        for vulnerability in ws_library.vulnerabilities:
            vuln = WsVulnerability(vulnerability, ws_library)
            with open(gl_report, 'a') as report:
                json.dump(vuln.jsonify_for_gitlab(), report, indent=2)
                report.write(',')

# Removes the last comma from the report to avoid any errors.
with open(gl_report, 'ab+') as report:
    report.seek(-1, os.SEEK_END)
    report.truncate()

# Closes the vulnerabilities list.
with open(gl_report, 'a') as report:
    report.write(report_footer_json)

print("Finished formatting")
