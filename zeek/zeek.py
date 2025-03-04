import json
import os
import re
import subprocess

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline.odm.models.ontology.results.network import NetworkConnection
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTableSection, TableRow


IP_REGEX = re.compile(IP_ONLY_REGEX)


class DedupResultTableSection(ResultTableSection):
    def add_row(self, row):
        # Minimize on duplicate rows
        if row not in self.section_body._data:
            return super().add_row(row)


class Zeek(ServiceBase):
    """This Assemblyline service uses Zeek to analyze PCAP files."""

    def execute(self, request: ServiceRequest):
        """Run the service."""
        result = Result()

        # Use Zeek to analyze the PCAP file and dump as JSON logs
        subprocess.run(
            ["/opt/zeek/bin/zeek", "-r", request.file_path, "LogAscii::use_json=T"], cwd=self.working_directory
        )

        log_files = [file for file in os.listdir(self.working_directory) if file.endswith(".log")]
        # TODO: Will add all log files as supplementary for now until we know what's important
        for log_file in log_files:
            request.add_supplementary(
                path=os.path.join(self.working_directory, log_file),
                name=log_file,
                description=f"{log_file[:-4].upper()} logs from Zeek",
            )

        # HTTP
        if "http.log" in log_files:
            log_path = os.path.join(self.working_directory, "http.log")
            http_section = DedupResultTableSection("HTTP Logs")
            with open(log_path) as f:
                for log in f.read().splitlines():
                    log = json.loads(log)
                    if "host" not in log:
                        log["host"] = log["id.resp_h"]
                    uri = f"http{'s' if log['id.resp_p'] == 443 else ''}://{log['host']}{log['uri']}"
                    http_section.add_row(
                        TableRow(
                            {
                                "SRC": f"{log['id.orig_h']}:{log['id.orig_p']}",
                                "DST": f"{log['id.resp_h']}:{log['id.resp_p']}",
                                "METHOD": log["method"],
                                "URI": uri,
                            }
                        )
                    )

                    http_details = {
                        "request_uri": uri,
                        "request_method": log["method"],
                        "request_headers": {},
                        "response_headers": {},
                    }

                    if "status_code" in log:
                        http_details["response_status_code"] = log["status_code"]
                    if "resp_mime_types" in log:
                        http_details["response_content_mimetype"] = log["resp_mime_types"][0]
                    if "user_agent" in log:
                        http_details["request_headers"] = {
                            "User-Agent": log["user_agent"],
                        }

                    self.ontology.add_result_part(
                        NetworkConnection,
                        {
                            "source_ip": log["id.orig_h"],
                            "source_port": log["id.orig_p"],
                            "destination_ip": log["id.resp_h"],
                            "destination_port": log["id.resp_p"],
                            "direction": "outbound",
                            "connection_type": "http",
                            "http_details": http_details,
                        },
                    )

                    # Tag section
                    http_section.add_tag("network.static.ip", log["id.resp_h"])
                    http_section.add_tag("network.static.uri", uri)
                    if not log["host"].startswith(log["id.resp_h"]):
                        # Tag hostname if applicable
                        http_section.add_tag("network.static.domain", log["host"])
            result.add_section(http_section)

        if "dns.log" in log_files:
            log_path = os.path.join(self.working_directory, "dns.log")
            dns_section = DedupResultTableSection("DNS Logs")
            with open(log_path) as f:
                for log in f.read().splitlines():
                    log = json.loads(log)

                    if "query" not in log:
                        continue

                    dns_section.add_row(
                        TableRow(
                            {
                                "SRC": f"{log['id.orig_h']}:{log['id.orig_p']}",
                                "DST": f"{log['id.resp_h']}:{log['id.resp_p']}",
                                "QUERY": log["query"],
                                "ANSWER": log.get("answers", ["NXDOMAIN"]),
                            }
                        )
                    )

                    # Tag section
                    dns_section.add_tag("network.static.ip", log["id.resp_h"])
                    dns_section.add_tag("network.static.domain", log["query"])
                    for answer in log.get("answers", []):
                        if IP_REGEX.match(answer):
                            dns_section.add_tag("network.static.ip", answer)
                        else:
                            dns_section.add_tag("network.static.domain", answer)
            result.add_section(dns_section)

        if "files.log" in log_files:
            log_path = os.path.join(self.working_directory, "files.log")
            # Add extracted files to result
            with open(log_path) as f:
                for log in f.read().splitlines():
                    log = json.loads(log)

                    request.add_extracted(
                        path=os.path.join(self.working_directory, "extract_files", log["extracted"]),
                        name=log["extracted"],
                        description=f"Extracted file from {log['source']}",
                    )

        request.result = result
