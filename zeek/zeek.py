"""This Assemblyline service uses Zeek to analyze PCAP files."""

import json
import os
import re
import subprocess
from hashlib import sha256

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline.odm.models.ontology.results.network import NetworkConnection
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection, TableRow

IP_REGEX = re.compile(IP_ONLY_REGEX)


class DedupResultTableSection(ResultTableSection):
    """This class is used to generate a TableSection with de-duplicated rows."""

    def add_row(self, row):
        """Add unique rows to the table."""
        # Minimize on duplicate rows
        if row not in self.section_body._data:
            super().add_row(row)


class Zeek(ServiceBase):
    """This Assemblyline service class uses Zeek to analyze PCAP files."""

    def execute(self, request: ServiceRequest):
        """Run the service."""
        result = Result()

        # Use Zeek to analyze the PCAP file and dump as JSON logs
        subprocess.run(
            ["/opt/zeek/bin/zeek", "-r", request.file_path, "LogAscii::use_json=T"], cwd=self.working_directory
        )

        # Add all log files as supplementary files and include them in the ontology
        log_files = [file for file in os.listdir(self.working_directory) if file.endswith(".log")]
        for log_file in log_files:
            filepath = os.path.join(self.working_directory, log_file)
            request.add_supplementary(
                path=filepath,
                name=log_file,
                description=f"{log_file[:-4].upper()} logs from Zeek",
            )
            with open(filepath, "r") as log:
                self.ontology.add_other_part(log_file, {"encoding": "raw", "tool": "zeek", "content": log.read()})

        # Extracted files
        if "files.log" in log_files:
            file_extracted_section = ResultSection("File(s) extracted by Zeek", parent=result)
            log_path = os.path.join(self.working_directory, "files.log")
            added_files = []
            # Add extracted files to result
            with open(log_path) as f:
                for log in f.read().splitlines():
                    log = json.loads(log)

                    filepath = os.path.join(self.working_directory, "extract_files", log["extracted"])
                    with open(filepath, "rb") as extracted_file:
                        file_sha256 = sha256(extracted_file.read()).hexdigest()

                    # Add file to result if it hasn't been added yet
                    if file_sha256 not in added_files:
                        added_files.append(file_sha256)
                        filename = log["extracted"]
                        request.add_extracted(
                            path=filepath,
                            name=filename,
                            description=f"Extracted file from {log['source']}",
                        )

                        file_extracted_section.add_line(filename)
                        file_extracted_section.add_tag("file.name.extracted", filename)
                        file_extracted_section.add_tag("file.name.extracted", file_sha256)

        # HTTP
        if "http.log" in log_files:
            log_path = os.path.join(self.working_directory, "http.log")
            http_section = DedupResultTableSection("HTTP Logs", parent=result)
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

        if "dns.log" in log_files:
            log_path = os.path.join(self.working_directory, "dns.log")
            dns_section = DedupResultTableSection("DNS Logs", parent=result)
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

        request.result = result
