"""This Assemblyline service uses Zeek to analyze PCAP files."""

from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result


class Zeek(ServiceBase):
    """This Assemblyline service uses Zeek to analyze PCAP files."""

    def execute(self, request: ServiceRequest):
        """Run the service."""

        result = Result()
        request.result = result
