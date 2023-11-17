from datetime import datetime
from re import findall
from re import match as re_match
from typing import Any, Dict, List

from assemblyline_service_utilities.common.dynamic_service_helper import MIN_TIME, OntologyResults, Process
from assemblyline_service_utilities.common.safelist_helper import is_tag_safelisted

from assemblyline.common.isotime import LOCAL_FMT_WITH_MS, ensure_time_format
from assemblyline.odm.base import IPV4_REGEX
from assemblyline.odm.models.ontology.results import Process as ProcessModel

# Possible Sysmon image name value
UNKNOWN_PROCESS = "<unknown process>"


def convert_sysmon_processes(
    sysmon: List[Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    ontres: OntologyResults,
):
    """
    This method creates the GUID -> Process lookup table
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param ontres: The Ontology Results object instance
    :return: None
    """
    session = ontres.sandboxes[-1].objectid.session
    for event in sysmon:
        event_id = int(event["System"]["EventID"])
        # EventID 10: ProcessAccess causes too many misconfigurations of the process tree
        if event_id == 10:
            continue
        process: Dict[str, str] = {}
        event_data = event["EventData"]["Data"]
        for data in event_data:
            name = data["@Name"].lower()
            text = data.get("#text")

            # Process Create and Terminate
            if name == "utctime" and event_id in [1, 5]:
                t = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                if event_id == 1:
                    process["start_time"] = t
                else:
                    process["start_time"] = MIN_TIME
                    process["end_time"] = t
            elif name == "utctime":
                t = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                process["time_observed"] = t
            elif name in ["sourceprocessguid", "parentprocessguid"]:
                process["pguid"] = text
            elif name in ["processguid", "targetprocessguid"]:
                process["guid"] = text
            elif name in ["parentprocessid", "sourceprocessid"]:
                process["ppid"] = int(text)
            elif name in ["processid", "targetprocessid"]:
                process["pid"] = int(text)
            elif name in ["sourceimage"]:
                process["pimage"] = text
            elif name in ["image", "targetimage"]:
                # This is a Linux-specific behaviour in Sysmon
                if text.endswith(" (deleted)"):
                    text = text[: text.index(" (deleted)")]
                if not is_tag_safelisted(text, ["dynamic.process.file_name"], safelist):
                    process["image"] = text
            elif name in ["parentcommandline"]:
                if not is_tag_safelisted(text, ["dynamic.process.command_line"], safelist):
                    process["pcommand_line"] = text
            elif name in ["commandline"]:
                if not is_tag_safelisted(text, ["dynamic.process.command_line"], safelist):
                    process["command_line"] = text
            elif name == "originalfilename":
                process["original_file_name"] = text
            elif name == "integritylevel":
                process["integrity_level"] = text
            elif name == "hashes":
                split_hash = text.split("=")
                if len(split_hash) == 2:
                    _, hash_value = split_hash
                    process["image_hash"] = hash_value

        if not process.get("pid") or not process.get("image") or not process.get("start_time"):
            continue

        if ontres.is_guid_in_gpm(process["guid"]):
            ontres.update_process(**process)
        else:
            p_oid = ProcessModel.get_oid(
                {
                    "pid": process["pid"],
                    "ppid": process.get("ppid"),
                    "image": process["image"],
                    "command_line": process.get("command_line"),
                }
            )
            p = ontres.create_process(
                objectid=ontres.create_objectid(
                    tag=Process.create_objectid_tag(process["image"]),
                    ontology_id=p_oid,
                    guid=process.get("guid"),
                    session=session,
                ),
                **process,
            )
            ontres.add_process(p)


def convert_sysmon_network(
    sysmon: List[Dict[str, Any]],
    network: Dict[str, Any],
    safelist: Dict[str, Dict[str, List[str]]],
    convert_timestamp_to_epoch: bool = False,
) -> None:
    """
    This method converts network connections observed by Sysmon to the format supported by common sandboxes
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param network: The JSON of the network section from the report generated by common sandboxes
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param convert_timestamp_to_epoch: A flag indicating if we want timestamps converted to EPOCH
    :return: None
    """
    for event in sysmon:
        event_id = int(event["System"]["EventID"])

        # There are two main EventIDs that describe network events: 3 (Network connection) and 22 (DNS query)
        if event_id == 3:
            protocol = None
            network_conn = {
                "src": None,
                "dst": None,
                "time": None,
                "dport": None,
                "sport": None,
                "guid": None,
                "pid": None,
                "image": None,
            }
            for data in event["EventData"]["Data"]:
                name = data["@Name"]
                text = data.get("#text")
                if name == "UtcTime":
                    if convert_timestamp_to_epoch:
                        network_conn["time"] = datetime.strptime(text, LOCAL_FMT_WITH_MS).timestamp()
                    else:
                        network_conn["time"] = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                elif name == "ProcessGuid":
                    network_conn["guid"] = text
                elif name == "ProcessId":
                    network_conn["pid"] = int(text)
                elif name == "Image":
                    # Sysmon for Linux adds this to the image if the file is deleted.
                    if text.endswith(" (deleted)"):
                        text = text[: len(text) - len(" (deleted)")]
                    network_conn["image"] = text
                elif name == "Protocol":
                    protocol = text.lower()
                elif name == "SourceIp":
                    if re_match(IPV4_REGEX, text):
                        network_conn["src"] = text
                elif name == "SourcePort":
                    network_conn["sport"] = int(text)
                elif name == "DestinationIp":
                    if re_match(IPV4_REGEX, text):
                        network_conn["dst"] = text
                elif name == "DestinationPort":
                    network_conn["dport"] = int(text)
            if any(network_conn[key] is None for key in network_conn.keys()) or not protocol:
                continue
            elif any(
                req["dst"] == network_conn["dst"]
                and req["dport"] == network_conn["dport"]
                and req["src"] == network_conn["src"]
                and req["sport"] == network_conn["sport"]
                for req in network[protocol]
            ):
                # Replace record since we have more info from Sysmon
                for req in network[protocol][:]:
                    if (
                        req["dst"] == network_conn["dst"]
                        and req["dport"] == network_conn["dport"]
                        and req["src"] == network_conn["src"]
                        and req["sport"] == network_conn["sport"]
                    ):
                        network[protocol].remove(req)
                        network[protocol].append(network_conn)
            else:
                network[protocol].append(network_conn)
        elif event_id == 22:
            dns_query = {
                "type": "A",
                "request": None,
                "answers": [],
                "first_seen": None,
                "guid": None,
                "pid": None,
                "image": None,
            }
            for data in event["EventData"]["Data"]:
                name = data["@Name"]
                text = data.get("#text")
                if text is None:
                    continue
                if name == "UtcTime":
                    if convert_timestamp_to_epoch:
                        dns_query["first_seen"] = datetime.strptime(text, LOCAL_FMT_WITH_MS).timestamp()
                    else:
                        dns_query["first_seen"] = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                elif name == "ProcessGuid":
                    dns_query["guid"] = text
                elif name == "ProcessId":
                    dns_query["pid"] = int(text)
                elif name == "QueryName":
                    if not is_tag_safelisted(text, ["network.dynamic.domain"], safelist):
                        dns_query["request"] = text
                elif name == "QueryResults":
                    ip = findall(IPV4_REGEX, text)
                    for item in ip:
                        dns_query["answers"].append({"data": item, "type": "A"})
                elif name == "Image":
                    # Sysmon for Linux adds this to the image if the file is deleted.
                    if text.endswith(" (deleted)"):
                        text = text[: len(text) - len(" (deleted)")]
                    dns_query["image"] = text

            if any(dns_query[key] is None for key in dns_query.keys()):
                continue
            # If Sysmon was unable to get the QueryResults from the DNS event, populate the missing fields
            elif dns_query["answers"] == []:
                for query in network.get("dns", [])[:]:
                    if query["request"] == dns_query["request"]:
                        for key in dns_query.keys():
                            if key not in query:
                                query[key] = dns_query[key]
                        break
            elif any(query["request"] == dns_query["request"] for query in network.get("dns", [])):
                # Replace record since we have more info from Sysmon
                for query in network.get("dns", [])[:]:
                    if query["request"] == dns_query["request"]:
                        network["dns"].remove(query)
                        network["dns"].append(dns_query)
                        break
            else:
                if "dns" not in network:
                    network["dns"] = []
                network["dns"].append(dns_query)
