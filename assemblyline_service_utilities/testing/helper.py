import json
import os
import re
import shutil
from pathlib import Path

import assemblyline_v4_service.common.api
import pytest
from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten
from assemblyline.common.str_utils import truncate
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file

# Test in development mode
# Patching api instead of utils because at this point api is already imported with the original value
assemblyline_v4_service.common.api.DEVELOPMENT_MODE = True

class FileMissing(Exception):
    pass


class HeuristicFiletypeMismatch(Exception):
    pass


class IssueHelper:
    ACTION_MISSING = "--"
    ACTION_ADDED = "++"
    ACTION_CHANGED = "-+"

    TYPE_HEUR = "HEURISTICS"
    TYPE_TAGS = "TAGS"
    TYPE_TEMP = "TEMP_DATA"
    TYPE_SUPPLEMENTARY = "SUPPLEMENTARY"
    TYPE_EXTRACTED = "EXTRACTED"
    TYPE_EXTRA = "EXTRA"
    TYPE_TEST = "TEST"

    def __init__(self):
        self.issues = {}

    def add_issue(self, itype: str, action: str, message: str):
        self.issues.setdefault(itype, [])
        self.issues[itype].append((action, message))

    def get_issue_list(self):
        return [
            f"[{k.upper()}] {action.capitalize()} {message}" for k, v in self.issues.items() for action, message in v
        ]

    def get_issues(self):
        return self.issues

    def has_issues(self):
        return len(self.issues.keys()) != 0


class TestHelper:
    def __init__(self, service_class, result_folder, extra_sample_locations=None):
        # Set service class to use
        self.service_class = service_class

        # Set location for samples
        self.locations = []

        # Extra samples location
        if extra_sample_locations:
            self.locations.append(extra_sample_locations)

        # Main samples location
        full_samples_location = os.environ.get("FULL_SAMPLES_LOCATION", None)
        if full_samples_location:
            self.locations.append(full_samples_location)

        # Set result folder location
        self.result_folder = result_folder

        # Load identify
        self.identify = forge.get_identify(use_cache=False)

        # Load submission params
        self.submission_params = helper.get_service_attributes().submission_params

        # Load service heuristic
        self.heuristics = helper.get_heuristics()

        # Set the options for tests
        self.test_options = {}

    def _create_service_task(self, file_path, params):
        fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type", "uri_info"]

        # Set proper default values
        if params is None:
            params = {}

        metadata = params.get("metadata", {})
        temp_submission_data = params.get("temp_submission_data", {})
        submission_params = params.get("submission_params", {})
        tags = params.get("tags", [])
        filename = params.get("filename", os.path.basename(file_path))
        depth = params.get("task_depth", ServiceTask.fields()["depth"].default)

        return ServiceTask(
            {
                "sid": get_random_id(),
                "metadata": metadata,
                "deep_scan": False,
                "depth": depth,
                "service_name": self.service_class.__name__,
                "service_config": {
                    param.name: submission_params.get(param.name, param.default) for param in self.submission_params
                },
                "fileinfo": {
                    k: v
                    for k, v in self.identify.fileinfo(
                        file_path, skip_fuzzy_hashes=True, calculate_entropy=False
                    ).items()
                    if k in fileinfo_keys
                },
                "filename": filename,
                "min_classification": "TLP:C",
                "max_files": 501,
                "ttl": 3600,
                "temporary_submission_data": [
                    {"name": name, "value": value} for name, value in temp_submission_data.items()
                ],
                "tags": tags,
            }
        )

    def _find_sample(self, sample):
        # Assume samples are carted
        sample = f"{sample.split('_', 1)[0]}.cart"

        for location in self.locations:
            p = [path for path in Path(location).rglob(sample)]
            if len(p) == 1:
                return p[0]

        raise FileMissing(sample)

    @staticmethod
    def _generalize_result(result, temp_submission_data=None):
        # Create a result for this file that contain generalized information for testing and
        # detailed information as well so the service writter has a better idea of the impact
        # of its changes to the service output.
        generalized_results = {
            "files": {
                "extracted": sorted(
                    [
                        {"name": x["name"], "sha256": x["sha256"]}
                        for x in result.get("response", {}).get("extracted", [])
                    ],
                    key=lambda x: x["sha256"],
                ),
                "supplementary": sorted(
                    [
                        {"name": x["name"], "sha256": x["sha256"]}
                        for x in result.get("response", {}).get("supplementary", [])
                    ],
                    key=lambda x: x["sha256"],
                ),
            },
            "results": {"heuristics": [], "tags": {}, "temp_submission_data": temp_submission_data},
            "extra": {
                "sections": [],
                "score": result.get("result", {}).get("score", 0),
                "drop_file": result.get("drop", False),
            },
        }

        # Parse sections
        for section in result.get("result", {}).get("sections", []):
            try:
                section["body"] = json.loads(section["body"])
            except (json.decoder.JSONDecodeError, TypeError):
                pass

            # Add section to extras (This will not be tested)
            generalized_results["extra"]["sections"].append(section)

            # Parse Heuristics
            heuristic = section.get("heuristic", None)
            sigs = []
            heur_id = None
            if heuristic:
                sigs = list(heuristic["signatures"].keys())
                heur_id = heuristic["heur_id"]
                generalized_results["results"]["heuristics"].append(
                    {"heur_id": heur_id, "attack_ids": heuristic["attack_ids"], "signatures": sigs}
                )
            # Sort Heuristics
            generalized_results["results"]["heuristics"] = sorted(
                generalized_results["results"]["heuristics"], key=lambda x: x["heur_id"]
            )

            # Parse tags
            for k, v in flatten(section.get("tags", {})).items():
                generalized_results["results"]["tags"].setdefault(k, [])
                for tag in v:
                    generalized_results["results"]["tags"][k].append(
                        {"value": tag, "heur_id": heur_id, "signatures": sigs}
                    )
            # Sort Tags
            for k, v in generalized_results["results"]["tags"].items():
                try:
                    generalized_results["results"]["tags"][k] = sorted(v, key=lambda x: x["value"])
                except TypeError:
                    # Sorting for list with different types: https://stackoverflow.com/a/68416981
                    type_weights = {}
                    for element in v:
                        if type(element["value"]) not in type_weights:
                            type_weights[type(element["value"])] = len(type_weights)

                    generalized_results["results"]["tags"][k] = sorted(
                        v, key=lambda x: (type_weights[type(x["value"])], str(x["value"]))
                    )

        return generalized_results

    def _execute_sample(self, sample, save=False, save_files=False):
        file_path = os.path.join("/tmp", sample.split("_", 1)[0])
        cls = None

        try:
            # Find and unpack sample
            sample_path = self._find_sample(sample)
            unpack_file(sample_path, file_path)

            # Load optional submission parameters
            params_file = os.path.join(self.result_folder, sample, "params.json")
            if os.path.exists(params_file):
                params = json.load(open(params_file))
            else:
                params = {}

            # Initialize service class
            cls = self.service_class(params.get("config", {}))
            cls.start()

            # Create the service request
            task = Task(self._create_service_task(file_path, params))
            service_request = ServiceRequest(task)
            cls._working_directory = task.working_directory

            # Execute the service
            cls.execute(service_request)

            # Get results from the scan
            results = self._generalize_result(task.get_service_result(), task.temp_submission_data)

            # Apply test options per sample
            self.test_options = params.get("options", {})

            # Save results if needs be
            if save:
                # If we are re-writing the results, validate that the heuristics raised were meant for the sample
                for heuristic in results["results"]["heuristics"]:
                    if not re.match(self.heuristics[heuristic["heur_id"]].filetype, task.file_type):
                        raise HeuristicFiletypeMismatch(
                            (
                                f"Tried to raise Heuristic {heuristic['heur_id']} "
                                f"({self.heuristics[heuristic['heur_id']].filetype}) for filetype {task.file_type}"
                            )
                        )

                # Save results
                result_json = os.path.join(self.result_folder, sample, "result.json")
                json.dump(results, open(result_json, "w"), indent=2, allow_nan=False, sort_keys=True)

                if save_files:
                    # Cleanup old extracted and supplementary
                    extracted_dir = os.path.join(self.result_folder, sample, "extracted")
                    supplementary_dir = os.path.join(self.result_folder, sample, "supplementary")
                    if os.path.exists(extracted_dir):
                        shutil.rmtree(extracted_dir)
                    if os.path.exists(supplementary_dir):
                        shutil.rmtree(supplementary_dir)

                    # Save extracted files
                    for ext in task.extracted:
                        if isinstance(save_files, list):
                            if ext["name"] not in save_files:
                                continue
                        target_file = os.path.join(self.result_folder, sample, "extracted", ext["sha256"])
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        shutil.move(ext["path"], target_file)

                    # Save supplementary files
                    for ext in task.supplementary:
                        if isinstance(save_files, list):
                            if ext["name"] not in save_files:
                                continue
                        target_file = os.path.join(self.result_folder, sample, "supplementary", ext["sha256"])
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        shutil.move(ext["path"], target_file)

            return results
        finally:
            # Cleanup files
            if cls:
                if os.path.exists(cls.working_directory):
                    shutil.rmtree(cls.working_directory)
                cls._cleanup()
            if os.path.exists(file_path):
                os.remove(file_path)

    def result_list(self):
        if not os.path.exists(self.result_folder):
            return []

        return [
            f
            for f in os.listdir(self.result_folder)
            if len(f.split("_")[0]) == 64 and os.path.isdir(os.path.join(self.result_folder, f))
        ]

    def compare_sample_results(self, sample, test_extra=False, ignore_new_extra_fields=True):
        ih = IssueHelper()
        original_results_file = os.path.join(self.result_folder, sample, "result.json")

        if os.path.exists(original_results_file):
            original_results = json.load(open(original_results_file))
            results = self._execute_sample(sample)

            # Compile the list of issues between the two results
            # Test extra results
            if test_extra or self.test_options.get("test_extra", False):
                self._data_compare(
                    ih,
                    original_results.get("extra", {}),
                    results.get("extra", {}),
                    ih.TYPE_EXTRA,
                    ignore_new_extra_fields=ignore_new_extra_fields,
                )

            # Extracted files
            self._file_compare(
                ih, ih.TYPE_EXTRACTED, original_results["files"]["extracted"], results["files"]["extracted"]
            )
            # Supplementary files
            self._file_compare(
                ih, ih.TYPE_SUPPLEMENTARY, original_results["files"]["supplementary"], results["files"]["supplementary"]
            )
            # Heuristics triggered
            self._heuristic_compare(ih, original_results["results"]["heuristics"], results["results"]["heuristics"])

            # Tags generated
            if not self.test_options.get("ignore_tags", False):
                self._tag_compare(ih, original_results["results"]["tags"], results["results"]["tags"])

            # Temp submission data generated
            self._data_compare(
                ih,
                original_results["results"]["temp_submission_data"],
                results["results"]["temp_submission_data"],
                ih.TYPE_TEMP,
                ignore_new_extra_fields=ignore_new_extra_fields,
            )
        else:
            ih.add_issue(ih.TYPE_TEST, ih.ACTION_MISSING, f"Original result file missing for sample: {sample}")

        return ih

    def run_test_comparison(self, sample, test_extra=False, ignore_new_extra_fields=True):
        # WARNING: This function is only to be run into a pytest context!
        ih = self.compare_sample_results(sample, test_extra=test_extra, ignore_new_extra_fields=ignore_new_extra_fields)
        if ih.has_issues():
            issues = ih.get_issue_list()
            issues.insert(0, "")
            pytest.fail("\n".join(issues))

    @staticmethod
    def _heuristic_compare(ih: IssueHelper, original, new):
        oh_map = {x["heur_id"]: x for x in original}
        nh_map = {x["heur_id"]: x for x in new}
        for heur_id, heur in oh_map.items():
            if heur_id not in nh_map:
                ih.add_issue(ih.TYPE_HEUR, ih.ACTION_MISSING, f"Heuristic #{heur_id} missing from results.")
            else:
                new_heur = nh_map[heur_id]
                for attack_id in heur["attack_ids"]:
                    if attack_id not in new_heur["attack_ids"]:
                        ih.add_issue(
                            ih.TYPE_HEUR,
                            ih.ACTION_MISSING,
                            f"Attack ID '{attack_id}' missing from heuristic #{heur_id}.",
                        )
                for signature in heur["signatures"]:
                    if signature not in new_heur["signatures"]:
                        ih.add_issue(
                            ih.TYPE_HEUR,
                            ih.ACTION_MISSING,
                            f"Signature '{signature}' missing from heuristic #{heur_id}.",
                        )

                for attack_id in new_heur["attack_ids"]:
                    if attack_id not in heur["attack_ids"]:
                        ih.add_issue(
                            ih.TYPE_HEUR, ih.ACTION_ADDED, f"Attack ID '{attack_id}' added to heuristic #{heur_id}."
                        )
                for signature in new_heur["signatures"]:
                    if signature not in heur["signatures"]:
                        ih.add_issue(
                            ih.TYPE_HEUR, ih.ACTION_ADDED, f"Signature '{signature}' added to heuristic #{heur_id}."
                        )

        for heur_id in nh_map.keys():
            if heur_id not in oh_map:
                ih.add_issue(ih.TYPE_HEUR, ih.ACTION_ADDED, f"Heuristic #{heur_id} added to results.")

    @staticmethod
    def _tag_compare(ih: IssueHelper, original, new):
        for tag_type, tags in original.items():
            if tag_type not in new:
                for t in tags:
                    ih.add_issue(
                        ih.TYPE_TAGS, ih.ACTION_MISSING, f"Tag '{t['value']} [{tag_type}]' missing from the results."
                    )
            else:
                otm = {x["value"]: x for x in tags}
                ntm = {x["value"]: x for x in new[tag_type]}
                for v, tag in otm.items():
                    if v not in ntm:
                        ih.add_issue(
                            ih.TYPE_TAGS, ih.ACTION_MISSING, f"Tag '{v} [{tag_type}]' missing from the results."
                        )
                    else:
                        new_tag = ntm[v]
                        if tag["heur_id"] != new_tag["heur_id"]:
                            ih.add_issue(
                                ih.TYPE_TAGS,
                                ih.ACTION_CHANGED,
                                (
                                    f"Heuristic ID for tag '{v} [{tag_type}]' has changed "
                                    f"from {tag['heur_id']} to {new_tag['heur_id']}."
                                ),
                            )
                        if tag["signatures"] != new_tag["signatures"]:
                            ih.add_issue(
                                ih.TYPE_TAGS,
                                ih.ACTION_CHANGED,
                                (
                                    f"Associated signatures for tag '{v} [{tag_type}]' have changed "
                                    f"from {tag['signatures']} to {new_tag['signatures']}."
                                ),
                            )

                for v in ntm.keys():
                    if v not in otm:
                        ih.add_issue(ih.TYPE_TAGS, ih.ACTION_ADDED, f"Tag '{v} [{tag_type}]' added to results.")

        for tag_type, tags in new.items():
            if tag_type not in original:
                for t in tags:
                    ih.add_issue(
                        ih.TYPE_TAGS, ih.ACTION_ADDED, f"Tag '{t['value']} [{tag_type}]' added to the results."
                    )

    @staticmethod
    def _data_compare(ih: IssueHelper, original, new, data_type, ignore_new_extra_fields=True, root=""):
        for k, v in original.items():
            if root:
                root = f"{root}.{k}"
            else:
                root = k

            if (new is None) or (k not in new):
                ih.add_issue(
                    data_type,
                    ih.ACTION_MISSING,
                    f"@{root} - {data_type} with key '{k}' is missing from the results.",
                )
            elif v != new[k]:
                if isinstance(v, dict):
                    TestHelper._data_compare(
                        ih, v, new[k], data_type, ignore_new_extra_fields=ignore_new_extra_fields, root=root
                    )
                elif isinstance(v, list) and all(isinstance(item, dict) for item in v) and len(v) == len(new[k]):
                    for index, item in enumerate(v):
                        TestHelper._data_compare(
                            ih,
                            item,
                            new[k][index],
                            data_type,
                            ignore_new_extra_fields=ignore_new_extra_fields,
                            root=f"{root}[{index}]",
                        )
                else:
                    ih.add_issue(
                        data_type,
                        ih.ACTION_CHANGED,
                        (
                            f"@{root} - Value of {data_type} with key '{k}' has changed "
                            f"from {truncate(v)} to {truncate(new[k])}."
                        ),
                    )

        # Only ignore new files in the "extra" data
        if data_type == ih.TYPE_EXTRA and ignore_new_extra_fields:
            pass
        else:
            for k, v in new.items():
                if k not in original:
                    ih.add_issue(
                        data_type,
                        ih.ACTION_ADDED,
                        f"@{root} - {data_type} with key '{k}' was added to the results.",
                    )

    @staticmethod
    def _file_compare(ih: IssueHelper, f_type, original, new):
        if original == new:
            # These file lists are exactly identical, no need to process for differences
            return
        elif len(new) == len(original) and all(n in original for n in new):
            # The file lists, although the contents might be out of order, are the same
            return

        # Prune out items in the lists where nothing changed
        for file in list(original):
            if file in new:
                original.remove(file)
                new.remove(file)

        # All remaining files in the new file list are assumed to have been additions to the original
        change_record = [(ih.ACTION_ADDED, x["name"], x["sha256"]) for x in new]

        # Check to see if any of the files in the old list have been changed when comparing against the new files
        for x in original:
            name, sha256 = x["name"], x["sha256"]

            # We assume that if there's any change, it only applies to one file at a time
            change_action = None

            # During this check, we are going to priorize changes that involve hash for the same filename
            hash_changes = [c for c in change_record if c[0] == ih.ACTION_ADDED and c[1] == name and c[2] != sha256]
            for r in hash_changes:
                # The filename is the same but the hashes are different
                change_action = (ih.ACTION_CHANGED, "hash_change", name, sha256, r[2])
                change_record.insert(change_record.index(r), change_action)
                change_record.remove(r)
                break

            if change_action:
                continue

            name_changes = [c for c in change_record if c[0] == ih.ACTION_ADDED and c[1] != name and c[2] == sha256]
            for r in name_changes:
                # The hash is the same but the filenames are different
                change_action = (ih.ACTION_CHANGED, "name_change", sha256, name, r[1])
                change_record.insert(change_record.index(r), change_action)
                change_record.remove(r)
                break

            if change_action:
                continue

            # Assume this is a old file that's missing in the output
            change_record.append((ih.ACTION_MISSING, name, sha256))

        sha256_change_msg = "The sha256 of the file '{}' has changed. {} -> {}"
        name_change_msg = "The name of the file '{}' has changed. {} -> {}"
        file_added_msg = "File '{} [{}]' added to the file list."
        file_missing_msg = "File '{} [{}]' missing from the file list."

        # Process the change record for issue handling in the given order: ACTION_MISSING, ACTION_CHANGED, ACTION_ADDED
        for record in sorted(change_record, key=lambda x: ["--", "-+", "++"].index(x[0])):
            message = None
            if record[0] == ih.ACTION_CHANGED:
                if record[1] == "hash_change":
                    message = sha256_change_msg.format(*record[2:])

                elif record[1] == "name_change":
                    message = name_change_msg.format(*record[2:])

            elif record[0] == ih.ACTION_ADDED:
                message = file_added_msg.format(*record[1:])
            elif record[0] == ih.ACTION_MISSING:
                message = file_missing_msg.format(*record[1:])

            ih.add_issue(f_type, record[0], message)

    def regenerate_results(self, save_files=False, sample_sha256=""):
        result_list = self.result_list()
        for i, f in enumerate(result_list):
            if sample_sha256 and f != sample_sha256:
                print(f"{sample_sha256} requested. Skipping {f}...")
                continue
            try:
                if not sample_sha256:
                    print(f"Executing {f}  [{(i+1)*100//len(result_list)}%]")
                else:
                    print(f"Executing {f}")
                self._execute_sample(f, save=True, save_files=save_files)
            except FileMissing:
                print(f"[W] File {f} was not found in any of the following locations: {', '.join(self.locations)}")


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        result_heuristic_equality = (
            this.heuristic.attack_ids == that.heuristic.attack_ids
            and this.heuristic.frequency == that.heuristic.frequency
            and this.heuristic.heur_id == that.heuristic.heur_id
            and this.heuristic.score == that.heuristic.score
            and this.heuristic.score_map == that.heuristic.score_map
            and this.heuristic.signatures == that.heuristic.signatures
        )

        if not result_heuristic_equality:
            print("The heuristics are not equal:")
            if this.heuristic.attack_ids != that.heuristic.attack_ids:
                print("The attack_ids are different:")
                print(f"{this.heuristic.attack_ids}")
                print(f"{that.heuristic.attack_ids}")
            if this.heuristic.frequency != that.heuristic.frequency:
                print("The frequencies are different:")
                print(f"{this.heuristic.frequency}")
                print(f"{that.heuristic.frequency}")
            if this.heuristic.heur_id != that.heuristic.heur_id:
                print("The heur_ids are different:")
                print(f"{this.heuristic.heur_id}")
                print(f"{that.heuristic.heur_id}")
            if this.heuristic.score != that.heuristic.score:
                print("The scores are different:")
                print(f"{this.heuristic.score}")
                print(f"{that.heuristic.score}")
            if this.heuristic.score_map != that.heuristic.score_map:
                print("The score_maps are different:")
                print(f"{this.heuristic.score_map}")
                print(f"{that.heuristic.score_map}")
            if this.heuristic.signatures != that.heuristic.signatures:
                print("The signatures are different:")
                print(f"{this.heuristic.signatures}")
                print(f"{that.heuristic.signatures}")

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        print("The heuristics are not equal:")
        if this.heuristic:
            print(f"{this.heuristic.__dict__}")
        else:
            print("this.heuristic is None")
        if that.heuristic:
            print(f"{that.heuristic.__dict__}")
        else:
            print("that.heuristic is None")
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = (
        result_heuristic_equality
        and this.body == that.body
        and this.body_format == that.body_format
        and this.classification == that.classification
        and this.depth == that.depth
        and len(this.subsections) == len(that.subsections)
        and this.title_text == that.title_text
        and this.tags == that.tags
        and this.auto_collapse == that.auto_collapse
    )

    if not current_section_equality:
        print("The current sections are not equal:")
        if not result_heuristic_equality:
            print("The result heuristics are not equal")
        if this.body != that.body:
            print("The bodies are different:")
            print(f"{this.body}")
            print(f"{that.body}")
        if this.body_format != that.body_format:
            print("The body formats are different:")
            print(f"{this.body_format}")
            print(f"{that.body_format}")
        if this.classification != that.classification:
            print("The classifications are different:")
            print(f"{this.classifications}")
            print(f"{that.classifications}")
        if this.depth != that.depth:
            print("The depths are different:")
            print(f"{this.depths}")
            print(f"{that.depths}")
        if len(this.subsections) != len(that.subsections):
            print("The number of subsections are different:")
            print(f"{len(this.subsections)}")
            print(f"{len(that.subsections)}")
        if this.title_text != that.title_text:
            print("The title texts are different:")
            print(f"{this.title_text}")
            print(f"{that.title_text}")
        if this.tags != that.tags:
            print("The tags are different:")
            print(f"{this.tags}")
            print(f"{that.tags}")
        if this.auto_collapse != that.auto_collapse:
            print("The auto_collapse settings are different:")
            print(f"{this.auto_collapse}")
            print(f"{that.auto_collapse}")
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True
