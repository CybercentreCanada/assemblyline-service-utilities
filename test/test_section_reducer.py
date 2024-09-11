import os

import pytest
from assemblyline_service_utilities.common.section_reducer import _reduce_specific_tags, _section_traverser, reduce
from assemblyline_v4_service.common.result import Result, ResultSection

from . import setup_module, teardown_module

setup_module()
class TestSectionReducer:
    @staticmethod
    def test_reduce():
        res = Result()
        result_section = ResultSection("blah")
        res.add_section(result_section)
        reduce(res)
        # Code coverage only
        assert True

    @staticmethod
    @pytest.mark.parametrize("tags, correct_tags",
                             [({
                                 "network.dynamic.uri":
                                 ["https://google.com?query=allo", "https://google.com?query=mon",
                                  "https://google.com?query=coco"]},
                               {"network.dynamic.uri": ["https://google.com?query=${ALPHA}"]},), ])
    def test_section_traverser(tags, correct_tags):
        section = ResultSection("blah")
        subsection = ResultSection("subblah")
        for t_type, t_values in tags.items():
            for t_value in t_values:
                subsection.add_tag(t_type, t_value)
        section.add_subsection(subsection)
        assert _section_traverser(section).subsections[0].tags == correct_tags

    @staticmethod
    @pytest.mark.parametrize("tags, correct_reduced_tags",
                             [(None, {}),
                              ({
                                  "network.dynamic.uri":
                                  ["https://google.com?query=allo", "https://google.com?query=mon",
                                   "https://google.com?query=coco"]},
                               {"network.dynamic.uri": ["https://google.com?query=${ALPHA}"]}),
                              ({
                                  "network.static.uri":
                                  ["https://google.com?query=allo", "https://google.com?query=mon",
                                   "https://google.com?query=coco"]},
                               {"network.static.uri": ["https://google.com?query=${ALPHA}"]}),
                              ({"network.dynamic.uri_path": ["/blah/123", "/blah/321"]},
                               {"network.dynamic.uri_path": ["/blah/${NUMBER}"]}),
                              ({"network.static.uri_path": ["/blah/123", "/blah/321"]},
                               {"network.static.uri_path": ["/blah/${NUMBER}"]}),
                              ({"attribution.actor": ["MALICIOUS_ACTOR"]},
                               {"attribution.actor": ["MALICIOUS_ACTOR"]}), ])
    def test_reduce_specific_tags(tags, correct_reduced_tags):
        assert _reduce_specific_tags(tags) == correct_reduced_tags

teardown_module()
