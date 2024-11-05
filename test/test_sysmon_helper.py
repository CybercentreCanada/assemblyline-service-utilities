import pytest
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from assemblyline_service_utilities.common.sysmon_helper import convert_sysmon_network, convert_sysmon_processes


class TestModule:
    @staticmethod
    @pytest.mark.parametrize(
        "sysmon, expected_process",
        [([],
          {}),
         ([{"System": {"EventID": 2},
            "EventData":
            {
             "Data":
             [{"@Name": "ParentProcessId", "#text": "2"},
              {"@Name": "Image", "#text": "blah.exe"},
              {"@Name": "CommandLine", "#text": "./blah"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"}]}}],
          {}),
         ([{"System": {"EventID": 1},
            "EventData":
            {
             "Data":
             [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
              {"@Name": "ProcessId", "#text": "1"},
              {"@Name": "ParentProcessId", "#text": "2"},
              {"@Name": "Image", "#text": "blah.exe"},
              {"@Name": "CommandLine", "#text": "./blah"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"}]}}],
          {'start_time': "1970-01-01 12:40:30.123",
           'end_time': "9999-12-31 23:59:59.999999",
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345679}', 'tag': 'blah.exe', 'treeid': None,
            'time_observed': "1970-01-01 12:40:30.123", 'ontology_id': 'process_4Kj6sgz5Y8rvIQnT9nPBS2',
            'processtree': None, 'service_name': 'CAPE',},
           'pobjectid': None,
           'pimage': None, 'pcommand_line': None, 'ppid': 2, 'pid': 1, 'image': 'blah.exe', 'command_line': './blah',
           'integrity_level': None, 'image_hash': None, 'original_file_name': None, 'services_involved': None, 'loaded_modules': None,}),
         ([{"System": {"EventID": 1},
            "EventData":
            {
             "Data":
             [
              {"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
              {"@Name": "ProcessId", "#text": "1"},
              {"@Name": "ParentProcessId", "#text": "2"},
              {"@Name": "Image", "#text": "blah.exe"},
              {"@Name": "CommandLine", "#text": "./blah"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"},
              {"@Name": "SourceProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"}]}}],
          {'start_time': "1970-01-01 12:40:30.123",
           'end_time': "9999-12-31 23:59:59.999999",
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345679}', 'tag': 'blah.exe', 'treeid': None,
            'time_observed': "1970-01-01 12:40:30.123", 'ontology_id': 'process_4Kj6sgz5Y8rvIQnT9nPBS2',
            'processtree': None, 'service_name': 'CAPE'},
           'pobjectid': None,
           'pimage': None, 'pcommand_line': None, 'ppid': 2, 'pid': 1, 'image': 'blah.exe', 'command_line': './blah',
           'integrity_level': None, 'image_hash': None, 'original_file_name': None, 'loaded_modules': None, 'services_involved': None}),
         ([{"System": {"EventID": 1},
            "EventData":
            {
             "Data":
             [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
              {"@Name": "ProcessId", "#text": "123"},
              {"@Name": "Image", "#text": "blah"}]}}],
          {'start_time': '1970-01-01 12:40:30.123', 'end_time': "9999-12-31 23:59:59.999999",
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': 'blah', 'treeid': None, 'processtree': None,
            'time_observed': '1970-01-01 12:40:30.123', 'ontology_id': 'process_5FPZdIxfHmzxsWKUlsSNGl', 'service_name': 'CAPE'},
           'pobjectid': None,
           'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': 123, 'image': 'blah', 'command_line': None,
           'integrity_level': None, 'image_hash': None, 'original_file_name': None, 'loaded_modules': None, 'services_involved': None}),
         ([{"System": {"EventID": 1},
            "EventData":
            {
             "Data":
             [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
              {"@Name": "ProcessId", "#text": "123"},
              {"@Name": "Image", "#text": "blah (deleted)"}]}},
           {"System": {"EventID": 5},
            "EventData":
            {
               "Data":
               [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:31.123"},
                {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
                   {"@Name": "ProcessId", "#text": "123"},
                   {"@Name": "Image", "#text": "blah"}]}}],
          {'start_time': '1970-01-01 12:40:30.123', 'end_time': "1970-01-01 12:40:31.123",
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': 'blah', 'treeid': None, 'processtree': None,
            'time_observed': '1970-01-01 12:40:30.123', 'ontology_id': 'process_5FPZdIxfHmzxsWKUlsSNGl', 'service_name': 'CAPE'},
           'pobjectid': None,
           'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': 123, 'image': 'blah', 'command_line': None,
           'integrity_level': None, 'image_hash': None, 'original_file_name': None, 'services_involved': None, 'loaded_modules': None}), ])
    def test_convert_sysmon_processes(sysmon, expected_process, mocker):
        so = OntologyResults(service_name="CAPE")
        mocker.patch.object(so, "sandboxes", return_value="blah")
        safelist = {}
        convert_sysmon_processes(sysmon, safelist, so)
        if expected_process:
            proc_as_prims = so.processes[0].as_primitives()
            _ = proc_as_prims["objectid"].pop("session")
            assert proc_as_prims == expected_process

    @staticmethod
    @pytest.mark.parametrize(
        "sysmon, actual_network, correct_network",
        [
            ([], {}, {}),
            ([], {}, {}),
            ([{"System": {"EventID": '1'}}], {}, {}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": []}, {'tcp': []}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "Protocol", "#text": "tcp"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": []}, {'tcp': [{'dport': 321, 'dst': '11.11.11.11', 'guid': '{blah}', 'image': 'blah.exe', 'pid': 123, 'sport': 123, 'src': '10.10.10.10', 'time': 1627054921.001}]}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "Protocol", "#text": "tcp"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": [{"dst": '11.11.11.11', "dport": 321, "src": '10.10.10.10', "sport": 123}]}, {'tcp': [
                                  {'dport': 321, 'dst': '11.11.11.11', 'guid': '{blah}', 'image': 'blah.exe', 'pid': 123, 'sport': 123,
                                   'src': '10.10.10.10', 'time': 1627054921.001}]}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "Protocol", "#text": "tcp"},
                                  {"@Name": "SourceIp", "#text": "::ffff:7f00:1"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": []}, {'tcp': []}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "Protocol", "#text": "tcp"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "::ffff:7f00:1"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": []}, {'tcp': []}),
            ([{
                "System": {"EventID": '22'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "QueryName", "#text": "blah.com"},
                                  {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                              ]
                              }}], {"dns": []}, {'dns': [
                                  {
                                      'answers': [{'data': '10.10.10.10', 'type': 'A'}],
                                      'guid': '{blah}',
                                      'image': 'blah.exe',
                                      'pid': 123,
                                      'request': 'blah.com',
                                      'first_seen': 1627054921.001,
                                      'type': 'A'
                                  }]}),
            ([{
                "System": {"EventID": '22'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "QueryName", "#text": "blah.com"},
                                  {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                              ]
                              }}], {"dns": []}, {'dns': []}),
            ([{
                "System": {"EventID": '22'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "QueryName", "#text": "blah.com"},
                                  {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                              ]
                              }}], {"dns": [{"request": "blah.com"}]}, {'dns': [
                                  {
                                      'answers': [{'data': '10.10.10.10', 'type': 'A'}],
                                      'guid': '{blah}',
                                      'image': 'blah.exe',
                                      'pid': 123,
                                      'request': 'blah.com',
                                      'first_seen': 1627054921.001,
                                      'type': 'A'
                                  }]}
             ),


        ]
    )
    def test_convert_sysmon_network_cuckoo(sysmon, actual_network, correct_network):
        safelist = {}
        convert_sysmon_network(sysmon, actual_network, safelist, convert_timestamp_to_epoch=True)
        assert actual_network == correct_network

    @staticmethod
    @pytest.mark.parametrize(
        "sysmon, actual_network, correct_network",
        [
            ([], {}, {}),
            ([], {}, {}),
            ([{"System": {"EventID": "1"}}], {}, {}),
            (
                [
                    {
                        "System": {"EventID": "3"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessGuid", "#text": "{blah}"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                {"@Name": "SourcePort", "#text": "123"},
                                {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                {"@Name": "DestinationPort", "#text": "321"},
                            ]
                        },
                    }
                ],
                {"tcp": []},
                {"tcp": []},
            ),
            (
                [
                    {
                        "System": {"EventID": "3"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessGuid", "#text": "{blah}"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "Protocol", "#text": "tcp"},
                                {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                {"@Name": "SourcePort", "#text": "123"},
                                {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                {"@Name": "DestinationPort", "#text": "321"},
                            ]
                        },
                    }
                ],
                {"tcp": []},
                {
                    "tcp": [
                        {
                            "dport": 321,
                            "dst": "11.11.11.11",
                            "guid": "{blah}",
                            "image": "blah.exe",
                            "pid": 123,
                            "sport": 123,
                            "src": "10.10.10.10",
                            "time": "2021-07-23 15:42:01.001",
                        }
                    ]
                },
            ),
            (
                [
                    {
                        "System": {"EventID": "3"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessGuid", "#text": "{blah}"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "Protocol", "#text": "tcp"},
                                {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                {"@Name": "SourcePort", "#text": "123"},
                                {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                {"@Name": "DestinationPort", "#text": "321"},
                            ]
                        },
                    }
                ],
                {"tcp": [{"dst": "11.11.11.11", "dport": 321, "src": "10.10.10.10", "sport": 123}]},
                {
                    "tcp": [
                        {
                            "dport": 321,
                            "dst": "11.11.11.11",
                            "guid": "{blah}",
                            "image": "blah.exe",
                            "pid": 123,
                            "sport": 123,
                            "src": "10.10.10.10",
                            "time": "2021-07-23 15:42:01.001",
                        }
                    ]
                },
            ),
            (
                [
                    {
                        "System": {"EventID": "22"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessGuid", "#text": "{blah}"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "QueryName", "#text": "blah.com"},
                                {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                            ]
                        },
                    }
                ],
                {"dns": []},
                {
                    "dns": [
                        {
                            "answers": [{"data": "10.10.10.10", "type": "A"}],
                            "guid": "{blah}",
                            "image": "blah.exe",
                            "pid": 123,
                            "request": "blah.com",
                            "first_seen": "2021-07-23 15:42:01.001",
                            "type": "A",
                        }
                    ]
                },
            ),
            (
                [
                    {
                        "System": {"EventID": "22"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "QueryName", "#text": "blah.com"},
                                {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                            ]
                        },
                    }
                ],
                {"dns": []},
                {"dns": []},
            ),
            (
                [
                    {
                        "System": {"EventID": "22"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessGuid", "#text": "{blah}"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "QueryName", "#text": "blah.com"},
                                {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                            ]
                        },
                    }
                ],
                {"dns": [{"request": "blah.com"}]},
                {
                    "dns": [
                        {
                            "answers": [{"data": "10.10.10.10", "type": "A"}],
                            "guid": "{blah}",
                            "image": "blah.exe",
                            "pid": 123,
                            "request": "blah.com",
                            "first_seen": "2021-07-23 15:42:01.001",
                            "type": "A",
                        }
                    ]
                },
            ),
            # Example where Sysmon registered the QueryResults but no IP was found
            (
                [
                    {
                        "System": {"EventID": "22"},
                        "EventData": {
                            "Data": [
                                {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                {"@Name": "ProcessGuid", "#text": "{blah}"},
                                {"@Name": "ProcessId", "#text": "123"},
                                {"@Name": "Image", "#text": "blah.exe"},
                                {"@Name": "QueryName", "#text": "blah.com"},
                                {"@Name": "QueryResults", "#text": "-"},
                            ]
                        },
                    }
                ],
                {"dns": [{"request": "blah.com", "answers": [{"data": "10.10.10.10", "type": "A"}],}]},
                {
                    "dns": [
                        {
                            "answers": [{"data": "10.10.10.10", "type": "A"}],
                            "guid": "{blah}",
                            "image": "blah.exe",
                            "pid": 123,
                            "request": "blah.com",
                            "first_seen": "2021-07-23 15:42:01.001",
                            "type": "A",
                        }
                    ]
                },
            ),
        ],
    )
    def test_convert_sysmon_network_cape(sysmon, actual_network, correct_network):
        safelist = {}
        convert_sysmon_network(sysmon, actual_network, safelist)
        assert actual_network == correct_network
