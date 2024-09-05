import os

TEMP_SERVICE_CONFIG_PATH ="/tmp/service_manifest.yml"

def setup_module():
    open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
    open_manifest.write("\n".join(['name: Sample', 'version: sample', 'docker_config: ', '  image: sample', 'heuristics:', '  - heur_id: 17', '    name: blah', '    description: blah', "    filetype: '*'", '    score: 250']))
    open_manifest.close()


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)
