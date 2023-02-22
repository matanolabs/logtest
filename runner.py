import json
import requests
import yaml
from pathlib import Path
import pyperclip
import sys

from rich import print

url = "http://0.0.0.0:8080/resolve"

from argparse import ArgumentParser

template = """
if .message != null {{
    .json, err = parse_json(string!(.message))
    if err == null {{
        del(.message)
    }}
}}

.related.ip = []
.related.hash = []
.related.user = []

{}
del(.json)

. = compact(.)
.ecs.version = "8.0.0"
"""


def run_transform_vrl(prog, event):
    prog = template.format(prog)
    if type(event) == dict:
        event = {"json": event}
    else:
        assert type(event) == str
        event = {"message": event}
    # pyperclip.copy(prog)

    result, output = vrl(prog, event)
    return {
        "result": result,
        "output": output,
    }


def vrl(prog, event):
    try:
        payload = json.dumps({"program": prog, "event": event})
        headers = {"Content-Type": "application/json"}
        response = requests.request("POST", url, headers=headers, data=payload)
        res = json.loads(response.text)
        if res.get("error"):
            error_suffix = ""
            if "call to undefined function" in res["error"]:
                error_suffix = f"\n[bold yellow]WARNING: Missing function in VRL program.[/bold yellow]\n\n[bold white]Please make sure you have the latest version of the vrl-web server running from [/bold white]\n[bold cyan]https://github.com/shaeqahmed/vrl-web[/bold cyan]\n\n[bold yellow]If you are using the latest version, please open an issue.[/bold yellow]"
            raise Exception(res["error"] + error_suffix)
        return res["success"]["result"], res["success"]["output"]
    except requests.exceptions.ConnectionError:
        print(
            "\n[bold red]Error: [/bold red]Could not connect to Vector Remap Language (VRL) server. Please make sure it is running at http://0.0.0.0:8080 (cargo run)"
        )
        sys.exit(1)


if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("file", type=str)
    opts = parser.parse_args()

    with open(Path(opts.file)) as f:
        pipeline = yaml.safe_load(f)
        event = {
            "ts": 1591367999.512593,
            "uid": "C5bLoe2Mvxqhawzqqd",
            "id.orig_h": "192.168.4.76",
            "id.orig_p": 46378,
            "id.resp_h": "31.3.245.133",
            "id.resp_p": 80,
            "trans_depth": 1,
            "method": "GET",
            "host": "testmyids.com",
            "uri": "/",
            "version": "1.1",
            "user_agent": "curl/7.47.0",
            "request_body_len": 0,
            "response_body_len": 39,
            "status_code": 200,
            "status_msg": "OK",
            "tags": [],
            "resp_fuids": ["FEEsZS1w0Z0VJIb5x4"],
            "resp_mime_types": ["text/plain"],
        }
        run_transform_vrl(pipeline["transform"], event)
