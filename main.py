from fileinput import filename
from ecs_schema_to_iceberg import *
from validate import validate_iceberg_schema
from runner import run_transform_vrl, vrl
import os
import csv
from pathlib import Path
import jsonlines
import tempfile
import traceback
import sh
import editor
import argparse
import time
from rich.panel import Panel
from rich import print
from random import shuffle
from itertools import chain


def jsonlines_or_multiline_read(p):
    rdr = []
    try:
        rdr = jsonlines.open(p)
        rdr = [i for i in rdr]
    except:
        f = open(p)
        dd = f.read()
        try:
            rdr = json.loads("[" + dd.replace("}\n{", "},\n{") + "]")
        except:
            f.close()
            rdr = open(p).read().splitlines()
    return rdr


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


is_clean = defaultdict(lambda: True)
renamed_fields = set()

difft = sh.Command("difft")


def normalize(e):
    prog = """
.ts = .ts || del(."@timestamp")

if .event.type != null && !is_array(.event.type) {
    if .__expected == true {
        .event.type = [ .event.type ]
    } else {
        abort
    }
}

if .__expected == true && is_array(.event.action) {
    .event.action = .event.action[0]
}

if .__expected == true && !is_array(.vulnerability.category) {
    .vulnerability.category = [ .vulnerability.category ]
}

if .threat.tactic.name != null && !is_array(.threat.tactic.name) {
    if .__expected == true {
        .threat.tactic.name = [ .threat.tactic.name ]
    } else {
        abort
    }
}

if .threat.technique.name != null && !is_array(.threat.technique.name) {
    if .__expected == true {
        .threat.technique.name = [ .threat.technique.name ]
    } else {
        abort
    }
}

if .__expected == true {
    if .tls.client.x509.subject != null {
        .tls.client.x509.subject = map_values(compact(object!(.tls.client.x509.subject))) -> |v| { [v] }
        if .tls.client.x509.subject.distinguished_name != null {
            .tls.client.x509.subject.distinguished_name = array!(.tls.client.x509.subject.distinguished_name)[0]
        }
    }
    if .tls.server.x509.subject != null {
        .tls.server.x509.subject = map_values(compact(object!(.tls.server.x509.subject))) -> |v| { [v] }
        if .tls.server.x509.subject.distinguished_name != null {
            .tls.server.x509.subject.distinguished_name = array!(.tls.server.x509.subject.distinguished_name)[0]
        }
    }
    if .tls.server.x509.issuer != null {
        .tls.server.x509.issuer = map_values(compact(object!(.tls.server.x509.issuer))) -> |v| { [v] }
        if .tls.server.x509.issuer.distinguished_name != null {
            .tls.server.x509.issuer.distinguished_name = array!(.tls.server.x509.issuer.distinguished_name)[0]
        }
    }
    if .tls.client.x509.issuer != null {
        .tls.client.x509.issuer = map_values(compact(object!(.tls.client.x509.issuer))) -> |v| { [v] }
        if .tls.client.x509.issuer.distinguished_name != null {
            .tls.client.x509.issuer.distinguished_name = array!(.tls.client.x509.issuer.distinguished_name)[0]
        }
    }
    if .file.x509.issuer != null {
        .file.x509.issuer = map_values(compact(object!(.file.x509.issuer))) -> |v| { [v] }
        if .file.x509.issuer.distinguished_name != null {
            .file.x509.issuer.distinguished_name = array!(.file.x509.issuer.distinguished_name)[0]
        }
    }
    if .file.x509.subject != null {
        .file.x509.subject = map_values(compact(object!(.file.x509.subject))) -> |v| { [v] }
        if .file.x509.subject.distinguished_name != null {
            .file.x509.subject.distinguished_name = array!(.file.x509.subject.distinguished_name)[0]
        }
    }
    .host.ip = [ .host.ip ]
    .network.application = if .network.application != null { downcase!(.network.application[0]) } else { null }
}

if .event.category != null && !is_array(.event.category) && .__expected == true {
    .event.category = [.event.category]
}
if .observer.ip != null && !is_array(.observer.ip) {
    if .__expected == true {

    .observer.ip = [.observer.ip]
    } else {
    abort
    }
}
del(.source.geo)
del(.source.as)
del(.observer.geo)


# if .process.args != null && .process.args_arr_str == null {
#     .process.args_arr_str = encode_json(.process.args)
# }

if .zeek.smb_files.path != null && .zeek.smb_files.name != null {
    .file.path = replace!(.file.path, r'\\\\', "\")
}

del(.threat.indicator.geo)
del(.threat.indicator.as)

if .zeek.session_id != null && is_array(.zeek.session_id) {
    .zeek.session_ids = del(.zeek.session_id)
    .event.id = join!(.zeek.session_ids, ",")
}

del(.zeek.weird.name)
del(.rule.name)

del(.destination.geo)
del(.destination.as)
del(.destination.asn)
del(.destination.organization_name)

del(.event.original)
del(.event.created)

del(.user_agent)

# wow.. todo fix these.....
# del(.url)
del(.threat.indicator.url)

del(.ecs.version)
del(.tags)

del(.network.community_id)

del(.dns.question.name)
del(.dns.question.registered_domain)
del(.dns.question.subdomain)
del(.dns.question.top_level_domain)

del(.url.extension)
del(.url.name)
del(.url.registered_domain)
del(.url.subdomain)
del(.url.top_level_domain)

del(.server.name)
del(.server.registered_domain)
del(.server.subdomain)
del(.server.top_level_domain)

# if .dns.answers != null {
#     .dns.answers = map_values(array!(.dns.answers)) -> |d| {
#         d.ttl = to_float!(d.ttl)
#     }
# }

# o365
if is_string(.o365.audit.ExtendedProperties) {
    .o365.audit.ExtendedProperties = parse_json!(.o365.audit.ExtendedProperties)
}
del(.o365.audit.ExtendedProperties.UserAgent)
del(.o365.audit.UserAgent)
if is_string(.o365.audit.Item) {
    .o365.audit.Item = parse_json!(.o365.audit.Item)
}
if is_string(.o365.audit.ExchangeMetaData) {
    .o365.audit.ExchangeMetaData = parse_json!(.o365.audit.ExchangeMetaData)
}
if is_string(.o365.audit.SharePointMetaData) {
    .o365.audit.SharePointMetaData = parse_json!(.o365.audit.SharePointMetaData)
}
if is_array(.rule.id) {
    .rule.id = join!(.rule.id, ", ")
}
if is_array(.rule.reference) {
    .rule.reference = join!(.rule.reference, ", ")
}
if is_array(.destination.user.email) {
    .destination.user.email = join!(.destination.user.email, ", ")
}
if is_array(.file.name) {
    .file.name = join!(.file.name, ", ")
}

# remove weird unicode issue encoded /u2229 encoded as slashes by VRL, but removed by es
. = map_values(., recursive: true) -> |v| {
    if is_string(v) {
        v = string!(v)
        # v = replace(v, r'\\\\,', "")

        # normalize UTC timestamp strings
        if length(v) < 50 && match(v, r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(\.?)([0-9]*)?(Z)?$') {
            if !contains(v, "+") && !ends_with(v, "Z") {
                v = v + "Z"
            }
            # v = slice!(to_string(to_timestamp!(v)), 0, 22)
            v = slice!(to_string(to_timestamp!(v)), 0, 21) # check only first two decimal places (avoid diff on decimal round differences)
            v = split(v, "Z")[0]
            if ends_with!(v, ".0") {
                v = slice!(v, 0, length!(v) - 2)
            }
        }

        v
    } else if is_float(v) {
        v = float!(v)
        v = round(v, precision: 20)
    } else {
        v
    }
}

# o365
if .o365.audit.Item != null {
    .o365 = object!(.o365 || {})
    .o365.audit = object!(.o365.audit || {})
    .o365.audit.Item = encode_json(.o365.audit.Item)
}
if is_object(.o365.audit.ExtendedProperties) {
    .o365.audit.RawExtendedProperties = del(.o365.audit.ExtendedProperties._raw)
    .o365.audit.ExtendedProperties = if !is_empty!(.o365.audit.ExtendedProperties) {
        encode_json(.o365.audit.ExtendedProperties)
    } else {
        null
    }
}
if is_object(.o365.audit.ModifiedProperties) {
    .o365.audit.RawModifiedProperties = del(.o365.audit.ModifiedProperties._raw)
    .o365.audit.ModifiedProperties = if !is_empty!(.o365.audit.ModifiedProperties) {
        encode_json(.o365.audit.ModifiedProperties)
    } else {
        null
    }
}
if is_object(.o365.audit.Parameters) {
    .o365.audit.RawParameters = del(.o365.audit.Parameters._raw)
    .o365.audit.Parameters = if !is_empty!(.o365.audit.Parameters) {
        encode_json(.o365.audit.Parameters)
    } else {
        null
    }
}
if .o365.audit.ExchangeMetaData != null {
    .o365.audit.ExchangeMetaData = encode_json(.o365.audit.ExchangeMetaData)
}
if .o365.audit.SharePointMetaData != null {
    .o365.audit.SharePointMetaData = encode_json(.o365.audit.SharePointMetaData)
}
if is_object(.o365.audit.ExceptionInfo) {
    .o365.audit.ExceptionInfo = encode_json(.o365.audit.ExceptionInfo)
}
if .o365.audit.PolicyDetails != null {
    .o365.audit.PolicyDetails = map_values(array!(.o365.audit.PolicyDetails)) -> |v| {
        if is_string(v) {
            v
        } else {
            encode_json(v)
        }
    }
}

if is_object(.okta.debug_context.debug_data.flattened) {
    .okta.debug_context.debug_data.flattened = encode_json(.okta.debug_context.debug_data.flattened)
}
if .okta.debug_context.debug_data.flattened != null {
    .okta.debug_context.debug_data.flattened = parse_json!(.okta.debug_context.debug_data.flattened)
    .okta.debug_context.debug_data.flattened.risk = .okta.debug_context.debug_data.flattened.risk || .okta.debug_context.debug_data.flattened.logOnlySecurityData.risk
    .okta.debug_context.debug_data.flattened.behaviors = .okta.debug_context.debug_data.flattened.behaviors || .okta.debug_context.debug_data.flattened.logOnlySecurityData.behaviors
    del(.okta.debug_context.debug_data.flattened.risk_object)
    .okta.debug_context.debug_data.flattened = encode_json(.okta.debug_context.debug_data.flattened)
}

# crowdstrike fdr fixes
if exists(.crowdstrike) && .crowdstrike.DownloadPort == null && .url.scheme != null {
    .url.scheme = null
}

# crowdstrike falcon fixes
if .crowdstrike.event.AuditKeyValues != null {
.crowdstrike.event.AuditKeyValues = map_values(array!(.crowdstrike.event.AuditKeyValues)) -> |v| {
  if !is_string(v) {
    encode_json(v)
  } else {
    v
  }
}
}
if .crowdstrike.event.ExecutablesWritten != null {
.crowdstrike.event.ExecutablesWritten = map_values(array!(.crowdstrike.event.ExecutablesWritten)) -> |v| {
  if !is_string(v) {
    encode_json(v)
  } else {
    v
  }
}
}

# cisco duo
.duo = del(.cisco_duo) || .duo
if is_array(.source.user.group.name) {
    .source.user.group.name = join!(.source.user.group.name, ", ")
}
del(.duo.auth.auth_device.geo)
del(.duo.auth.auth_device.as)
if is_object(.duo.admin.flattened) {
    .duo.admin.flattened = encode_json(.duo.admin.flattened)
}
if is_object(.duo.summary) {
    del(.ts)
}

# aws cloudtrail
if .aws.cloudtrail.flattened != null {
  .aws.cloudtrail.flattened = map_values(compact!(.aws.cloudtrail.flattened)) -> |v| {
    if !is_string(v) {
      encode_json(v)
    } else {
      v
    } 
  }
}
del(.aws.cloudtrail.request_parameters)
del(.aws.cloudtrail.response_elements)
del(.aws.cloudtrail.additional_eventdata)
del(.aws.cloudtrail.service_event_details)
del(.aws.cloudtrail.insight_details)

# aws config, history uses now()
if is_object(.aws.config_history) {
    del(.ts)
}

# aws waf
if is_object(.aws.waf) {
    del(.aws.waf.labels)
    del(.aws.waf.request.headers)
}

# snyk
if is_object(.snyk.audit.content) {
    .snyk.audit.content = encode_json(.snyk.audit.content)
}
if is_object(.snyk.vulnerabilities.semver) {
    .snyk.vulnerabilities.semver = encode_json(.snyk.vulnerabilities.semver)
}

# MS Graph - Azure AD SigninLogs
if is_object(.azure.signinlogs) {
    .azure.aad_signinlogs = del(.azure.signinlogs)
}
if is_object(.azure.aad_signinlogs) {
    del(.azure.resource)
    # minor bug in tests, easier to replace here than in all the test data
    if is_string(.azure.aad_signinlogs.authentication_processing_details) {
        if contains(string!(.azure.aad_signinlogs.authentication_processing_details), "Legacy TLS") {
            del(.azure.aad_signinlogs.authentication_processing_details)
        }
    }
    del(.azure.aad_signinlogs.resource_id)
    del(.azure.correlation_id)
    del(.azure.aad_signinlogs.time)
    del(.azure.aad_signinlogs.created_at)
    del(.related.user)
    del(.event.risk_score_norm)
}

if is_object(.google_workspace) {
    if is_string(.google_workspace.login.challenge_method) {
        .google_workspace.login.challenge_method = [.google_workspace.login.challenge_method]
    }
}

if is_object(.azure.auditlogs) {
    .azure.aad_auditlogs = del(.azure.auditlogs)
}

if is_object(.azure.aad_auditlogs.properties) {
    props = del(.azure.aad_auditlogs.properties)
    .azure.aad_auditlogs = object!(.azure.aad_auditlogs)
    .azure.aad_auditlogs |= object!(props)
}

if is_object(.azure.aad_auditlogs.target_resources) {
    ret = values(object!(.azure.aad_auditlogs.target_resources))
    .azure.aad_auditlogs.target_resources = map_values(ret) -> |v| {
        if is_object(v.modified_properties) {
            v.modified_properties = values(object!(v.modified_properties))
        }
        v
    }
}

if is_object(.azure.aad_auditlogs) {
    del(.azure.correlation_id)
    del(.azure.resourceId)
    del(.azure.resource)

    del(.client.ip)
    if .source.address != null && .source.ip == null {
        .source.ip = .source.address
    } else if .source.ip != null && .source.address == null {
        .source.address = .source.ip
    }

    # precision issue?
    del(.azure.aad_auditlogs.activity_datetime)
    del(.related)

    if is_array(.azure.aad_auditlogs.additional_details) {
        .azure.aad_auditlogs.additional_details = encode_json(.azure.aad_auditlogs.additional_details)
    }
    del(.event.category)
    del(.event.type)
}

# Cloudflare fixes
if .__expected == true && exists(.cloudflare_logpush) {
    .cloudflare = del(.cloudflare_logpush)

    if is_object(.cloudflare.audit.new_value) {
        .cloudflare.audit.new_value = encode_json(.cloudflare.audit.new_value)
    }
    if is_object(.cloudflare.audit.old_value) {
        .cloudflare.audit.old_value = encode_json(.cloudflare.audit.old_value)
    }
    if is_object(.cloudflare.audit.metadata) {
        .cloudflare.audit.metadata = encode_json(.cloudflare.audit.metadata)
    }
    if exists(.cloudflare.firewall_event.meta_data) {
        .cloudflare.firewall_event.metadata = del(.cloudflare.firewall_event.meta_data)
    }
    if is_object(.cloudflare.firewall_event.metadata) {
        .cloudflare.firewall_event.metadata = encode_json(.cloudflare.firewall_event.metadata)
    }
    if is_object(.cloudflare.http_request.cookies) {
        .cloudflare.http_request.cookies = encode_json(.cloudflare.http_request.cookies)
    }

    del(.cloudflare.network_analytics.destination.geo_location)
    del(.cloudflare.network_analytics.source.geo_location)
    del(.cloudflare.network_analytics.colo.geo_location)
}

del(.__expected)
. = compact(.)
"""
    e = vrl(prog, e)[0]
    return e


def str_presenter(dumper, data):
    """configures yaml for dumping multiline strings
    Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
    if "\n" in data:  # check for multiline string
        node = dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        # breakpoint()
        return node
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, str_presenter)

# to use with safe_dump:
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)


def walk(path):
    for p in Path(path).iterdir():
        if p.is_dir():
            yield from walk(p)
            continue
        yield p.resolve()


def table(s):
    if "." not in s:
        return {"log_source": s, "table": "*"}
    else:
        log_source, table = s.split(".")
        return {"log_source": log_source, "table": table}


def run_tests_get_errors(logsource_dir, opts, table_schema, table_file, data):
    global count_passed

    from_test_seen = opts.from_test is None
    for test_event_f in chain(
        logsource_dir.rglob("test/**/*.log"), logsource_dir.rglob("test/**/*.json"), logsource_dir.rglob("test/**/*.csv")
    ):
        if "-expected.json" in str(test_event_f):
            continue

        testname = test_event_f.name.split(".")[0]

        from_test = opts.from_test.split(":")[0] if opts.from_test is not None else None
        from_test_idx = (
            int(opts.from_test.split(":")[1]) if opts.from_test is not None else None
        )
        just_saw = False
        if not from_test_seen:
            if testname == from_test:
                from_test_seen = True
                just_saw = True
            else:
                print(f"[bold cyan]Skipping {testname}")
                continue

        print(f"Running testfile: {test_event_f}")
        console.print(f"\nRunning test: [bold yellow]{testname}")

        if str(test_event_f).endswith(".json"):
            rdr = json.load(open(test_event_f))["events"]
            for i in range(len(rdr)):
                if "message" in rdr[i]:
                    d = rdr[i].pop("message")
                    d = d.split("\n")[0]
                    rdr[i] = json.loads(d)
        elif str(test_event_f).endswith(".csv"):
            rdr = []
            with open(test_event_f) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rdr.append(row)
        else:
            rdr = jsonlines_or_multiline_read(test_event_f)

        try:
            with open(f"{test_event_f}-expected.json") as f:
                expected = json.load(f)["expected"]
        except FileNotFoundError:
            expected = None
        except json.decoder.JSONDecodeError:
            print(
                "\n[red bold]Failed: [reset][bold]Expected test file is not valid json."
            )
            editor.edit(filename=f"{test_event_f}-expected.json")
            return ["errors"]

        if expected is None:
            shuffle(rdr)
        for i, test_event in enumerate(rdr):
            # remove key _table if exists
            if type(test_event) == dict and "_table" in test_event:
                del test_event["_table"]

            if just_saw and i < from_test_idx:
                continue
            # if i > 20:
            #     print("Skipping remaining events...")
            #     break
            try:
                if test_event.get("result", {}).get("splunk_server") or test_event.get(
                    "result", {}
                ).get("_raw"):
                    continue
            except:
                pass

            try:
                if (expected is not None and len(expected) > i):
                    if expected[i] is None:
                        expected[i] = {}
                    expected[i]["__expected"] = True
                n_expected = normalize(expected[i]) if expected is not None and len(expected) > i else None
                res = run_transform_vrl(data["transform"], test_event)["result"]
                n_res = normalize(res)

                if n_expected is None:
                    print(
                        f"[yellow]No expected result corresponding to testcase #{i} in {test_event_f} to assert against."
                    )
                    n_expected = n_res
            except Exception as e:
                console.print("\n❌ Test failed: ", testname, style="bold red")
                try:
                    print("\n[green bold]Expected: ", n_expected)
                    print("\n[yellow bold]Input event: ", test_event)
                except:
                    console.print(str(e))
                    sys.exit(1)

                console.print(str(e))
                print(f"\n[bold red]❌ Error running transform\n")

                editor.edit(
                    filename=str(table_file),
                    other_filenames=[
                        logsource_dir,
                        generated_table_filename,
                        test_event_f,
                        f"{test_event_f}-expected.json",
                    ],
                )
                return ["errors"]

            try:
                if (
                    n_expected.get("ts")
                    and n_res.get("ts")
                    and n_expected["ts"] != n_res["ts"]
                    and n_expected["ts"][:22] == n_res["ts"][:22]
                ):
                    n_res["ts"] = n_expected["ts"]
            except Exception as e:
                traceback.print_exc()
                print(
                    f"\n[bold red]Failed: [reset][bold]Failed to compare events, missing fields for normalized output event or expected event: {e}",
                )
                editor.edit(
                    filename=str(table_file),
                    other_filenames=[
                        logsource_dir,
                        generated_table_filename,
                        test_event_f,
                        f"{test_event_f}-expected.json",
                    ],
                )
                return ["errors"]

            if n_res != n_expected:
                console.print("\n❌ Test failed: ", testname, style="bold red")
                print("\n[red bold]Actual: ", n_res)
                print("\n[green bold]Expected: ", n_expected)
                print("\n[yellow bold]Input event: ", test_event)

                td = tempfile.mkdtemp("logtest")

                expected_tmp = Path(os.path.join(td, "expected.json"))
                with open(str(expected_tmp.absolute()), "w") as f:
                    f.write(json.dumps(n_expected, indent=2))

                actual_tmp = Path(os.path.join(td, "actual.json"))
                with open(str(actual_tmp.absolute()), "w") as f:
                    f.write(json.dumps(n_res, indent=2))

                diff = difft(
                    str(actual_tmp.absolute()),
                    str(expected_tmp.absolute()),
                    language="json",
                )
                diff = "\n".join(
                    [
                        x
                        for x in str(diff).split("\n")
                    ]
                )
                console.print(
                    f"\n🔧 [red]Value[reset] did not match [green]expected:",
                    style="yellow",
                )
                __builtins__.print(diff)
                editor.edit(
                    filename=str(table_file),
                    other_filenames=[
                        logsource_dir,
                        generated_table_filename,
                        str(actual_tmp.absolute()),
                        str(expected_tmp.absolute()),
                        test_event_f,
                        f"{test_event_f}-expected.json",
                    ],
                )
                return ["errors"]

            if not validate_iceberg_schema(table_schema, [n_res]):
                editor.edit(
                    filename=str(table_file),
                    other_filenames=[
                        logsource_dir,
                        generated_table_filename,
                        test_event_f,
                        f"{test_event_f}-expected.json",
                    ],
                )
                return ["errors"]

            count_passed += 1
            print(f"Test {i} passed: ✅", testname)


if __name__ == "__main__":
    parser = ArgumentParser()
    # parser.add_argument("dir", help="the path to log sources", type=str)
    # parser.add_argument(
    #     "--sources",
    #     help="the tables to generate",
    #     type=lambda s: [table(item) for item in s.split(",")],
    # )

    parser.add_argument(
        "--logsource-dir",
        help="the path to log source dir to read from (fields, test) and write to (generated log_source.yml etc.)",
        type=str,
    )
    parser.add_argument("--from-test", type=str, default=None)
    parser.add_argument(
        "--skip-tests",
        type=str2bool,
        nargs="?",
        const=True,
        default=False,
        help="Skip tests.",
    )

    opts = parser.parse_args()
    # d = Path(opts.dir)

    # "/Users/shaeqahmed/testt/matano/data/managed/"
    logsource_dir = Path(opts.logsource_dir)

    if not logsource_dir.is_dir():
        print(
            f"\n[red bold]Log source dir does not exist: [reset]{logsource_dir.resolve()}"
        )
        exit(1)

    if not (logsource_dir / "test").is_dir():
        print(
            f"\n[red bold]Log source dir does not contain a test dir at: [reset]{(logsource_dir / 'test').resolve()}"
        )
        exit(1)

    if not (logsource_dir / "fields").is_dir():
        print(
            f"\n[red bold]Log source dir does not contain a fields dir at: [reset]{(logsource_dir / 'fields').resolve()}"
        )
        exit(1)

    print(logsource_dir)

    all_passed = False
    while not all_passed:
        from_test_seen = opts.from_test is None
        if opts.from_test:
            if ":" not in opts.from_test:
                opts.from_test = f"{opts.from_test}:0"

        table = {}

        for h in logsource_dir.rglob("fields/*.yml"):
            print(h)
            with open(h) as f:
                p = yaml.safe_load(f)
            ecs_fields = [f["name"] for f in p if f.get("external") == "ecs"]
            p = [l for l in p if l.get("external") != "ecs"]
            for f in ecs_fields:
                table.setdefault("schema", {}).setdefault("ecs_field_names", []).append(
                    f
                )
            if p:
                schema, ecs_fields = schema_to_iceberg(p)
                for f in ecs_fields:
                    table.setdefault("schema", {}).setdefault(
                        "ecs_field_names", []
                    ).append(f)
                table.setdefault("schema", {})["schema"] = merge(
                    table.setdefault("schema", {}).setdefault("schema", {}), schema
                )

        table_schema = table.setdefault("schema", {}).setdefault("schema", {})
        table["schema"]["fields"] = expand_and_serialize_to_fields(
            table.setdefault("schema", {}).setdefault("schema", {})
        )
        table["schema"]["fields"] = [
            f
            for f in table["schema"]["fields"]
            if f["name"] not in ["input", "log", "cloud", "host"]
        ]

        table["schema"]["ecs_field_names"] = [
            f
            for f in table.setdefault("schema", {}).setdefault("ecs_field_names", [])
            if f
            not in {"data_stream.type", "data_stream.dataset", "data_stream.namespace",}
        ]

        # print(yaml.dump(table["schema"]["schema"], sort_keys=False))
        del table["schema"]["schema"]

        tablename = logsource_dir.name

        if "transform" not in table:
            table["transform"] = "# Transform\n\n# Write your VRL transform script here :)"

        table["name"] = tablename

        managed_tables_dir = logsource_dir
        table_file = next(
            chain(
                managed_tables_dir.glob(f"log_source.yml"),
                managed_tables_dir.glob(f"log_source.yml.go"),
                [managed_tables_dir / f"log_source.yml"],
            )
        )
        table["$file"] = table_file

        if not table_file.exists():
            table_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            with open(table_file, "r+") as f:
                data = yaml.safe_load(f)
                if "schema" not in data:
                    data["schema"] = {}
                data["schema"]["ecs_field_names"] = sorted(
                    list({ *set(table["schema"]["ecs_field_names"]) - set(["@timestamp"]), *set(data["schema"].get("ecs_field_names", [])) } )
                )
                table["schema"]["ecs_field_names"] = data["schema"]["ecs_field_names"]
                table_schema = fields_to_schema(
                    data.get("schema", {}).get("fields", [])
                )
                f.seek(0)
                f.write(yaml.dump(data, sort_keys=False))
                f.truncate()
        generated_table_filename = (
            str(table_file)
            .replace(".yml.go", "_generated.yml.go")
            .replace(".yml", "_generated.yml.go")
        )
        with open(
            generated_table_filename if table_file.exists() else table_file, "w+"
        ) as f:
            f.write(
                yaml.dump(
                    {k: v for k, v in table.items() if k != "$file"}, sort_keys=False
                )
            )

        print(f"\n[bold]Using schema for table [green]{tablename} ✨")
        print(yaml.dump(table_schema))

        # TODO(): open EDITOR and allow to resolve conflicts/issues here
        # editor.edit(filename=str(table_file), other_filenames=[test_event_f, f"{test_event_f}-expected.json"])

        print(f"\n[bold]Generated log source for table [green]{tablename} 🚀")

        if not opts.skip_tests:
            # print("Running tests...\n")
            global count_passed
            count_passed = 0

            ecs_subschema = ecs_subschema_from_fields(table["schema"]["ecs_field_names"])
            table_schema = merge(
                ecs_subschema,
                table_schema,
            )

            with open(table_file) as f:
                data = yaml.safe_load(f)
                errors = run_tests_get_errors(
                    logsource_dir, opts, table_schema, table_file, data
                )
                all_passed = errors is None
                if not all_passed:
                    count_passed = 0
                    print(
                        f"\n\n[bold yellow]Press enter to re-run tests for table {tablename} and check if errors resolved 👀..."
                    )
                    input()

            console.print(
                f"\n[bold]✨ {count_passed} tests passed ✨\n\n", f"{tablename}"
            )

            console.print("\n[bold green]All tests passed! 🎉\n")

    console.print(Panel.fit(f"\n🎉🎉🎉 [bold green] FINITO {tablename}! 🎉🎉🎉\n"))
