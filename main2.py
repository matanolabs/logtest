from fileinput import filename
from ecs_schema_to_iceberg import *
from ecs_pipeline_to_vrl import *
# from validate import validate_iceberg_schema
# from runner import run_transform_vrl, vrl
import os
import csv
from pathlib import Path
import jsonlines
import tempfile
import requests
import traceback
import sh
import editor
import argparse
import time
from rich.panel import Panel
from rich import print
from random import shuffle
from itertools import chain

def compact(my_dict):
    temp_dict = {}
    for k, v in my_dict.items():
        if v:
            if isinstance(v, dict):
                 return_dict = compact(v)
                 if return_dict:
                     temp_dict[k] = return_dict
            elif isinstance(v, list):
                return_list = []
                for i in v:
                    if isinstance(i, dict):
                        return_dict = compact(i)
                        if return_dict:
                            return_list.append(return_dict)
                    else:
                        return_list.append(i)
                if return_list:
                    temp_dict[k] = return_list
            else:
                temp_dict[k] = v
    return temp_dict


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


def run_tests_get_errors(logsource_dir, opts, table_schema, table_file, data, update_snapshot=False, replace_expected=False):
    global count_passed

    tablename = opts.table_name if opts.table_name else "default"
    logsourcename = opts.log_source
    resolved_tablename = f"{logsourcename}_{tablename}" if tablename != "default" else logsourcename

    res = requests.post(
        f"http://127.0.0.1:3030/test",
        json={
            "directory": str(logsource_dir.parent.parent),
            "managed_tables": [resolved_tablename],
        },
    )
    if res.status_code != 200:
        print("Failed to run tests")
        print(res.text)
        return ["errors"]
    
    res = res.json()

    # flatten res array
    res = [item for sublist in res for item in sublist]

    # open editor with just res in temp file
    if res and opts.open_results:
        td = tempfile.mkdtemp("logtest")

        res_tmp = Path(os.path.join(td, "res.json"))
        with open(str(res_tmp.absolute()), "w") as f:
            f.write(json.dumps(res, indent=2))

        editor.edit(
            filename=str(res_tmp.absolute()),
        )

    for test_case_result in res:
        test_case_filenames = []
        for path in (logsource_dir / "test" / tablename).rglob("*"):
            if path.is_file() and test_case_result["test_case_name"].replace("_", "-") in str(path):
                test_case_filenames.append(str(path))

        if test_case_result["all_passed"]:
            count_passed += len(test_case_result["actual_results"])
            print(f"✅ Test {test_case_result['test_case_name']} w/ {len(test_case_result['actual_results'])} logs passed")
        else:
            # open vscode with diff
            testname = test_case_result["test_case_name"]

            failing_diff_log_index = None
            failing_diff_message = None
            for error in test_case_result["errors"]:
                if error["error_info"]["error_type"] == "TransformDiffError":
                    failing_diff_log_index = error["log_index"]
                    failing_diff_message = error["error_info"]["error_message"]
                    break
            
            if not update_snapshot and not replace_expected and failing_diff_log_index is not None:
                console.print("\n❌ Test failed: ", testname, style="bold red")

                expected = test_case_result["expected_results"][failing_diff_log_index]
                actual = None
                actual_obj = test_case_result["actual_results"][failing_diff_log_index]
                if actual_obj:
                    actual = actual_obj.get("final_for_diff") or actual_obj.get("final") or actual_obj.get("transformed")

                td = tempfile.mkdtemp("logtest")

                expected_tmp = Path(os.path.join(td, "expected.json"))
                with open(str(expected_tmp.absolute()), "w") as f:
                    f.write(json.dumps(expected, indent=2))
                
                actual_tmp = Path(os.path.join(td, "actual.json"))
                with open(str(actual_tmp.absolute()), "w") as f:
                    f.write(json.dumps(actual, indent=2))

                diff = difft(
                    str(actual_tmp.absolute()),
                    str(expected_tmp.absolute()),
                    language="json",
                )

                diff = "\n\n".join(
                    [
                        x
                        for x in str(diff).split("\n")
                    ]
                )

                console.print(
                    f"\n🔧 [red]Value[reset] did not match [green]expected:\n",
                    style="yellow",
                )
                console.print(failing_diff_message)

                # __builtins__.print(diff)
                editor.edit(
                    filename=str(table_file),
                    other_filenames=[x for x in [
                        logsource_dir,
                        generated_table_filename,
                        str(actual_tmp.absolute()),
                        str(expected_tmp.absolute()),
                        *test_case_filenames,
                        # test_event_f, # TODO(): open the test file and highlight the failing log
                        # f"{test_event_f}-expected.json",
                    ] if x is not None],
                )
                return test_case_result["errors"]
            
            for error in test_case_result["errors"]:
                if error["error_info"]["error_type"] == "TransformDiffError":
                    continue

                failing_log_index = error["log_index"]
                failing_actual_obj = test_case_result["actual_results"][failing_log_index]
                failing_actual = None
                if failing_actual_obj:
                    failing_actual = failing_actual_obj.get("final_for_diff") or failing_actual_obj.get("final") or failing_actual_obj.get("transformed")
                failing_expected = test_case_result["expected_results"][failing_log_index]
                console.print("\n❌ Test failed: ", testname, ":", failing_log_index, style="bold red")
                console.print("\❌ [red bold]Message: ", error["error_info"]["error_message"],)

                td = tempfile.mkdtemp("logtest")

                expected_tmp = Path(os.path.join(td, "expected.json"))
                with open(str(expected_tmp.absolute()), "w") as f:
                    f.write(json.dumps(failing_expected, indent=2))
                
                actual_tmp = Path(os.path.join(td, "actual.json"))
                with open(str(actual_tmp.absolute()), "w") as f:
                    f.write(json.dumps(failing_actual, indent=2))

                editor.edit(
                    filename=str(table_file),
                    other_filenames=[x for x in [
                        logsource_dir,
                        generated_table_filename,
                        str(actual_tmp.absolute()),
                        str(expected_tmp.absolute()),
                        *test_case_filenames,
                        # test_event_f, # TODO(): open the test file and highlight the failing log
                        # f"{test_event_f}-expected.json",
                    ] if x is not None],
                )

                return test_case_result["errors"]

    seen_warnings = set()
    for test_case_result in res:
        # print warnings with color / emoji warning sign. text ontent bold white but heaeers yellow
        if test_case_result["warnings"]:
            for warning in test_case_result["warnings"]:
                warning_message = warning['warning_info']['warning_message'].replace("\n", ", ")
                if warning_message in seen_warnings:
                    continue
                seen_warnings.add(warning_message)
                print(f"\n❗️  [yellow bold]Warning ({warning['warning_info']['warning_type']}): {warning_message}")
                if warning["log_index"] is not None:
                    print(f"\n❗️  [yellow bold]Warning log index: {warning['log_index']}")


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument(
        "--matano-integrations-dir",
        help="the path to log source dir to read from (fields, test) and write to (generated log_source.yml etc.)",
        type=str,
    )
    parser.add_argument(
        "--log-source",
        help="the log source to reference and write to",
        type=str,
    )
    parser.add_argument(
        "--table-name",
        help="the table to reference and write to",
        type=str,
        default=None
    )
    parser.add_argument(
        "--pin-to-log-source",
        help="pin the table schema to the log source level",
        nargs="?",
        const=True,
        default=False,
        type=str2bool,
    )
    parser.add_argument(
        "--ecs-data-stream-dir",
        help="the source path to read ECS formatted fields (folders: fields, test, pipeline) from and use to generate or merge in to the destination log_source.yml/<table>.yml etc.)",
        type=str,
    )
    parser.add_argument(
        "--update-snapshot",
        type=str2bool,
        nargs="?",
        const=True,
        default=False,
        help="Update snapshot.",
    )
    parser.add_argument(
        "--replace-expected",
        type=str2bool,
        nargs="?",
        const=True,
        default=False,
        help="Overwrite expected files.",
    )
    parser.add_argument(
        "--exclude-test-sync-pattern",
        type=str,
        default=None,
        help="Exclude tests matching this pattern when syncing from ECS data stream dir to log source table dir in matano-integrations.",
    )
    parser.add_argument(
        "--include-test-sync-pattern",
        type=str,
        default=None,
        help="Include tests matching this pattern when syncing from ECS data stream dir to log source table dir in matano-integrations.",
    )
    parser.add_argument(
        "--pipeline",
        help="the pipeline to reference",
        type=str,
        default=None
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
    parser.add_argument(
        "--open-results",
        type=str2bool,
        nargs="?",
        const=True,
        default=False,
        help="Open test results in a code window first.",
    )
    parser.add_argument(
        "--sync-ecs",
        type=str2bool,
        nargs="?",
        const=True,
        default=False,
        help="Do not sync ECS data stream dir schema configuration + tests to log source table dir in matano-integrations.",
    )

    opts = parser.parse_args()
    # d = Path(opts.dir)

    # /Users/shaeqahmed/tempes2stuff/integrations/packages/m365_defender/data_stream/event
    ecs_stream_dir = Path(opts.ecs_data_stream_dir) if opts.ecs_data_stream_dir else None
    sync_ecs = opts.sync_ecs and ecs_stream_dir

    # /Users/shaeqahmed/tempes2stuff/integrations/packages/m365_defender/data_stream/event/_dev/test/pipeline/* 
    ecs_tests_dir = ecs_stream_dir / "_dev/test/pipeline" if ecs_stream_dir else None

    # "/Users/shaeqahmed/testt/matano-integrations/integrations/log_sources/<log_source>"
    matano_integrations_dir = Path(opts.matano_integrations_dir)
    logsource_dir = matano_integrations_dir / "log_sources" / opts.log_source

    tablename = opts.table_name if opts.table_name else "default"
    logsourcename = opts.log_source
    resolved_tablename = f"{logsourcename}_{tablename}" if tablename != "default" else logsourcename
    
    # rsync these ecs_tests_dir files into the log_source_dir / "test" dir
    if sync_ecs:
        if ecs_tests_dir:
            print(f"rsyncing {ecs_tests_dir} to {logsource_dir /  'test' / tablename}")
            for path in ecs_tests_dir.rglob("*"):
                if path.is_file():
                    if not (logsource_dir / "test" / tablename).is_dir():
                        (logsource_dir / "test" / tablename).mkdir(parents=True, exist_ok=True)
                    if opts.exclude_test_sync_pattern:
                        re_match = re.search(opts.exclude_test_sync_pattern, str(path))
                        if re_match:
                            print(f"Skipping test {path} due to exclude pattern.")
                            continue
                    if opts.include_test_sync_pattern:
                        re_match = re.search(opts.include_test_sync_pattern, str(path))
                        if not re_match:
                            print(f"Skipping test {path} due to include pattern.")
                            continue
                    sh.rsync("-av", str(path), str(logsource_dir / "test" / tablename))

        pipeline_path = Path(opts.pipeline) if opts.pipeline else None
        if not pipeline_path and ecs_stream_dir:
            for path in ecs_stream_dir.rglob("elasticsearch/ingest_pipeline/*.yml"):
                if opts.table_name in path.name:
                    pipeline_path = path
                    print(f"Using inferred pipeline: {pipeline_path}")
                    break
            if not pipeline_path and (ecs_stream_dir / "elasticsearch/ingest_pipeline/default.yml").is_file():
                pipeline_path = ecs_stream_dir / "elasticsearch/ingest_pipeline/default.yml"
                print(f"Using inferred pipeline: {pipeline_path}")

        pipeline_paths = [pipeline_path] if pipeline_path else []
        # if pipeline_path is not a default.yml as name, check if a default.yml exists in the same dir and add it to pipeline_paths
        if pipeline_path and not pipeline_path.name == "default.yml":
            if (pipeline_path.parent / "default.yml").is_file():
                pipeline_paths = [pipeline_path.parent / "default.yml", pipeline_path,]
        print(f"Using pipelines: {pipeline_paths}")
    else:
        pipeline_paths = []

    if not logsource_dir.is_dir():
        print(
            f"\n[red bold]Log source dir does not exist: [reset]{logsource_dir.resolve()}"
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
        table_schema = None
        generated_table_filename = None

        managed_tables_dir = logsource_dir / "tables"
        table_file = next(
            chain(
                managed_tables_dir.glob(f"{tablename}.yml"),
                managed_tables_dir.glob(f"{tablename}.yml.go"),
                [managed_tables_dir / f"{tablename}.yml"],
            )
        )
        ls_file = logsource_dir / "log_source.yml"

        if sync_ecs:
            for h in ecs_stream_dir.rglob("fields/*.yml"):
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
                not in {"data_stream.type", "data_stream.dataset", "data_stream.namespace",} and not f.startswith("data_stream")
            ]

            # print(yaml.dump(table["schema"]["schema"], sort_keys=False))
            # print(table_schema)
            del table["schema"]["schema"]
        
            if pipeline_paths:
                template = "" 
                for path in pipeline_paths:
                    with open(path) as f:
                        p = yaml.safe_load(f)

                    template += "# Pipeline: " + path.name + "\n\n"
                    template += pipeline_to_vrl(p, mode=Mode.prod)
                    # print("\n", template, "\n")
                table["transform"] = template

            if "transform" not in table:
                table["transform"] = "# Transform\n\n# Write your VRL transform script here :)"

            table["name"] = tablename

            table["$file"] = table_file

            if not table_file.exists():
                table_file.parent.mkdir(parents=True, exist_ok=True)
            if opts.pin_to_log_source and not ls_file.exists():
                ls_file.parent.mkdir(parents=True, exist_ok=True)

            file_to_open = ls_file if opts.pin_to_log_source else table_file
            with open(file_to_open, "r+") as f:
                data = yaml.safe_load(f)
                if "schema" not in data:
                    data["schema"] = {}
                data["schema"]["ecs_field_names"] = sorted(
                    list({ *set(table["schema"]["ecs_field_names"]) - set(["@timestamp"]), *set(data["schema"].get("ecs_field_names", [])) } )
                )

                table_schema_ret = fields_to_schema(
                    data.get("schema", {}).get("fields", []) or []
                )
                print("a:", fields_to_schema(table["schema"]["fields"]))
                print("b:", table_schema_ret)
                data["schema"]["fields"] = expand_and_serialize_to_fields(compact(merge(
                    fields_to_schema(table["schema"]["fields"]),
                    table_schema_ret,
                )))

                table["schema"]["ecs_field_names"] = data["schema"]["ecs_field_names"]
                table_schema_ret = fields_to_schema(data["schema"]["fields"])

                if table_schema_ret:
                    table_schema = table_schema_ret
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

            print(f"\n[bold]Using schema for table [green]{resolved_tablename} ✨")
            print(yaml.dump(table_schema))

            # TODO(): open EDITOR and allow to resolve conflicts/issues here
            # editor.edit(filename=str(table_file), other_filenames=[test_event_f, f"{test_event_f}-expected.json"])

            print(f"\n[bold]Generated log source for table [green]{resolved_tablename} 🚀")

        if not opts.skip_tests:
            # print("Running tests...\n")
            global count_passed
            count_passed = 0

            ecs_subschema = ecs_subschema_from_fields(table["schema"]["ecs_field_names"]) if table else {}
            table_schema = merge(
                ecs_subschema,
                table_schema,
            ) if ecs_subschema else table_schema

            with open(table_file) as f:
                data = yaml.safe_load(f)
                errors = run_tests_get_errors(
                    logsource_dir, opts, table_schema, table_file, data, update_snapshot=opts.update_snapshot, replace_expected=opts.replace_expected
                )
                all_passed = errors is None or len(errors) == 0
                if not all_passed:
                    count_passed = 0
                    print(
                        f"\n\n[bold yellow]Press enter to re-run tests for table {resolved_tablename} and check if errors resolved 👀..."
                    )
                    input()

            console.print(
                f"\n[bold]✨ {count_passed} tests passed ✨\n\n", f"{resolved_tablename}"
            )

            console.print("\n[bold green]All tests passed! 🎉\n")

    console.print(Panel.fit(f"\n🎉🎉🎉 [bold green] FINITO {resolved_tablename}! 🎉🎉🎉\n"))
