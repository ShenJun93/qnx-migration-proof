import subprocess, pathlib, json, hashlib, argparse, sys
parser=argparse.ArgumentParser(description="Run original, synthetic QNX 8 migration build probes on Windows. Never executes target binaries.")
parser.add_argument("--sdk", required=True, type=pathlib.Path)
parser.add_argument("--output", required=True, type=pathlib.Path, help="New directory; never overwrites existing evidence")
args=parser.parse_args()
repo=pathlib.Path(__file__).resolve().parent
sdk=args.sdk.resolve()/"qnxsdp-env.bat"
if sys.platform != "win32" or not sdk.is_file():
    parser.error("Windows QNX SDP environment batch file required")
if any(c in str(sdk) for c in '%!"&|<>^\r\n'):
    parser.error("Unsupported SDK path characters")
root=args.output.resolve()
root.mkdir(parents=True, exist_ok=False)
cases={
"auxbase": (
 "int main(void) { return 0; }\n",
 "int main(void) { return 0; }\n",
 "-Wc,-auxbase,main", "", "QNX8-CC-001"),
"ids": (
 "#include <login.h>\nint main(int argc, char **argv) { return argc == 2 ? set_ids_from_arg(argv[1]) : 0; }\n",
 "#include <secpol/ids.h>\nint main(int argc, char **argv) { return argc == 2 ? set_ids_from_arg(argv[1]) : 0; }\n",
 "-llogin", "-lsecpol", "QNX8-SRC-002"),
"interrupt": (
 "#include <sys/neutrino.h>\n#include <stddef.h>\nstatic const struct sigevent *handler(void *area, int id) { (void)area; (void)id; return NULL; }\nint main(void) { return InterruptAttach(0,handler,NULL,0,0); }\n",
 "#include <sys/neutrino.h>\n#include <sys/siginfo.h>\nint main(void) { struct sigevent ev; SIGEV_INTR_INIT(&ev); int id=InterruptAttachEvent(0,&ev,0); if(id<0) return 1; if(InterruptWait(0,NULL)==0) InterruptUnmask(0,id); return InterruptDetach(id); }\n",
 "", "", "QNX8-SRC-001")}
results=[]
for name,(before,after,oldflag,newflag,rule) in cases.items():
    for stage,source,flag in [("before",before,oldflag),("after",after,newflag)]:
        d=root/name/stage; d.mkdir(parents=True)
        (d/"main.c").write_text(source,encoding="ascii")
        (d/"Makefile").write_text("CFLAGS += "+flag+"\n",encoding="ascii")
        scan=subprocess.run([sys.executable,str(repo/"qnx_migration_audit.py"),str(d),"--format","json"],capture_output=True,text=True,check=True)
        findings=json.loads(scan.stdout)["findings"]
        command=f'qcc -Vgcc_ntox86_64 -Wall -Wextra -Werror main.c {flag} -o app'
        batch=d/"build.cmd"
        batch.write_text(f'@echo off\ncall "{sdk}" >nul\n@echo off\n{command}\nexit /b %errorlevel%\n',encoding="ascii")
        p=subprocess.run(["cmd.exe","/d","/c","build.cmd"],cwd=d,capture_output=True,text=True,errors="replace",timeout=60)
        output=d/"app"
        record=dict(case=name,stage=stage,rule=rule,findings=[x["rule_id"] for x in findings],command=command,exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr,source_sha256=hashlib.sha256((d/"main.c").read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest() if output.exists() else None)
        results.append(record)
        print(json.dumps(record),flush=True)
(root/"results.json").write_text(json.dumps(results,indent=2),encoding="utf-8")

# A passing interrupt compile is expected on the observed SDK; it is not runtime proof.
expected={"auxbase":(1,0),"ids":(1,0),"interrupt":(0,0)}
ok=True
for name,pair in expected.items():
    a,b=[r for r in results if r["case"]==name]
    rc_ok=(a["exit_code"]!=0 if pair[0] else a["exit_code"]==0) and b["exit_code"]==0
    scan_ok=a["findings"]==[a["rule"]] and not b["findings"]
    signature_ok={"auxbase":"unrecognized command-line option '-auxbase'" in a["stderr"],"ids":"implicit declaration" in a["stderr"] and "set_ids_from_arg" in a["stderr"],"interrupt":True}[name]
    ok=ok and rc_ok and scan_ok and signature_ok and bool(b["binary_sha256"])
print("EXPECTED_OBSERVATIONS_MATCH" if ok else "OBSERVATIONS_DIFFER")
sys.exit(0 if ok else 1)
