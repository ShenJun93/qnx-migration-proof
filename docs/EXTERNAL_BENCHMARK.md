# External migration review benchmark

## What changed

This release expands ISR API coverage and distinguishes deprecated C++ driver options from unsupported GCC coverage options. It preserves the read-only host tool model: source locations are review candidates, not build or runtime verdicts.

## Reproduce the comparison

Clone these public repositories into separate directories, check out the exact commits, and run the scanner from the tool repository root. Do not run third-party build scripts or redistribute their source.

| Public repository | Pinned commit | Files inspected | V1 | V2 |
| --- | --- | ---: | ---: | ---: |
| [QNXCarSim](https://github.com/sidbmw/QNXCarSim) | 38178ab49cba5523ac7b8d0f7e85fdbad7e45601 | 11 | 0 | 0 |
| [qnx-screen](https://github.com/Robin329/qnx-screen) | 0cab755cb8139d47df971b0fe8aeef26eea47903 | 16 | 3 | 6 |
| [qnx-ports/build-files](https://github.com/qnx-ports/build-files) | 44f037160c281708a5ac107e852abdecba7a15a5 | 1796 | 0 | 9 |
| [WILC1000 QNX Driver](https://github.com/MicrochipTech/WILC1000_QNX_Driver) | bf89098012b6c615d86b5f711e4bf8796bafa1db | 61 | 3 | 4 |
| Total | | 1884 | 6 | 19 |

    python qnx_migration_audit.py PATH_TO_CHECKOUT --format json
    python qnx_review_dashboard.py PATH_TO_CHECKOUT --output review.html

For a reproducible source-only comparison, use separate directories. From a fresh scratch directory:

    git clone --no-recurse-submodules https://github.com/ShenJun93/qnx-migration-proof.git tool-v1
    git -C tool-v1 checkout --detach 723be5e258475a91a2cc9c12e90b6e48fdcfccbc
    git clone --no-recurse-submodules https://github.com/ShenJun93/qnx-migration-proof.git tool-v2
    git -C tool-v2 checkout --detach a004ad9f1dcbb502328bf028799f7eef0478f437
    git clone --no-recurse-submodules https://github.com/sidbmw/QNXCarSim.git car
    git -C car checkout --detach 38178ab49cba5523ac7b8d0f7e85fdbad7e45601
    git clone --no-recurse-submodules https://github.com/Robin329/qnx-screen.git screen
    git -C screen checkout --detach 0cab755cb8139d47df971b0fe8aeef26eea47903
    git clone --no-recurse-submodules https://github.com/qnx-ports/build-files.git ports
    git -C ports checkout --detach 44f037160c281708a5ac107e852abdecba7a15a5
    git clone --no-recurse-submodules https://github.com/MicrochipTech/WILC1000_QNX_Driver.git wilc
    git -C wilc checkout --detach bf89098012b6c615d86b5f711e4bf8796bafa1db

For each checkout (car, screen, ports, wilc), run both scanner versions, substituting the directory name:

    python tool-v1/qnx_migration_audit.py screen --format json
    python tool-v2/qnx_migration_audit.py screen --format json

Keep the repositories unmodified. Use a host with Python 3.10+ and Git. No SDK is required for the comparison. Compare the coverage and findings fields; a different source checkout is not a valid comparison. This release adds 12 deprecated -lang-c++ references and one legacy InterruptAttach_r call. Three existing -auxbase-strip locations and three io-pkt header path references remain visible. Counts refer to rule/location pairs, not independent defects. Mixed-version repositories are not a labeled compatibility dataset.

## Controlled QNX SDK observations

Windows host, licensed QNX SDP 8.0.6, GCC 12.2.0, x86_64. In a fresh scratch directory with the SDK environment initialized, create the following original minimal source files. Use new output filenames.

    // probe.c
    int main(void) { return 0; }

    // probe.cpp
    #include <iostream>
    int main() { std::cout << "QNX migration probe"; return 0; }

    qcc -Vgcc_ntox86_64 -g -O0 -ftest-coverage -fprofile-arcs -nopipe -Wc,-auxbase-strip,probe.o -c probe.c -o legacy.o
    qcc -Vgcc_ntox86_64 -g -O0 -ftest-coverage -fprofile-arcs -nopipe -c probe.c -o migrated.o

The first compile fails with an unrecognized option; the second succeeds. The test does not establish coverage-data equivalence.

    qcc -Vgcc_ntox86_64 -lang-c++ -c probe.cpp -o old.o
    qcc -Vgcc_ntox86_64 -x c++ -c probe.cpp -o new.o

Both compile successfully; the first emits a deprecated-option warning. For link-only commands, test the actual C++ linker driver rather than blindly substituting a source language flag.

    qcc -Vgcc_ntox86_64 -lang-c++ new.o -o old-app
    q++ -Vgcc_ntox86_64 new.o -o new-app

Both link successfully for the controlled iostream example; the first warns. Neither target binary was executed. No third-party application was built, no target timing or network behavior was tested, and no SDK artifacts are included.

Official sources: [toolchain migration](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/IDE.html), [BSP migration](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/bsps.html), [legacy ISR array variants](https://www.qnx.com/developers/docs/7.1/com.qnx.doc.neutrino.lib_ref/topic/i/interruptattacharray.html).

The original five controlled lab pairs continue to pass. See the codelab for replay and tamper rejection. Benchmark scope is limited: no precision/recall estimate, independent ground truth, or complete migration certification.
