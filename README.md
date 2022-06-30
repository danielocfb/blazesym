# BlazeSym

BlazeSym is a library to symbolize addresses to get symbol names, file
names of source files, and line numbers.  It can translate a stack
trace to function names and their locations in the
source code.

 - <https://github.com/ThinkerYzu1/blazesym>

## Build

You should install a Rust environment to build BlazeSym.

Once you have installed Rust, you also need the source code of BlazeSym.

 - `git clone https://github.com/ThinkerYzu1/blazesym.git`

Now, you should go to the root directory of the BlazeSym source code
to build BlazeSym.

 - cargo build

You may want to build a C header (**blazesym.h**) to include in your C programs.

 - cargo build --features="cheader"

You will see **blazesym.h** and **libblazesym.a** in target/debug/ or
target/release/ directory.  Your C programs, if there are, should
include **blazesym.h** and link against **libblazesysm.a** to access
functions and types of BlazeSym.

## Rust API

The following code uses BlazeSym to get symbol names, filenames of
sources, and line numbers of addresses in a process.


```ignore
	use blazesym::{BlazeSymbolizer, SymSrcCfg, SymbolizedResult};
	
	let process_id: u32 = <process id>;
    // load all symbols of loaded files of the given process.
	let sym_srcs = [SymSrcCfg::Process { pid: process_id }];
	let symbolizer = BlazeSymbolizer::new().unwrap();

    let stack: [u64] = [0xff023, 0x17ff93b];			// Addresses of instructions
	let symlist = symbolizer.symbolize(&sym_srcs,		// Pass this configuration every time
	                                   &stack);
	for i in 0..stack.len() {
	    let address = stack[i];
		
		if symlist.len() <= i or symlist[i].len() == 0 {	// Unknown address
			println!("0x{:016x}", address);
			continue;
		}
		
		let sym_results = &symlist[i];
		if sym_results.len() > 1 {
			// One address may get several results (ex, inline code)
			println!("0x{:016x} ({} entries)", address, sym_results.len());
			
			for result in sym_results {
				let SymbolizedResult {symbol, start_address, path, line_no, column} = result;
				println!("    {}@0x{:016x} {}:{}", symbol, start_address, path, line_no);
			}
		} else {
			let SymbolizedResult {symbol, start_address, path, line_no, column} = &sym_results[0];
			println!("0x{:016x} {}@0x{:016x} {}:{}", address, symbol, start_address, path, line_no);
		}
	}
```

`sym_srcs` is a list of sources of symbols loaded in a process.
However, there is only one `SymSrcCfg::Process {}` here.
`SymSrcCfg::Process {}` is a convenient variant to load all objects,
i.e., binaries and shared libraries, mapped in a process.  Developers
do not have to specify every object and its base address with
`SymSrcCfg::Process {}`.

`symlist` is a list of lists of `SymbolizedResult`.  The instruction
at an address can result from several lines of code from several
functions with inlining and optimization.  In other words, the result
of an address is a list of `SymbolizedResult`.  Each entry in
`symlist` results from the address at the respective position in the
argument passed to [`BlazeSymbolizer::symbolize()`].

### With Linux Kernel

`SymSrcCfg::Kernel {}` is a variant to load symbols of the Linux kernel.

```ignore
	let sym_srcs = [SymSrcCfg::Kernel {
		kallsyms: Some("/proc/kallsyms".to_string()),
		kernel_image: Some("/boot/vmlinux-xxxxx".to_string()),
	}];
```

Here, you give the path of kallsyms and the path of a kernel image.
The path of kallsyms can be the one in /proc/ or a copy of kallsym.

If you are symbolizing against the current running kernel on the same
device, give `None` for both paths.  It will find out the correct
paths for you if possible. It will use `"/proc/kallsyms"` for
kallsyms, and find the kernel image of the running kernel from several
potential directories; ex, /boot/ and /usr/lib/debug/boot/.

```ignore
	let sym_srcs = [SymSrcCfg::Kernel { kallsyms: None, kernel_image: None }];
```

### A list of ELF files

You can still give a list of ELF files and their base addresses if necessary.

```ignore
	let sym_srcs = [SymSrcCfg::Elf { file_name: String::from("/lib/libc.so.xxx"),
	                                 base_address: 0x1f005d },
	                SymSrcCfg::Elf { fie_name: String::from("/path/to/my/binary"),
				                     base_address: 0x77777 },
	                ......
	];
```

The base address of an ELF file is where its executable segment(s) is
loaded.

### Example of Rust API

examples/addr2ln_pid.rs is an example doing symbolization for an
address in a process.

```text
    $ ./target/debug/examples/addr2ln_pid 1234 7f0c41ade000
	PID: 1234
	0x7f0c41ade000 wcsxfrm_l@0x7f0c41addd10+752 src/foo.c:0
	$
```

The above command will show the symbol name, the file name of the
source, and the line number of the address 0x7f0c41ade000 in the process
1234.

Users should build examples with the following command at the root of the
source.

```text
    $ cargo build --examples
```

## C API

The following code symbolizes a list of addresses of a process.  It
shows the addresses, their symbol names, the filenames of source files,
and the line numbers.

```ignore
	#include "blazesym.h"
	
	struct sym_src_cfg sym_srcs[] = {
		{ SRC_T_PROCESS, .params = { .process { <pid> } } },
	};
	const struct blazesym *symbolizer;
	const struct blazesym_result * result;
	const struct blazesym_csym *sym;
	uint64_t stack[] = { 0x12345, 0x7ff992, ..};
	int stack_sz = sizeof(stack) / sizeof(stack[0]);
	uint64_t addr;
	int i, j;
	
	symbolizer = blazesym_new();
	/* sym_srcs should be passed every time doing symbolization */
	result = blazesym_symbolize(symbolizer,
	                            sym_srcs, 1,
								stack, stack_sz);
	
	for (i = 0; i < stack_sz; i++) {
		addr = stack[i];
		
		if (!result || i >= result->size || result->entries[i].size == 0) {
			/* not found */
			printf("[<%016llx>]\n", addr);
			continue;
		}
		
		if (result->entries[i].size == 1) {
			/* found one result */
			sym = &result->entries[i].syms[0];
			printf("[<%016llx>] %s@0x%llx %s:%ld\n", addr, sym->symbol, sym->start_address,
			        sym->path, sym->line_no);
			continue;
		}
		
		/* Found multiple results */
		printf("[<%016llx>] (%d entries)\n", addr, result->entries[i].size);
		for (j = 0; j < result->entries[i].size; j++) {
			sym = &result->entries[i].syms[j];
			printf("    %s@0x$llx %s:%ld\n", sym->symbol, sym->start_address,
			       sym->path, sym->line_no);
		}
	}
	
	blazesym_result_free(result);
	blazesym_free(symbolizer);
```

`struct sym_src_cfg` describes a binary, a symbol file, a shared
object, a kernel, or a process.  In this example, it uses a `struct sym_src_cfg`
instance with [`blazesym_src_type::SRC_T_PROCESS`] type to
describe a process.  BlazeSym will figure out all loaded
ELF files of the process and load symbol and DWARF information from
them to perform symbolization.

### Link C programs

You should include “blazesym.h” in a C program in order to call
BlazeSym.  Check the “Build” section to generate "blazesym.h".

You also need the following arguments to link against BlazeSym.

```text
	-lrt -ldl -lpthread -lm libblazesym.a
```

You may want to link a shared library, `libblazesym.so`.

### With Linux Kernel

[`blazesym_src_type::SRC_T_KERNEL`] is a variant of `struct sym_src_cfg` to
describe a kernel as a source of symbolization.

```ignore
	struct sym_src_cfg sym_srcs[] = {
		{ SRC_T_KERNEL, .params = { .kernel = { .kallsyms = "/proc/kallsyms",
		                                        .kernel_image = "/boot/vmlinux-XXXXX" } } },
	};
```

You can give `kallsyms` and `kernel_image` a `NULL`.  BlazeSym will
figure out where they are for the running kernel.  For example, by
default, `kallsyms` is at `"/proc/kallsyms"`.  The kernel image of the
current kernel will be in /boot/ or /usr/lib/debug/boot/.

### A list of ELF files

The [`blazesym_src_type::SRC_T_ELF`] variant of `struct sym_src_cfg` gives the path of an
ELF file and its base address.  You can specify a list of ELF files
and where they are loaded.


```ignore
	struct sym_src_cfg sym_srcs[] = {
		{ SRC_T_ELF, .params = { .elf = { .file_name = "/lib/libc.so.xxx",
		                                  .base_address = 0x7fff31000 } } },
		{ SRC_T_ELF, .params = { .elf = { .file_name = "/path/to/a/binary",
		                                  .base_address = 0x1ff329000 } } },
	};
```

The base address of an ELF file is where its executable segment(s) is loaded.

### Example of C API

There is a C example in libbpf-bootstrap.  You can find it at
<https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/profile.c>
.  This example samples the running process of every processor
in a system periodically and prints their stack traces at the moment
doing sampling.
