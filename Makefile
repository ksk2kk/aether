arch ?= x86_64
kernel := build/kernel-$(arch).bin
iso := build/os-$(arch).iso
guest_bin := guests/init_domain/init_domain.bin
macro_bin := guests/macro_domain/macro_domain.bin

linker_script := src/arch/$(arch)/linker.ld
grub_cfg := src/arch/$(arch)/grub.cfg
assembly_source_files := $(wildcard src/arch/$(arch)/*.S)
kernel_assembly_source_files := $(filter-out src/arch/$(arch)/guest.S, $(assembly_source_files))
assembly_object_files := $(patsubst src/arch/$(arch)/%.S, build/arch/$(arch)/%.o, $(kernel_assembly_source_files))

target_dir ?= target
rust_os := $(target_dir)/$(arch)-unknown-none/release/libaether.a

.PHONY: all clean run run-kvm iso kernel guest macro check

guest: $(guest_bin)

macro: $(macro_bin)

all: $(kernel) $(guest_bin) $(macro_bin)

check:
	@cargo check --workspace --target $(arch)-unknown-none
	@./scripts/build-guest.sh

clean:
	@rm -rf build
	@cargo clean

run: $(iso)
	@./scripts/run-qemu.sh "$(iso)"

run-kvm: $(iso)
	@qemu-system-x86_64 -enable-kvm -cpu host,+vmx -cdrom $(iso) -serial stdio -display none

iso: $(iso)

$(guest_bin):
	@./scripts/build-guest.sh

$(macro_bin):
	@cargo build -p macro_domain --target x86_64-unknown-none --release
	@rust-objcopy -O binary target/x86_64-unknown-none/release/macro_domain $(macro_bin) || objcopy -O binary target/x86_64-unknown-none/release/macro_domain $(macro_bin)

$(iso): $(kernel) $(guest_bin) $(macro_bin) $(grub_cfg)
	@mkdir -p build/isofiles/boot/grub
	@cp $(kernel) build/isofiles/boot/kernel.bin
	@cp $(guest_bin) build/isofiles/boot/guest.bin
	@cp $(macro_bin) build/isofiles/boot/macro.bin
	@cp $(grub_cfg) build/isofiles/boot/grub
	@grub-mkrescue -o $(iso) build/isofiles 2> /dev/null
	@rm -r build/isofiles

$(kernel): cargo $(assembly_object_files) $(linker_script)
	@ld -n -T $(linker_script) -o $(kernel) $(assembly_object_files) $(rust_os)

cargo:
	@CARGO_TARGET_DIR="$(target_dir)" cargo build -p aether --target $(arch)-unknown-none --release

build/arch/$(arch)/%.o: src/arch/$(arch)/%.S
	@mkdir -p $(shell dirname $@)
	@gcc -m64 -c $< -o $@