from pathlib import Path
import struct, hashlib, json

ROOT = Path('/workspace/scratch/dzh3-firmware')
MAGIC = 0xD00DFEED


def uints(raw):
    if len(raw) % 4:
        raise ValueError('unaligned property cell array')
    return list(struct.unpack('>' + str(len(raw) // 4) + 'I', raw)) if raw else []


def strings(raw):
    return raw.rstrip(b'\0').decode('utf-8', errors='replace').split('\0') if raw else []


def cellnum(cells):
    n = 0
    for c in cells:
        n = (n << 32) | c
    return n


def parse(b):
    if len(b) < 40:
        raise ValueError('truncated header')
    magic, size, off_struct, off_strings, off_reserve, version, last_comp, cpu, size_strings, size_struct = struct.unpack_from('>10I', b)
    assert magic == MAGIC and size == len(b)
    assert version >= 17 and last_comp <= 17
    for off, length in [(off_struct, size_struct), (off_strings, size_strings)]:
        assert off >= 40 and off + length <= size
    assert off_struct + size_struct <= off_strings or off_strings + size_strings <= off_struct
    reserve = []
    p = off_reserve
    while True:
        assert p + 16 <= size
        addr, length = struct.unpack_from('>QQ', b, p)
        p += 16
        if addr == length == 0:
            break
        reserve.append({'address': hex(addr), 'size': hex(length)})
    reserve_end = p
    names = b[off_strings:off_strings + size_strings]
    nodes = {}
    stack = []
    p = off_struct
    end = off_struct + size_struct
    ended = False
    while p < end:
        assert p + 4 <= end
        token = struct.unpack_from('>I', b, p)[0]
        p += 4
        if token == 1:
            q = b.find(b'\0', p, end)
            assert q >= p
            name = b[p:q].decode('utf-8')
            p = (q + 4) & ~3
            path = ('/' + '/'.join(stack + [name])).replace('//', '/')
            assert path not in nodes
            nodes[path] = {}
            stack.append(name)
        elif token == 2:
            assert stack
            stack.pop()
        elif token == 3:
            assert p + 8 <= end and stack
            length, noff = struct.unpack_from('>II', b, p)
            p += 8
            assert p + length <= end and noff < len(names)
            q = names.find(b'\0', noff)
            assert q >= noff
            name = names[noff:q].decode('utf-8')
            path = ('/' + '/'.join(stack)).replace('//', '/')
            assert name not in nodes[path]
            nodes[path][name] = b[p:p + length]
            p = (p + length + 3) & ~3
        elif token == 4:
            pass
        elif token == 9:
            assert not stack
            ended = True
            break
        else:
            raise ValueError(f'Unknown FDT token {token} at {p - 4:x}')
    assert ended and p <= end
    return nodes, reserve, {
        'version': version,
        'last_compatible_version': last_comp,
        'structure_offset': off_struct,
        'structure_size': size_struct,
        'strings_offset': off_strings,
        'strings_size': size_strings,
        'reserve_map_end': reserve_end,
    }


def parent(path):
    return path.rpartition('/')[0] or '/'


def counts(nodes, path):
    props = nodes.get(path, {})
    return uints(props.get('#address-cells', b'\0\0\0\2'))[0], uints(props.get('#size-cells', b'\0\0\0\1'))[0]


def regs(nodes, path):
    data = nodes[path].get('reg')
    if data is None:
        return None
    cells = uints(data)
    ac, sc = counts(nodes, parent(path))
    step = ac + sc
    assert step > 0 and len(cells) % step == 0
    return [
        {'address': hex(cellnum(cells[i:i + ac])), 'size': hex(cellnum(cells[i + ac:i + step]))}
        for i in range(0, len(cells), step)
    ]


b = (ROOT / 'vendor-dtbs.bin').read_bytes()
p = 0
report = []
out = ROOT / 'dtbs'
out.mkdir(exist_ok=True)
while p < len(b):
    assert p + 40 <= len(b) and struct.unpack_from('>I', b, p)[0] == MAGIC
    length = struct.unpack_from('>I', b, p + 4)[0]
    assert length >= 40 and p + length <= len(b)
    tree = b[p:p + length]
    nodes, reserve, header = parse(tree)
    index = len(report)
    target = out / f'vendor-{index:02d}.dtb'
    target.write_bytes(tree)
    root = nodes['/']
    ident = {}
    for key, value in root.items():
        if key in ['model', 'compatible']:
            ident[key] = strings(value)
        elif key.startswith('qcom,') and any(word in key for word in ['id', 'name']):
            ident[key] = [hex(x) for x in uints(value)] if len(value) % 4 == 0 else strings(value)
    memory = []
    reserved = []
    bootargs = []
    for path, props in nodes.items():
        if path.split('/')[-1].startswith('memory@') or props.get('device_type', b'').rstrip(b'\0') == b'memory':
            memory.append(
                {
                    'path': path,
                    'reg': regs(nodes, path),
                    'properties': {
                        key: [hex(x) for x in uints(value)]
                        for key, value in props.items()
                        if key not in ['device_type', 'reg'] and len(value) % 4 == 0
                    },
                }
            )
        if path.startswith('/reserved-memory/'):
            item = {'path': path, 'reg': regs(nodes, path)}
            for key in ['compatible', 'status']:
                if key in props:
                    item[key] = strings(props[key])
            for key in ['size', 'alignment', 'alloc-ranges', 'qcom,alignment', 'qcom,size']:
                if key in props:
                    item[key] = [hex(x) for x in uints(props[key])]
            for key in ['no-map', 'reusable']:
                if key in props:
                    item[key] = True
            reserved.append(item)
        for key, value in props.items():
            if 'bootargs' in key or key in ['bootconfig']:
                bootargs.append({'path': path, 'property': key, 'value': strings(value)})
    report.append(
        {
            'index': index,
            'concatenation_offset': p,
            'size': length,
            'sha256': hashlib.sha256(tree).hexdigest(),
            'identifiers': ident,
            'memory': memory,
            'reserved_memory': reserved,
            'memreserve': reserve,
            'bootargs': bootargs,
            'node_count': len(nodes),
            'header': header,
        }
    )
    p += length

assert p == len(b)
summary = {
    'source_sha256': hashlib.sha256(b).hexdigest(),
    'source_size': len(b),
    'dtb_count': len(report),
    'exactly_consumed': True,
    'notes': [
        'The DTB concatenation contains platform variants; runtime selection cannot be established from the concatenation alone.',
        'Static /memory reg entries may be placeholders replaced by the bootloader; zero size does not mean the device has zero RAM.',
        'Reserved-memory reg entries are declarations in each static DTB, not a verified live memory map.',
    ],
    'dtbs': report,
}
(ROOT / 'vendor-dtb-metadata.json').write_text(json.dumps(summary, indent=2) + '\n')
for entry in report:
    print(entry['index'], entry['identifiers'], 'memory:', entry['memory'])
    print('gunyah:', [r for r in entry['reserved_memory'] if 'gunyah' in r['path']], 'bootargs:', entry['bootargs'])
print('Parsed', len(report), 'DTBs; consumed', p, 'bytes exactly.')
