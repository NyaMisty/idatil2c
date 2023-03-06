# Generate inter-op wrappers of ctypes structs we used
import os
import re
import subprocess
from collections import OrderedDict

import io

from pathlib import Path
ROOT_DIR = Path(__file__).absolute().parent

# By default, this script is adapted for clang2py from https://github.com/trolldbois/ctypeslib
# With GHIDRA environment set, this script will operate with more restriction to support Ghidra's "Parse C Source"
GHIDRA_MODE = os.getenv('GHIDRA')

STRUCT_BLACKLIST = ['_SCHANNEL_CRED', '_Mbstatet']
TYPEDEF_BLACKLIST = ['_Mbstatet', 'va_list']

# https://stackoverflow.com/questions/2319019/using-regex-to-remove-comments-from-source-files
def remove_comments(string):
    pattern = r"(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)"
    # first group captures quoted strings (double or single)
    # second group captures comments (//single-line or /* multi-line */)
    regex = re.compile(pattern, re.MULTILINE|re.DOTALL)
    def _replacer(match):
        # if the 2nd group (capturing comments) is not None,
        # it means we have captured a non-quoted (real) comment string.
        if match.group(2) is not None:
            return "" # so we will return empty to remove the comment
        else: # otherwise, we will return the 1st group
            return match.group(1) # captured quoted-string
    return regex.sub(_replacer, string)


IDENTIFIER = r'\w\d_'
# find all defined types' identifiers
IDENTIFIER_PAT = '[%s]+' % IDENTIFIER

def replaceTemplateArgs(content):
    def cleanName(nam):
        nam_map = {}
        for c in ' :<>,-()[]':
            nam_map[c] = '_'
        nam_map['&'] = '_R'
        nam_map['*'] = '_P'
        for c, v in nam_map.items():
            nam = nam.replace(c,v)
        return nam
    
    content = content.replace('::', '__')

    content = content.replace('$', '_')
    
    content = content.replace('?', '_')
    
    content = content.replace('~', '_del_')

    content = content.replace('\nconst struct', '\nstruct')
    
    typename = r'[%s][%s<>_ ,*]+?[%s>]' % (IDENTIFIER, IDENTIFIER, IDENTIFIER)

    templateArgChars = r'A-z0-9_ :,\-()?*&\[\]'
    templateArg_ = r'[%s]+?' % templateArgChars
    templateArg = r'[%s]*?' % templateArgChars
    templatePat = []
    def genTemplatePat(level):
        if level == 1:
            ret = r'<(%s)>' % templateArg
            templatePat.append(ret)
        else:
            genTemplatePat(level - 1)
            #for pat in templatePat[:]:
            matchPart = r'%s%s+?%s' % (templateArg_, '(%s)' % '|'.join(templatePat), templateArg)
            ret = r'<(%s,)*?%s>' % (matchPart, matchPart)
            templatePat.append(ret)

        return
    
    genTemplatePat(9)

    def findPatInLine(pat):
        if False:
            for l in content.splitlines():
                print(l)
                for match in re.finditer(pat, l):
                    yield match
        else:
            for match in re.finditer(pat, content):
                yield match

    #for strucName in re.findall(r'^typedef struct (.*?);\n', content):
    #    replaceList.append((strucName, cleanName(strucName)))
    #for strucName in re.findall(r'\nstruct (%s);\n' % typename, content):
    #    replaceList.append((strucName, cleanName(strucName)))
    
    #for strucName in re.findall(r'\n  struct (%s) \*[a-zA-Z_]+?;\n' % typename, content):
    #    replaceList.append((strucName, cleanName(strucName)))
    
    #for strucName, _, strucBase in re.findall(r'struct __cppobj (.*?)( : (.*?)|)\n', content):
    #for _, _, _, _, strucName, _, strucBase in re.findall(r'\nstruct( __[^ ]+?|)( __[^ ]+?|)( __[^ ]+?|)( __[^ ]+?|) (%s)( : (%s)|)\n' % (typename, typename), content):
    #    replaceList.append((strucName, cleanName(strucName)))
    #    replaceList.append((strucBase, cleanName(strucBase)))
    
    round = 0
    while True:
        round += 1
        print('Replacing template arg round %d' % round)

        replaceList = set()
        for i, pat in enumerate(templatePat):
            #print("Finding matchs on pattern %d: %s" % (i, pat))
            for match in findPatInLine(pat):
                tmplArg = match.group(0)
                if tmplArg == '*':
                    print(pat, match)
                    sys.exit(1)
                replaceList.add(tmplArg)
                #print(match.start(), tmplArg)
        
        if not replaceList:
            break
    
        replaceList = list(set(replaceList))
        #replaceList.sort(key=lambda x: len(x[0]), reverse=True)
        replaceList.sort(key=lambda x: len(x), reverse=True)
        
        for a in replaceList[:]:
            print(a)
            content = content.replace(a, cleanName(a))
            if 'struct_std__nested_exception_vtbl' in content:
                break
    return content

class TypeDecl(object):
    def __init__(self, typClass, typName, typDef):
        self.typClass = typClass
        self.typName = typName
        self.typDef = typDef
    
    def __repr__(self):
        return '<%s %s: %s>' % (self.typClass, self.typName, self.typDef)
    
    def __str__(self):
        return self.typDef

def parseDecls(types):
    type_defs = OrderedDict({})
    ignoredLines = 0
    def add_type(cls, t, line):
        #print(t, line[:100])
        if t in type_defs:
            print("Offending decl: %s" % type_defs[t])
        assert not t in type_defs
        type_defs[t] = TypeDecl(cls, t, line)
    for line in types.splitlines():
        print("Processing Line: %s" % line[:40])
        #if GHIDRA_MODE:
        #    if False and '__cppobj' in line:
        #        ignoredLines += 1
        #        continue
        oriLine = line
        line = line.replace('__cdecl ', '').replace('__cppobj ', '')
        
        _line = re.sub(r'__attribute__\(.*?\) ', '', line)
        if line.startswith('/*') or line.startswith('//'):
            ignoredLines += 1
            continue
        
        oriTypeLen = len(type_defs)
        if _line.startswith('enum '):
            matches = re.findall(r'enum (%s) (:|{)' % IDENTIFIER_PAT, _line)
            if not matches:
                print(line)
            match = matches[0][0]
            #identifiers.append('enum ' + match)
            line = re.sub('^enum ', 'enum class ', line)
            add_type('enum', match, line)
        elif _line.startswith('union '):
            match = re.findall(r'union (%s)(;| {)' % IDENTIFIER_PAT, _line)[0][0]
            #identifiers.append('union ' + match)
            add_type('union', match, line)
        elif _line.startswith('struct '):
            matches = []
            matches += re.findall(r'struct (%s) : (%s|, )+? {' % (IDENTIFIER_PAT, IDENTIFIER_PAT), _line)
            matches += re.findall(r'struct (%s) {' % IDENTIFIER_PAT, _line)
            matches += re.findall(r'struct (%s);' % IDENTIFIER_PAT, _line)
            for m in matches:
                if not isinstance(m, tuple):
                    m = [m]

                curdef = line
                add_type('struct', m[0], curdef)
                
        elif _line.startswith('typedef '):
            matches = []
            matches += re.findall(r'typedef .*?(%s);' % IDENTIFIER_PAT, _line)
            matches += re.findall(r'typedef .*?(%s)\(.*?\);' % IDENTIFIER_PAT, _line)
            matches += re.findall(r'typedef .*?(%s)\)\(.*?\);' % IDENTIFIER_PAT, _line)
            matches += re.findall(r'typedef .*?(%s)\[.*?\];' % IDENTIFIER_PAT, _line)
            if not matches:
                print(line)
            #identifiers.append(matches[0])
            add_type('typedef', matches[0], line)
        else:
            assert False
        if len(type_defs) - oriTypeLen != 1:
            print(line)
            assert False
    return type_defs, ignoredLines

def sanitizeHdr(hdrContent):
    content = hdrContent
    #content = content.replace(';', ';\n').replace('{', '{\n').replace('}', '}\n')
    
    #BLACKLIST = ['procmod_t', '__m128i']

    #for strucName in BLACKLIST:
    #    content = re.sub(r'(\n(struct|enum|union) .*?' + strucName + '.*?\n{\n[\s\S]+?\n};\n)', '/*\\1*/\n', content)

    types, _, symbols = content.partition('\n\n')
    symbols = '\n'.join([c for c in symbols.splitlines() if '?' not in c])
    content = types + '\n\n' + symbols

    #for typeName in TYPEDEF_BLACKLIST:
    #    content = re.sub(r'\n(typedef .*? [*]*?' + typeName + ';)\n', '\n/*\\1*/\n', content)

    # remove vft
    content = re.sub(r'^struct /\*VFT\*/ ((.*?_vtbl) {.*?};)$', r'struct \2; /* \1*/', content, flags=re.MULTILINE)
    content = re.sub(r'^struct ((.*?_vtbl_layout) {.*?};)$', r'struct \2; /* \1*/', content, flags=re.MULTILINE)
    
    content = re.sub(r'#\d+ ', 'void ', content)

    # remove coments
    #content = remove_comments(content)
    content = replaceTemplateArgs(content)
    
    content = re.sub(r'\nenum ([%s]+?) : __int32 ' % IDENTIFIER, '\nenum \\1 : unsigned __int32 ', content)
    
    return content

def parseHdr(content):
    types, _, symbols = content.partition('\n\n')
    
    type_defs, ignoredLines = parseDecls(types)
    while True:
        # handle multi level nested struct
        # example: 
        #    struct AAEntryAttributes {union {uint32_t bits;struct {unsigned __int32 UID : 1;unsigned __int32 GID : 1;unsigned __int32 FLG : 1;unsigned __int32 MOD : 1;unsigned __int32 BTM : 1;unsigned __int32 CTM : 1;unsigned __int32 MTM : 1;};};uint32_t uid;uint32_t gid;uint32_t flg;uint32_t mod;timespec btm;timespec ctm;timespec mtm;};
        #    union AAEntryAttributes___EFADEFB9DC9004767965205374614248 {uint32_t bits;struct {unsigned __int32 UID : 1;unsigned __int32 GID : 1;unsigned __int32 FLG : 1;unsigned __int32 MOD : 1;unsigned __int32 BTM : 1;unsigned __int32 CTM : 1;unsigned __int32 MTM : 1;};};
        # round1: 
        #    struct AAEntryAttributes {union {uint32_t bits;_678A87172BFFCBF6A0FE0078F3A89BFB __anonymous1;};uint32_t uid;uint32_t gid;uint32_t flg;uint32_t mod;timespec btm;timespec ctm;timespec mtm;};
        #    union AAEntryAttributes___EFADEFB9DC9004767965205374614248 {uint32_t bits;_678A87172BFFCBF6A0FE0078F3A89BFB __anonymous1;};
        # round2:
        #    struct AAEntryAttributes {AAEntryAttributes___EFADEFB9DC9004767965205374614248 __anonymous1;uint32_t uid;uint32_t gid;uint32_t flg;uint32_t mod;timespec btm;timespec ctm;timespec mtm;};
        # note: ida seems orders these child struct stablely (childs after parent), so this will work
        has_change = False
        for typName, typInfo in type_defs.items():
            newDef = typInfo.typDef
            i = 0
            for m in re.findall(r'(?<=[;{])(union|struct)(( : [\w\d]+ | ){[^{}]+});', typInfo.typDef):
                typeClass, strucBody, _ = m
                for typName2, typInfo2 in type_defs.items():
                    if typName2 == typName:
                        continue
                    if typInfo2.typClass != typeClass:
                        continue
                    if strucBody in typInfo2.typDef:
                        newDef = newDef.replace(typeClass + strucBody, '%s __anonymous%d' % (typName2, i))
                        i += 1
            if newDef != typInfo.typDef:
                print("Fixing nested struct!")
                print("   Ori struct: %s" % typInfo.typDef)
                print("   New struct: %s" % newDef)
                has_change = True
                typInfo.typDef = newDef
        if not has_change:
            break

    if GHIDRA_MODE:
        for typName, typInfo in type_defs.items():
            _line = typInfo.typDef
            mm = re.findall(r'struct (%s) : ((%s|, )+?) {' % (IDENTIFIER_PAT, IDENTIFIER_PAT), _line)
            if mm:
                name, bases = mm[0][:2]
                rec = [ '%s cppsuper%d' % (base, i) for i, base in enumerate(bases.split(', '))]
                _line = _line.replace(
                    'struct %s : %s {' % (name, bases), 
                    'struct %s { %s;' % (name, ';'.join(rec))
                )
    
                print('========= %s' % _line)
                # curdef = 'struct %s;' % m[0]
                typInfo.typDef = _line

    if 'procmod_t' in content:
        assert 'procmod_t' in type_defs # for debugging

    assert len(type_defs) + ignoredLines == len(types.splitlines())

    return type_defs, symbols


FORWARD_DECL_TYPES = ('struct', 'union', )
def outputCtypesLibCpp(type_defs, symbols):
    # analyse the type hierarchy
    type_defs_sorted = OrderedDict(sorted(type_defs.items(), key=lambda x: len(x[0]), reverse=True))
    typeDefDeps = {}
    for typName, typInfo in type_defs_sorted.items():
        typeDefDeps[typName] = []
        otherTyps = [t for t in type_defs_sorted if t != typName]
        typDef = typInfo.typDef
        for otherTyp in otherTyps:
            if otherTyp in typDef and re.search(r'[ ;*(){},]%s[ ;*(){},]' % (otherTyp), typDef):
                hasPointerRef = re.search(r'[ ;*(){},]%s *\*' % (otherTyp), typDef)
                hasDirectRef = re.search(r'[ ;*(){},]%s +[^* ]' % (otherTyp), typDef)
                otherTypInfo = type_defs_sorted[otherTyp]
                isDepend = True

                # typName is referencing otherTyp
                if not hasDirectRef and hasPointerRef: # is Pointer
                    if otherTypInfo.typClass in FORWARD_DECL_TYPES:
                        if typInfo.typClass in ('struct', 'union', ):
                            # ignored pointer to struct/union/typedef in struct or union
                            isDepend = False
                        if typInfo.typClass == 'typedef':
                            isDepend = False
                else:
                    if typInfo.typClass == 'typedef' and otherTypInfo.typClass in FORWARD_DECL_TYPES:
                        isDepend = False
                    pass
                if isDepend:    
                    typeDefDeps[typName].append(otherTyp)
                # masking cur type
                typDef = typDef.replace(otherTyp, '$$$$')
                
        #print("%s -> %s" % (typName, typeDefDeps[typName]))
    
    typeDefDeps_sorted = OrderedDict(sorted(typeDefDeps.items(), key=lambda x: len(x[1])))

    print("Type hierarchy analysis finished:")
    for t in typeDefDeps_sorted:
        print("%s -> %s" % (t, typeDefDeps_sorted[t]))

    # BFS the dependency tree
    typeLines = []
    typKnown = []
    while typeDefDeps_sorted:
        has_change = False
        for k, v in list(typeDefDeps_sorted.items()):
            if all((t in typKnown for t in v)):
                typeDefDeps_sorted.pop(k)
                typeLines.append(type_defs_sorted[k])
                typKnown.append(k)
                has_change = True
        if not has_change:
            errmsg = "Dependency loop!\n  curKnown: %s,\n  remaining: %s\n" % (
                    typKnown, 
                    '\n'.join(['%s -> %s' % (k,[type_defs_sorted[c] for c in v]) for k,v in typeDefDeps_sorted.items()])
                    )
            if False and GHIDRA_MODE:
                print(errmsg)
            else:
                raise Exception(errmsg)

    symbolLines = []
    for symLine in symbols.splitlines():
        if symLine.startswith('#error '):
            continue
        
        BLACKLIST_SYMS = [
            'operator delete', 'operator delete[]', 'operator new', 'operator new[]', 'operator""s', 'operator&', 'operator+', 'operator-', 'operator<', 'operator^', 'operator|',
            ' HUGE;'
        ]
        if any(c in symLine for c in BLACKLIST_SYMS):
            continue
        
        # for: int __cdecl _stat32(const char *_FileName, _stat32 *_Stat);
        symLine = symLine.replace('_stat32 *', 'struct _stat32 *').replace('_stat32i64 *', 'struct _stat32i64 *').replace('_stat64 *', 'struct _stat64 *').replace('_stat64i32 *', 'struct _stat64i32 *')

        if symLine.endswith('[];'): # const char regkey_history[];
            continue
        
        parts = symLine.split(' ')
        t = parts[0]
        if len(parts) == 2 and t in type_defs_sorted and type_defs_sorted[t].typClass == 'enum':
            symLine = '// ' + symLine
        symbolLines.append(symLine)

    f = io.StringIO()
    f.write('\n'.join('%s %s;' % (t.typClass, n) for n,t in type_defs_sorted.items() if t.typClass in FORWARD_DECL_TYPES))
    f.write('\n\n')
    f.write('\n'.join(c.typDef for c in typeLines))
    f.write('\n\n')
    if not GHIDRA_MODE:
        f.write('namespace SymbolsNamespace {\n')
        f.write('\n'.join(c for c in symbolLines))
        f.write('\n\n}')
    return re.sub(r'ANTICOLLISION[0-9]*?_', '', f.getvalue())
        

def remove_base_types(content, depHdrs):
    oriLines = content.split('\n')
    depLines = sum([open(c).read().split('\n') for c in depHdrs], [])
    newLines = list(filter(lambda x: (x.strip() == '') or x not in depLines, oriLines))
    return '\n'.join(newLines)

def gen_ctypes_cpp(hdrLoc, outLoc, depends=()):
    with open(hdrLoc, 'r') as f:
        content = f.read()
    
    content = remove_base_types(content, depends)
    
    outCpp = hdrLoc.replace('.h', '.cpp')
    with open(outCpp, 'w') as f:
        f.write(content)

    content = sanitizeHdr(content)
    with open(outCpp, 'w') as f:
        f.write(content)
    assert '<' not in content

    # outCppContent = rewrite_ida_header(content, depends)
    type_defs, symbols = parseHdr(content)
    with open(outCpp, 'w') as f:
        for c in type_defs.values():
            f.write(c.typDef + '\n')
        f.write('\n')
        f.write(symbols)

    for t in list(type_defs.keys()):
        if type_defs[t].typClass == 'typedef':
            if t in TYPEDEF_BLACKLIST:
                type_defs.pop(t)
                continue
        if type_defs[t].typClass == 'struct':
            if t in STRUCT_BLACKLIST:
                type_defs.pop(t)
                continue

    deps = '\n'.join([open(Path(c).with_suffix('.cpp')).read() for c in depends])

    for t in list(type_defs.keys()):
        if re.search(r' %s [{:]' % t, deps):
            type_defs.pop(t)

    outCppContent = outputCtypesLibCpp(type_defs, symbols)

    RESERVED_TOKENS = {
        'const': 'const_', 
        'float': 'float_',
        'register': 'register_',
        'default': 'default_',
    }
    if GHIDRA_MODE:
        # Ghidra does not support _extension keyword
        RESERVED_TOKENS['_extension'] = '_fuckghidra_extension' # __extension, _extension_____ all fails

    for token, replaceToken in RESERVED_TOKENS.items():
        outCppContent = re.sub(r'(?<=[^A-Za-z0-9])%s(?=[;[])' % token, r'%s' % replaceToken, outCppContent)
    outCppContent = outCppContent.replace(r'(...)', r'(int, ...)')

    if GHIDRA_MODE:
        # Ghidra does not support enumclass
        outCppContent = re.sub(r'enum class ([A-z0-9_]+?) : ([a-z0-9_ ]+?) {', r'enum \1 {', outCppContent)
        outCppContent = re.sub(r'enum class ([A-z0-9_]+?) {', r'enum \1 {', outCppContent)
        # Ghidra does not support __int128
        outCppContent = outCppContent.replace(r'unsigned __int128', r'__uint128')
        # Ghidra does not support array definition in parameter
        outCppContent = outCppContent.replace(r'[],', r'*,').replace(r'[])', r'*)')

        outCppContent = ''.join(c if ord(c) < 0x80 else '_u%04X' % (ord(c)) for c in outCppContent)
    getIncStmt = lambda hdrpath: '#include "%s"' % os.path.relpath(hdrpath, Path(outCpp).absolute().parent).replace('\\', '/')
    incls = []

    incls.append(getIncStmt(ROOT_DIR / 'common.h'))
    for path in depends:
        incls.append(getIncStmt(path.replace('.h', '.cpp')))

    inclGuard = 'INCLUDE_GUARD_%s' % (re.sub('[^A-Za-z0-9_]', '_', Path(outLoc).stem))
    with open(outCpp, 'w') as f:
        f.write('#ifndef %s\n' % inclGuard
            + '#define %s\n' % inclGuard
            + '\n'.join(incls) + '\n\n' + outCppContent
            + '\n\n#endif\n'
        )

def do_clang2py(hdrLoc, outLoc, depends=()):
    print("========= Calling clang2py!")
    if not depends:
        # for base.cpp, we still have to include object in common.h
        out = subprocess.check_output(['clang2py', '--verbose', '-i', '-x', outCpp], encoding='utf-8')
    else:
        # for others, which include "XXX.cpp", we forcibly remove all included object
        out = subprocess.check_output(['clang2py', '--verbose', '-i', '-X', outCpp], encoding='utf-8')
    
    wraps, sep, defs = out.partition("_libraries = {}\n_libraries['FIXME_STUB'] = FunctionFactoryStub() #  ctypes.CDLL('FIXME_STUB')\n")
    if not defs:
        wraps, sep, defs = out.partition("    c_long_double_t = ctypes.c_ubyte*8\n")
    def_patched = defs.replace('\n', '\n    ').replace('ctypes.POINTER(ctypes.c_char)', 'ctypes.c_char_p')
    newdef = '\n\n'
    newdef += r'''

def ctypeslib_define(__defs=[]):
    oriGlobals = globals().copy()
    def recGlob():
        for k in dict(globals()):
            if not k in oriGlobals:
                globals().pop(k)
        globals().update(oriGlobals)
    globals().update(__defs)

    ret = None
    try:
        ret = _ctypeslib_define()
    except:
        recGlob()
        raise
    recGlob()
    return ret

'''
    newdef += 'def _ctypeslib_define():'
    newdef += def_patched
    newdef += '\n    return locals()'
    newdef += '\n'
    
    with open(outLoc, 'wb') as f:
        f.write((wraps + sep + newdef).encode())

def gen_ctypes(hdrLoc, outLoc, depends=()):
    gen_ctypes_cpp(hdrLoc, outLoc, depends)
    if not GHIDRA_MODE:
        do_clang2py(hdrLoc, outLoc, depends)
    else:
        print("========= Ghidra Hdr Gen finished!")

def main(args):
    if not args:
        gen_ctypes('idasdk_win/idasdk_win.h', 'idasdk_win/idasdk_win.py')
    else:
        gen_ctypes(args[0], args[1], args[2:])

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])