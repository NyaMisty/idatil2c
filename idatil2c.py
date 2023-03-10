# Generate inter-op wrappers of ctypes structs we used
import json
import os
import re
import subprocess
from collections import OrderedDict

import io
from json import JSONEncoder

from pathlib import Path

from tempfile import TemporaryDirectory

ROOT_DIR = Path(__file__).absolute().parent

####################################################################################
####################################################################################
###
### Part 0: Configurations
###
####################################################################################
####################################################################################

# By default, this script is adapted for clang2py from https://github.com/trolldbois/ctypeslib
# With GHIDRA environment set, this script will operate with more restriction to support Ghidra's "Parse C Source"
# See references to GHIDRA_MODE to check what's missing
GHIDRA_MODE = not(not os.getenv('GHIDRA'))

# These types are polyfill for incomplete type in TIL,
#  Only used when the corresponding types are not defined
HELPER_TYPES = [
    'bool',
    '__u32', '__u16', '__u64', '__kernel_uid32_t', '__kernel_mqd_t', # gnulnx_arm(64)
    'DOT11_DIRECTION', # mssdk
    '_DEVICE_RELATION_TYPE', # mssdk64_win10
    # 'DWORD', 'ULONG', # mscor
]

# these blacklist are names after cleanup, without ::/?/$/etc.
def parseBlackList(envName, default):
    ret = default
    env = os.getenv(envName)
    if env:
        ret = [env]
        if len(ret) == 1:
            ret = ret.split(':')
        if len(ret) == 1:
            ret = ret.split(';')
        if ret[0] == '':
            ret = default + ret
    return ret

# Things that are builtin (so you can't do `typedef XXX wchar_t;`)
#   We replace them to #define wchar_t XXXX
TYPEDEF_BUILTIN = parseBlackList('TYPEDEF_BUILTIN', [
    'wchar_t', 'short', 'int', 'char',
    '_Bool', # Ghidra
])

# Things that should NEVER outputted (can be used together with common.h)
STRUCT_BLACKLIST = parseBlackList('STRUCT_BLACKLIST', [
    '_SCHANNEL_CRED',
    '_Mbstatet', # _Mbstatet circular typedef
])
TYPEDEF_BLACKLIST = parseBlackList('TYPEDEF_BLACKLIST', [
    '_Mbstatet',
    'va_list',
])
BLACKLIST_SYMS = parseBlackList('BLACKLIST_SYMS', [
    'operator delete', 'operator delete[]', 'operator new', 'operator new[]', 'operator""s', 'operator&', 'operator+', 'operator-', 'operator<', 'operator^', 'operator|',
    ' HUGE;'
])

IDENTIFIER = r'\w\d_'
IDENTIFIER_PAT = '[%s]+' % IDENTIFIER
# Matches like: `unsigned XXX` `XXX`, non-capturing
# match logic: find TYPE_MODIFIERS, and use lookahead to ensure no more TYPE_MODIFIERS left
TYPE_MODIFIERS = ['const','unsigned']
TYPEREF_PAT = r'(?:(?:%s) )*(?!%s)%s' % ('|'.join(TYPE_MODIFIERS), '|'.join(TYPE_MODIFIERS), IDENTIFIER_PAT) #

####################################################################################
####################################################################################
###
### Part 1: Convert CPP Header to C Header
###
####################################################################################
####################################################################################

class MyEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__

# This function clears <XXX> template arg
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

    templateArgChars = r'A-z0-9_ :,\-()?*&\[\]'
    templateArg_ = r'[%s]+?' % templateArgChars
    templateArg = r'[%s]*?' % templateArgChars # optional templateArg
    templatePat = []
    def genTemplatePat(level):
        if level == 1:
            # Simplest temple arg: <XXX>
            ret = r'<(%s)>' % templateArg
            templatePat.append(ret)
        else:
            genTemplatePat(level - 1)
            # match: FirstTemplateArg ExistingNextingPat OptionalLastArg
            # Actually matches template <> with parameters number of `level`
            matchPart = r'%s%s+?%s' % (templateArg_, '(%s)' % '|'.join(templatePat), templateArg)
            ret = r'<(%s,)*?%s>' % (matchPart, matchPart)
            templatePat.append(ret)

        return
    
    # Find 9 level templates one time
    genTemplatePat(9)

    def findPatInLine(pat):
        # for debugging regex matching:
        # for l in content.splitlines():
        #     print(l)
        #     for match in re.finditer(pat, l):
        #         yield match
        for match in re.finditer(pat, content):
            yield match
    
    round = 0
    while True:
        round += 1
        print('Replacing template arg round %d' % round)

        # First find the templateArg, then replace them using cleanName'ed name
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
        replaceList.sort(key=lambda x: len(x), reverse=True)
        
        for a in replaceList[:]:
            print(a)
            content = content.replace(a, cleanName(a))
            #if 'struct_std__nested_exception_vtbl' in content:
            #    break
    return content

# Convert IDA Cpp header into C header
def sanitizeHdr(hdrContent):
    content = hdrContent
    content = ''.join(c if ord(c) < 0x80 else '_u%04X' % (ord(c)) for c in content)
    
    # Note: We do blacklist later in filterDecls to achieve more precision
    
    types, _, symbols = content.partition('\n\n')
    symbols = '\n'.join([c for c in symbols.splitlines() if '?' not in c])
    content = types + '\n\n' + symbols

    # remove vft & vtbl_layout
    content = re.sub(r'^struct /\*VFT\*/ ((.*?_vtbl) {.*?};)$', r'struct \2; /* \1*/', content, flags=re.MULTILINE)
    content = re.sub(r'^struct ((.*?_vtbl_layout) {.*?};)$', r'struct \2; /* \1*/', content, flags=re.MULTILINE)
    
    # remove IDA missing oridinal type (like `#12 *field1;`)
    content = re.sub(r'#\d+ ', 'void ', content)

    # Remove things that must be invalid
    content = content.replace('::', '__')
    content = content.replace('$', '_')
    content = content.replace('?', '_')
    content = content.replace('~', '_del_')
    content = content.replace('\nconst struct', '\nstruct')
    content = content.replace(' far *', ' *') # bc5w16: IOleInPlaceActiveObject far *This
                                                # TODO: what about `near` in common.h? Maybe unify them

    content = replaceTemplateArgs(content)

    content = re.sub(r'\nenum ([%s]+?) : __int32 ' % IDENTIFIER, '\nenum \\1 : unsigned __int32 ', content)
    
    return content

####################################################################################
####################################################################################
###
### Part 2: Parse Each Type Line, get name and typeClass(struct/union/enum/typedef)
###
####################################################################################
####################################################################################

# `tilib64 -lc XXX.til > XXX.h` generates each type definition in single line
# And between struct types and symbol types, theres an empty line ('\n\n')
# so we can simply process each struct type line by line

class TypeDecl(object):
    def __init__(self, typClass, typName, typDef):
        self.typClass = typClass
        self.typName = typName
        self.typDef = typDef
    
    def __repr__(self):
        return '<%s %s: %s>' % (self.typClass, self.typName, self.typDef)
    
    def __str__(self):
        return self.typDef

# Parses each type definition line, but does not process them
def parseDecls(types):
    type_defs = OrderedDict({})
    ignoredLines = 0

    # Helper function to ensure each type are defined only once
    def add_type(cls, t, line):
        if t in type_defs:
            print("Offending decl: %s" % type_defs[t])
        print("Got Type Def: %s" % t)
        assert not t in type_defs
        type_defs[t] = TypeDecl(cls, t, line)

    for line in types.splitlines():
        #print("Processing Line: %s" % line[:80])
        try:
            oriLine = line
            # TODO: why __attribute__ are now replaced here?
            for word in (
                    '__cdecl', '__cppobj', '__unaligned', 'volatile', 
                    '__declspec\([^()]+\)', '__declspec\([^()]+\([^()]+\)\)', # mssdk
                    '__far', # bc5w16: IOleInPlaceActiveObject far *This
                    ):
                line = re.sub(r'(^|(?<=[^%s]))%s ' % (IDENTIFIER, word), '', line)
            
            # Preprocess line for easier regex, but we still uses original line when add_type
            _line = re.sub(r'__attribute__\(.*?\) ', '', line)
            
            # ignore comment line
            if line.startswith('/*') or line.startswith('//'):
                ignoredLines += 1
                continue
            
            oriTypeLen = len(type_defs)
            # handle enum
            if _line.startswith('enum '):
                matches = re.findall(r'^enum (%s)(;| :| {)' % IDENTIFIER_PAT, _line) # `enum XXX;` appears a lot in mssdk
                if not matches: # for debug
                    print(line)
                match = matches[0][0]
                add_type('enum', match, line)
            # handle union
            elif _line.startswith('union '):
                match = re.findall(r'^union (%s)(;| {)' % IDENTIFIER_PAT, _line)[0][0]
                add_type('union', match, line)
            # handle struct
            elif _line.startswith('struct '):
                matches = []
                # Struct with inherits
                matches += re.findall(r'^struct (%s) : (%s|, )+? {' % (IDENTIFIER_PAT, IDENTIFIER_PAT), _line)
                # Simple Struct
                matches += re.findall(r'^struct (%s) {' % IDENTIFIER_PAT, _line)
                # Forward Declaration Struct
                matches += re.findall(r'^struct (%s);' % IDENTIFIER_PAT, _line)
                for m in matches:
                    if not isinstance(m, tuple):
                        m = [m]
    
                    curdef = line
                    add_type('struct', m[0], curdef)
                    
            elif _line.startswith('typedef '):
                matches = []
                # simple typedef: typedef XXX A;
                matches += re.findall(r'^typedef .*?(%s);' % IDENTIFIER_PAT, _line)
                # function call typedef: typedef A(XXX);
                matches += re.findall(r'^typedef .*?(%s)\(.*?\);' % IDENTIFIER_PAT, _line)
                # function pointer typedef: typedef (*A)(XXX);
                matches += re.findall(r'^typedef .*?(%s)\)\(.*?\);' % IDENTIFIER_PAT, _line)
                # array typedef1: typedef char A[XXX];
                matches += re.findall(r'^typedef .*?(%s)\[.*?\];' % IDENTIFIER_PAT, _line)
                # array typedef2: typedef char (*A)[XXX];
                matches += re.findall(r'^typedef .*?(%s)\)\[.*?\];' % IDENTIFIER_PAT, _line)
                if not matches:
                    print(line)
                add_type('typedef', matches[0], line)
            else:
                print(line)
                assert False, "Cannot parse line: %s" % line
            if len(type_defs) - oriTypeLen != 1:
                print(line)
                assert False, "One line should only have one type, but we defined %d types" % (len(type_defs) - oriTypeLen)
        except Exception:
            print("ErrorLine: %s" % line)
            raise
    return type_defs, ignoredLines



####################################################################################
####################################################################################
###
### Part 3: Process each type def, filter or rewrite them
###
####################################################################################
####################################################################################


def filterDecls(type_defs, depends):
    # Filter types with blacklist and dependencies
    for t in list(type_defs.keys()):
        if type_defs[t].typClass == 'typedef':
            if t in TYPEDEF_BLACKLIST:
                type_defs.pop(t)
                continue
        if type_defs[t].typClass == 'struct':
            if t in STRUCT_BLACKLIST:
                type_defs.pop(t)
                continue

    deps = '\n'.join([open(Path(c)).read() for c in depends])
    for t in list(type_defs.keys()):
        # HACK: simple regex to check if a struct defined in dependencies
        if re.search(r'^(struct|union|enum)( [\w\d_]+)*%s [{:]' % t, deps):
            type_defs.pop(t)

    return type_defs

def processDecls(type_defs):

    # handle multi level nested struct, must execute before post processing, because ghidra's super replacement will interfere this
    while True:
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

    # Does post processing here
    for typName, typInfo in type_defs.items():
        _line = typInfo.typDef

        if typInfo.typClass == 'enum':
            # clang does not like this syntax: `enum XXX : int {`
            # so we replace them to `enum class XXX : int {`
            # but then Ghidra does not like enum LOL
            _line = re.sub('^enum ', 'enum class ', _line)

        if not GHIDRA_MODE:
            pass
        else:
            if typInfo.typClass == 'struct':
                # Convert struct inherits into super field (Ghidra struct does not support inheritation)
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
            elif typInfo.typClass == 'enum':
                # Ghidra does not support enumclass
                _line = re.sub(r'enum class ([A-z0-9_]+?) : ([a-z0-9_ ]+?) {', r'enum \1 {', _line)
                _line = re.sub(r'enum class ([A-z0-9_]+?) {', r'enum \1 {', _line)
                _line = re.sub(r'^enum class ', r'enum ', _line)

        typInfo.typDef = _line

    return type_defs



####################################################################################
####################################################################################
###
### Part 4: Generate output header in dependency order to ensure success compile
###
####################################################################################
####################################################################################


FORWARD_DECL_TYPES = ('struct', 'union', )
def outputCtypesLibCpp(type_defs, symbols):
    # analyse the type hierarchy, and output a compilable header

    # sort by name first, longer name would be in the front
    type_defs_sorted = OrderedDict(sorted(type_defs.items(), key=lambda x: len(x[0]), reverse=True))

    # calculate dependencies between types
    typeDefDeps = {}
    print("Compiling all type regex...")
    if True: # JS's RegExp is 10x faster than PyPy, 50x faster than CPython...
        with TemporaryDirectory() as tmpdir:
            typDefJson = tmpdir + '/' + 'typDef.json'
            regexRetJson = tmpdir + '/' + 'regexRet.json'
            with open(typDefJson, 'w') as f:
                json.dump(type_defs, f, cls=MyEncoder)
            subprocess.check_call(['node', str(ROOT_DIR / 'regexHelper.js'), typDefJson, regexRetJson])
            with open(regexRetJson) as f:
                regexRet = json.load(f)
        def parseTypDef(typName, typDef):
            return (tuple(c) for c in regexRet[typName])

    elif False: # 2x+ Faster in both PyPy and CPython
        # Must uses look ahead here
        # Example: struct AAA {BBB field;} would only got AAA
        #      because AAA match occupys ' {', while BBB match needs the '{' in front it
        allTypeRegex = re.compile(r'(?<=[ ;*(){},\[])(%s)([ ;*(){},\[]+)' % ('|'.join(c for c in type_defs_sorted)))
        def parseTypDef(typName, typDef):
            return allTypeRegex.findall(typDef)

    for typName, typInfo in type_defs_sorted.items():
        typeDefDeps[typName] = []
        typDef = typInfo.typDef
        print("Calculating dependency for: %s" % typName)
        if typInfo.typClass == 'enum': # enum will never have dependencies
            continue

        otherTypMap = {}
        for otherTyp, typNameEnd in set(parseTypDef(typName, typDef)):
            if not otherTyp in otherTypMap:
                otherTypMap[otherTyp] = set()
            otherTypMap[otherTyp].add(typNameEnd.strip()) # strips here

        if 'JSStaticFunction' == typName:
            print(otherTypMap)
        for otherTyp in otherTypMap:
            typNameEndList = otherTypMap[otherTyp]
            if otherTyp == typName:
                continue
            #if not otherTyp in typDef:
            #    continue
            if typInfo.typClass in FORWARD_DECL_TYPES:
                # in struct we don't want field name to be checked
                # example: struct _reent; struct _reent_XXXX { YYYY *_reent; }
                # so removing pure forward decl
                if all(typNameEnd[:1] == ';' for typNameEnd in typNameEndList):
                    continue

            if True:
                # Check (XXX *A;)
                hasPointerRef = any(typNameEnd.strip()[:1] == '*' for typNameEnd in typNameEndList)
                # Check (XXX A;)
                hasDirectRef = any(typNameEnd.strip()[:1] != '*' for typNameEnd in typNameEndList)
                assert hasDirectRef or hasPointerRef

                otherTypInfo = type_defs_sorted[otherTyp]
                isDepend = True

                # typName is referencing otherTyp
                if not hasDirectRef and hasPointerRef: # is Pointer
                    if otherTypInfo.typClass in FORWARD_DECL_TYPES:
                        if typInfo.typClass in ('struct', 'union', ):
                            # ignored pointer to struct/union/typedef in struct or union
                            # example: struct XXX; struct {XXX *t;}; union {XXX *t};
                            isDepend = False
                        if typInfo.typClass == 'typedef':
                            isDepend = False
                else:
                    if typInfo.typClass == 'typedef' and otherTypInfo.typClass in FORWARD_DECL_TYPES:
                        # example: struct XXX; typedef XXX A;
                        isDepend = False
                    pass
                if isDepend:
                    typeDefDeps[typName].append(otherTyp)
                # HACK: masking cur type, but if other type share same name parts (like AAA and AAABB), this will interfere
                # Actually useless now
                typDef = typDef.replace(otherTyp, '$$$$')
                
        #print("%s -> %s" % (typName, typeDefDeps[typName]))

    # process types with more dependencies first
    typeDefDeps_sorted = OrderedDict(sorted(typeDefDeps.items(), key=lambda x: len(x[1])))

    print("Type hierarchy analysis finished:")
    for t in typeDefDeps_sorted:
        print("%s -> %s" % (t, typeDefDeps_sorted[t]))

    # Perform builtin type rewrite AFTER depencendy, then replace them into macro
    builtinDefs = {}
    for n, t in type_defs.items():
        if n in TYPEDEF_BUILTIN:
            builtinDefs[n] = t
            _m = re.findall('^typedef ([\d\w ]+) (%s)' % (n), t.typDef)
            if not _m:
                continue
            m = _m[0]
            t.typDef = '#define %s %s' % (n, m[0])  # group1

    # BFS the dependency tree, pops the known class each round
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


    # (IDA Only) Process symbols now
    symbolLines = []
    for symLine in symbols.splitlines():
        if symLine.startswith('#error '):
            continue

        if any(c in symLine for c in BLACKLIST_SYMS):
            continue

        ## TODO: Make this configurable
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
    #f.write('\n'.join( c.typDef for c in builtinDefs.values()))
    f.write('\n\n')
    # Forward declaration first (struct XXX;)
    f.write('\n'.join('%s %s;' % (t.typClass, n) for n,t in type_defs_sorted.items() if t.typClass in FORWARD_DECL_TYPES))
    f.write('\n\n')
    # Real type defs in dependency order
    f.write('\n'.join(c.typDef for c in typeLines))
    f.write('\n\n')
    # Symbols
    if not GHIDRA_MODE:
        f.write('namespace SymbolsNamespace {\n')
        f.write('\n'.join(c for c in symbolLines))
        f.write('\n\n}')
    return re.sub(r'ANTICOLLISION[0-9]*?_', '', f.getvalue())
        
def sanitizeOutput(outCppContent):
    # Final sanitization
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
        # only replaces `const[]` / `const;`, avoid replacing `const char *`
        # ' float' '*float'
        outCppContent = re.sub(r'(?<=[ *])%s(?=[;[])' % token, r'%s' % replaceToken, outCppContent)
    outCppContent = outCppContent.replace(r'(...)', r'(int, ...)')

    # replace invalid uses of bool in arm/wince.h like parameter: (XXXX bool,)
    outCppContent = re.sub(r'(%s[ *]+)bool(?=[,)])' % TYPEREF_PAT, r'\1_bool', outCppContent)

    if GHIDRA_MODE:
        # Ghidra does not support __int128
        outCppContent = outCppContent.replace(r'unsigned __int128', r'__uint128')
        # Ghidra does not support array definition in parameter
        # Case1: strange function pointer void (*_fns[32])(void);
        outCppContent = re.sub(r'(%s)\[(\d*)\]\)\(' % IDENTIFIER_PAT, r'*\1)(', outCppContent)
        # (OLD) Case2: UINT8 LinkKey[16]);
        #outCppContent = re.sub(r'(%s)\[(\d*)\]\)' % IDENTIFIER_PAT, r'*\1)', outCppContent)
        # Case2: , TYPNAME fieldName[]) , replace first to avoid be replaced by next regex
        #   Note TYPNAME can have modifiers like const/unsigned
        #   Sidecase: there will be something like `Tcl_Obj *(__cdecl *tcl_ConcatObj)(int, Tcl_Obj *const [])`
        #   Because const modifier are useless, so `*const []` equals to `**const` and `*const *`, so we decide to see const as a name identifier
        #      We simply make this regex allow spaces after name to support this case
        outCppContent = re.sub(
            r'((?<=,|\() *)'  # match a , XXX or (XXX, with optional space, can't use lookaround because ` *` match
            + r'(%s[ *]+)(%s *)' % (TYPEREF_PAT, IDENTIFIER_PAT)  # match identifier1 & 2
            + '\[\d*\]'  # match the array
            + '(\)|;|,)'  # match ending: XXX[]) or XXX[]; or XXX[],
            , r'\1\2 *    \3\4',  # replace into (, )TYPNAME *fieldName(;,)
            outCppContent)
        # Case3: , TYPNAME[])
        outCppContent = re.sub(
              r'((?<=,|\() *)' # match a , XXX or (XXX, with optional space
                            # must uses lookbehind because there will be successive matches like: `(GLdouble[3], void *[4], GLfloat[4], ...)`
            + r'(%s[ *]*)' % TYPEREF_PAT # match an identifier
            + '\[\d*\]' # match the array
            + '(\)|;|,)' # match ending: XXX[]) or XXX[]; or XXX[],
            , r'\1\2 *       \3', # replace into (, )XXX *(;,)
            outCppContent)
        # Can not assert this, because we still [XXX] in struct
        # assert not re.search(r'\[(\d*)\](,|\))', outCppContent)

    return outCppContent


####################################################################################
####################################################################################
###
### Launchers
###
####################################################################################
####################################################################################


def gen_ctypes_cpp(hdrLoc, outCpp, depends=()):
    outCpp = Path(outCpp)
    with open(hdrLoc, 'r') as f:
        content = f.read()
    
    def remove_base_types(content, depHdrs):
        oriLines = content.split('\n')
        depLines = sum([open(c).read().split('\n') for c in depHdrs], [])
        newLines = list(filter(lambda x: (x.strip() == '') or x not in depLines, oriLines))
        return '\n'.join(newLines)

    content = remove_base_types(content, depends)

    with open(outCpp, 'w') as f:
        f.write(content)

    content = sanitizeHdr(content)
    with open(outCpp, 'w') as f:
        f.write(content)
    assert '<' not in content

    # Step: Split type & symbols, then parse types
    types, _, symbols = content.partition('\n\n')
    type_defs, ignoredLines = parseDecls(types)
    assert len(type_defs) + ignoredLines == len(types.splitlines()), "All line in type defs should be successfully processed!"

    # Step: Filter black list types & handle depends
    type_defs = filterDecls(type_defs, depends)
    if 'procmod_t' in content:
        assert 'procmod_t' in type_defs # for debugging

    # Step: Preprocess type defs
    type_defs = processDecls(type_defs)
    with open(outCpp, 'w') as f: # debug
        for c in type_defs.values():
            f.write(c.typDef + '\n')
        f.write('\n')
        f.write(symbols)

    with open(str(outCpp) + '.json', 'w') as f:
        json.dump(type_defs, f, cls=MyEncoder)

    # Step: Generate Output
    outCppContent = outputCtypesLibCpp(type_defs, symbols)

    # Step: Final sanitization
    outCppContent = sanitizeOutput(outCppContent)
    
    # Step: Final output
    getIncStmt = lambda hdrpath: '#include "%s"' % os.path.relpath(hdrpath, Path(outCpp).absolute().parent).replace('\\', '/')
    incls = []

    incls.append(getIncStmt(ROOT_DIR / 'common.h'))
    # if not GHIDRA_MODE: # uses ghidra's "Use opened archive feature instead of this"
    for path in depends:
        incls.append(getIncStmt(path))

    macros = []
    for t in HELPER_TYPES:
        if t in type_defs:
            tt = type_defs[t]
            if tt.typClass in ('enum', 'union', 'struct') and '{' not in tt.typDef: # forward decl like `enum XXX;`
                continue
            macros.append('HAVETYPE_%s' % t)

    if GHIDRA_MODE:
        macros.append('GHIDRA')

    inclGuard = 'INCLUDE_GUARD_%s' % (re.sub('[^A-Za-z0-9_]', '_', Path(hdrLoc).stem))
    with open(outCpp, 'w') as f:
        # InclGuard begin
        f.write('#ifndef %s\n' % inclGuard
                + '#define %s\n' % inclGuard)
        # Includes
        f.write('\n'.join(incls))
        # Predefine macros
        for c in macros:
            f.write('#define %s\n' % c)
        # Main body
        f.write('\n\n' + outCppContent)
        # InclGuard ends
        f.write('\n\n#endif\n')

def do_clang2py(outCpp, outLoc, depends=()):
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
    outLoc = Path(outLoc)
    if not GHIDRA_MODE:
        outCpp = outLoc.parent / (outLoc.stem + ".cpp")
        gen_ctypes_cpp(hdrLoc, outCpp, depends)
        do_clang2py(hdrLoc, outLoc, depends)
    else:
        gen_ctypes_cpp(hdrLoc, outLoc, depends)
        print("========= Ghidra Hdr Gen finished!")

def main(args):
    gen_ctypes(args[0], args[1], args[2:])

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])