# idatil2c

Convert IDA Type Library `*.til` to Compilable C Header!

## Related Project

This repo is intended to be used in other projects, enabling various C parser to directly use IDA's type library

- ida_kern_til: Convert IDA libs to Python ctypes
- ghidra_ida_til: Convert IDA til to Ghidra GDT
- ghidra_objc: Export ObjC class parsed by IDA to Ghidra

## How to Use

1. Install Node.JS (For faster RegExp) and PyPy (for faster, but CPython is also OK)
2. Export TIL content using `tilib -lc XXX.til > XXX.til.h`
3. Run script:
    - Simplest: `python3 idatil2c.py input/XXX.til.h output/XXX.til.h`
    - With dependency: `python3 idatil2c.py input/XXX.til.h output/XXX.til.h depends1.h depends2.h ...`
        - The script will exclude defined types, and convert to #include statements, so there won't duplicate types.
4. Throw them to others:
    - Ghidra: Compile to GDT
    - CtypesLib: Convert to Ctypes Wrapper

## How it works?
**BeforeAll: Everything in this script is based on RegEx, so it's highly dependent on tilib's stable output fomat**

1. Sanitize Header: (see `sanitizeHdr`) Remove ALL C++ things
    - Remove various Cpp syntax: `::` `?` `~`
    - Replace template arguments `<XXX>` using regex
    - Remove VFT
    - Remove definition that's same as depends header
        - That's round1, there'll still be forward decls to be removed
2. Parse Each Line: (see `parseDecls`) This step does not do filtering
    - Get each definition line's type class (typedef/union/enum/struct/etc.), type name
    - Removes various modifiers, so that RegEx would be easier
       ```
       '__cdecl', '__cppobj', '__unaligned', 'volatile', 
       '__declspec\([^()]+\)', '__declspec\([^()]+\([^()]+\)\)', # mssdk
       '__far', # bc5w16: IOleInPlaceActiveObject far *This
       '__attribute__(XXX)',
       ```
    - Remove comments
3. Filter Decls: (see `filterDecls`)
    - Remove blacklist types
    - Remove depends definition (round2)
        - Check if types are defined in depends: `^(struct|union|enum)( [\w\d_]+)*%s [{:]`
        - Only defs like `struct XXX {` or `struct XXX : YYY {` are accepted
4. PostProcess Decls: (see `processDecls`)
   - Handle anonymous nested structs (usually union types)
     - Example: struct XXX {union {char A; int B;};};
     - We need to extract the union to corresponding type (usually XXX::$ABCDEF12345)
   - For Clang: 
     - Convert `enum` to `enum class`: because clang doesn't like `enum XXX : int32 {`, but it likes `enum class XXX : int32 {`
   - For Ghidra: 
     - Ghidra simply can't specify enum's base type, we have to replace both `enum class XXX : YYY` and `enum XXX : YYY` to `enum XXX`
     - Ghidra does not support multi class inherit: we have to convert `struct XXX: YYY, ZZZ` into  `struct XXX { YYY __cppsuper0; ZZZ __cppsuper1; };`

5. Calculate Type Dependencies and Output: (see `outputCtypesLibCpp`)
   1. Ignore pure forward declarations (IDA's TIL ensures that a type name can only appear once, so there won't be forward decl and complete decl at same time)
   2. Compare each type to each type one by one
      - Even if it's only a O(n^2) operation, that would be too slow using Python
      - Instead, we fill all typenames into one RegEx, and uses JS to search it, then it would be a O(nlogn) operation
      - RegEx: `(?<=[ ;*(){},\[])(${Object.keys(typeDefs).join('|')})([ ;*(){},\[]+)`
   3. Check chars after typename to see whether it's pointer ref or direct ref, and check if it can be ignored
       - For struct/union they can be forward declarations, so pointer ref can be ignored.
       - If we are typedef, then typedef to struct/union can also be ignored.
   4. Replace builtin type's definition (like `typedef XXX wchar_t`) to `#define`
   5. BFS iterate all dependency pairs, and generate final output in the order of dependency

6. Final Output:
   - Replace various invalid identifiers: (Used in struct/union fields)
     - `const` `float` `register` `default`
     - (For Ghidra): `_extension`
     - `(...)` -> `(int, ...)`
   - Ghidra does not support array in method parameters (like `int XXX(char *arg1[])` )
     - Case1: `TYPNAME (*)FieldName[]`
     - Case2: `TYPNAME (*)[]`
     - Case3: `int (*methName[])(XXXXX)`
     - Actually TYPNAME can have modifiers like `unsigned`
   - Generate include statements
   - Generate macro statements (for TYPEDEF_HELPERS)