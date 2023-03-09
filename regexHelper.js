const fs = require('fs');

console.log(process.argv)
typInfoFile = process.argv[2]
outDepsFile = process.argv[3]

const data = fs.readFileSync(typInfoFile, 'utf8');
//console.log(data);
typeDefs = JSON.parse(data)

regex = new RegExp(String.raw `(?<=[ ;*(){},\[])(${Object.keys(typeDefs).join('|')})([ ;*(){},\[]+)`, 'g')

outDeps = {}

for (var k in typeDefs) {
    console.log(`Calculating dependency for ${k}`)
    t = outDeps[k] = []
    for (var m of typeDefs[k].typDef.matchAll(regex)) {
        t.push([m[1], m[2]])
    }
}

out = JSON.stringify(outDeps)

fs.writeFileSync(outDepsFile, out);
