const testAddon = require('./build/Release/openabejs.node');



const obj = new testAddon.OpenABEjs()
const obj2 = new testAddon.OpenABEjs()

obj.generateParams()
let pub = obj.exportPublicParams()
let priv = obj.exportSecretParams()
obj2.importPublicParams(pub)
obj2.importSecretParams(priv)
let new1 = (obj.exportPublicParams())
let new2 = (obj2.exportPublicParams())
console.log(new1)
console.log(new2)
console.log(compareArrays(new1,new2))

function compareArrays(a1, a2){
  if(a1.byteLength!=a2.byteLength){
    return false
  }
  for(var i =0;i<a1.byteLength;i++){
    if(a1[i]!=a2[i]){
      return false
    }
  }
  return true
}
/*
obj.keygen("a|b","farts")
let x = obj.encrypt("a or b")
console.log(x)
let y = obj.decrypt("farts",x.ciphertext)
console.log(y)
let input = new Uint8Array(x.key)
let output = new Uint8Array(y.key)
for(let i = 0;i<input.length;i++){
  if(input[i]!=output[i]){
    console.log("ERROR")
  }
}
console.log("done")

/*
 tree = "c"
 attrs = "|a|b|"
console.log("tree", tree)
console.log("attrs",attrs)
console.log(obj.test(tree,attrs))



 tree = "(attr121) and (arr123)"
 attrs = "|attr121|attr123|c|d|"
console.log("tree", tree)
console.log("attrs",attrs)
console.log(obj.test(tree,attrs))
*/
