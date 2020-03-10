const SecureDat = require('./secure-dat.js')
const fs = require('fs');

test =async ()=>{
  let x = await SecureDat.new()
  let y = await SecureDat.new()
  await x.addUser("a|b",y.params.pubDatKey)
  let result = await x.archive.readdir('/.sdat/users')
  let userdata = await x.archive.readFile(`/.sdat/users/${result[0]}`)
  await x.writeFile('/test','farts','a and b')
  console.log(await x._read('/test'))
  let stream  = fs.createReadStream('example.txt')

  await x.writeFile('/test2',stream,'a and b')

  console.log(await x._read('/test2'))

}
test()
