const SecureDat = require('./secure-dat.js')
const SecureParams = require('./secure-params.js')
const fs = require('fs');

test =async ()=>{
  let x = await SecureDat.new({},'x.json')
  let y = await SecureDat.new({},'y.json')
  console.log('adding user')
  await x.addUser("|a|b|",y.params.pubDatKey)
  console.log('done adding user')

  let result = await x.archive.readdir('/.sdat/users')
  let userdata = await x.archive.readFile(`/.sdat/users/${result[0]}`)
  console.log('writing file')
  await x.writeFile('/test','farts','a and b')
  console.log(await x._read('/test'))
  console.log('done writing file')



  console.log(await x._read('/test'))
  console.log(await x.readFile('/test'))
  await x.params.save()
  console.log(await SecureParams.load('x.json'))
}
test()
