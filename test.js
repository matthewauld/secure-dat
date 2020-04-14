const SecureDat = require('./secure-dat.js')
const SecureParams = require('./secure-params.js')
const fs = require('fs');
const utils = require('./utils.js')
const crypto = require('crypto')
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
  //console.log(await x._read('/test'))
  console.log('done writing file')



  //console.log(await x._read('/test'))
  console.log(await x.readFile('/test'))
  await x.params.save()
  console.log(await SecureParams.load('x.json'))
  console.log("MORE TESTS")
  let z = await SecureDat.load(x.params.pubDatKey,{},'y.json')
  console.log(await z.readFile('/test'))
}
test2 = async ()=>{
  const joinKey =  await utils.genKeyPair()
  let pt = Buffer.from("fart tastic!")
  const [iv, encryptedKey, ciphertext] = await utils.hybridEncrypt(joinKey.pub,pt)
  let keyfile = `${iv.toString('base64')}\n ${encryptedKey.toString('base64')}\n${ciphertext}`
  pt2 = await utils.hybridDecrypt(keyfile, joinKey.priv)
  console.log(Buffer.from(pt2,'base64').toString('utf8'))
}

test()
