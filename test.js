const SecureDat = require('./secure-dat.js')

test =async ()=>{
  let x = await SecureDat.new()
  let y = await SecureDat.new()
  await x.addUser("a|b",y.params.pubDatKey)
  let result = await x.archive.readdir('/.sdat/users')
  let userdata = await x.archive.readFile(`/.sdat/users/${result[0]}`)
  console.log(userdata)
  console.log(x.params.serialize())
}
test()
