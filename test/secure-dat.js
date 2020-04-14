const test = require('tape');
const assert = require('assert')
const SecureDat = require('../secure-dat.js')
const fs = require('fs')


test('test init',async assert=>{
  assert.plan(6)
  try{
    let sdat = await SecureDat.new({},'test.json')
    assert.ok(sdat, "Ensure static new function returns valid response")
    assert.ok(sdat.params.publicParams,"Ensure  public params are not null")
    assert.ok(sdat.params.secretParams,"Ensure  secret params are not null")
    assert.ok(sdat.params.joinKey,"Ensure  joinkey is not null")
    assert.ok(sdat.params.diffiePublic,"ensure diffeis not null")
    let x = await  sdat.archive.readdir('/.sdat')
    assert.equal(x.length,4,"Ensure right number of new files")
  } catch(e){
    assert.fail(e)
    assert.end();
  }
})

test('test simple read and write to files', async assert=>{
  try{
    assert.plan(4)
    console.log("adding three dats")
    const x = await SecureDat.new({},'x.json')
    const y = await SecureDat.new({},'y.json')
    const z = await SecureDat.new({},'z.json')
    await x.addUser("|a|b|",y.params.pubDatKey)
    await x.addUser("|a|c|",z.params.pubDatKey)
    const testData = "This is some data\nthis is some more data"
    await x.writeFile('/test1.txt',testData,"a and b")
    await x.writeFile('/test2.txt',testData,"a or b")
    const x_using_y = await SecureDat.load(x.params.pubDatKey,{},y.params)
    const x_using_z = await SecureDat.load(x.params.pubDatKey,{},z.params)
    let result = await x_using_y.readFile('/test1.txt')
    assert.equals(result,testData)

    try{
      let a = await x_using_z.readFile('/test1.txt')
      assert.fail("z should not be able tor read file1")
    } catch (e) {
      assert.ok("z cannot read file1")
    }

    result = await x_using_y.readFile('/test2.txt')
    assert.equals(result, testData)
    result = await x_using_z.readFile('/test2.txt')
    assert.equals(result, testData)
  } catch (e){
    assert.fail(e)
    assert.end()

  }
})

test('test user auth and deauth', async assert=>{
  try{
    console.log("adding three dats")
    const x = await SecureDat.new({},'x.json')
    const y = await SecureDat.new({},'y.json')
    const z = await SecureDat.new({},'z.json')
    await x.addUser("|a|b|",y.params.pubDatKey)
    const testData = "This is some data\nthis is some more data"
    await x.writeFile('/test1.txt',testData,"a and b")

    const x_using_y = await SecureDat.load(x.params.pubDatKey,{},y.params)

    try{
      let x_using_z = await SecureDat.load(x.params.pubDatKey,{},z.params)
      assert.fail("z should not have access to this dat")
    } catch (e) {
      assert.ok(true)
    }
    await x.addUser("|a|b|",z.params.pubDatKey)

    // make sure dat acutally has access
    let result = await x_using_y.readFile('/test1.txt')
    assert.equals(result, testData)

    //remove access and write a new file
    await x.removeUser(y.params.pubDatKey)
    await x.writeFile('/test2.txt',testData,"a and b")
    //while y can still read test1, it cannot read test2
    try {
      await x_using_y.readFile('/test2.txt')
      assert.fail("y should no longer be able to access file from z")
    } catch (e){
      assert.ok(true)
    }
    //z should still be able to read both
    let x_using_z = await SecureDat.load(x.params.pubDatKey,{},z.params)
    result = await x_using_z.readFile('/test1.txt')
    assert.equal(result,testData)

    result = await x_using_z.readFile('/test2.txt')
    assert.equal(result,testData)

  } catch (e){
    assert.fail(e)
    assert.end()

  }
})
