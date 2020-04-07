
//TODO: fix, should throw errors if poorly formed.
module.exports.parseAttributeList = (list)=>{
  const result = []
  const operators = ['=','<','>','>=','<=']
  let l = list.split('|')
  for (let element in l){
    if(element === ""){
      continue
    }
    let attr
    for(let operator in operators){
      if (element.includes(operator)){
        attr = (element.split(operator)[0])
        break
      }
    }
    //if no operator, trim and add.
    if(!attr){
      result.append(element.trim())
    } else {
      result.append(attr.trim)
    }
  }
  return result
}


module.exports.parseAttributeTree = (accessTree) =>{
  let items = accessTree.split(' ')
  let attributes = items.filter((item)=>{
    if(parseInt(item)==! NaN ){
      return false
    }
    if(['=','and','or','not','(',')','<','>','version','>=','<='].includes(item)){
      return false
    }
    return true
  }).map((x)=>x.trim())
  return attributes
}
