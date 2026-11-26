const cards=[...document.querySelectorAll('.task')];
const query=document.getElementById('query'),severity=document.getElementById('severity'),output=document.getElementById('visible');
function filter(){
 const q=query.value.trim().toLowerCase(),s=severity.value;
 let count=0;
 for(const card of cards){
  card.hidden=!(card.textContent.toLowerCase().includes(q)&&(s==='all'||card.dataset.severity===s));
  if(!card.hidden)count++;
 }
 output.textContent=count+' of '+cards.length+' review groups';
}
query.addEventListener('input',filter);severity.addEventListener('change',filter);
document.getElementById('expand').addEventListener('click',()=>{for(const c of cards)if(!c.hidden)c.open=true;});
document.getElementById('collapse').addEventListener('click',()=>{for(const c of cards)c.open=false;});
filter();
