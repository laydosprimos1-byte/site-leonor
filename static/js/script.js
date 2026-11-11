function aplicarTema(tema){
  document.body.classList.toggle('light', tema === 'light');
  document.querySelectorAll('.theme-toggle, .theme-toggle-inline')
    .forEach(el => el.textContent = tema === 'light' ? '☀️' : '🌙');
  localStorage.setItem('tema', tema);
}
function toggleTema(){
  const atual = localStorage.getItem('tema') || 'dark';
  aplicarTema(atual === 'dark' ? 'light' : 'dark');
}
(function(){ aplicarTema(localStorage.getItem('tema') || 'dark'); })();

document.addEventListener('click', (e)=>{
  const btn = e.target.closest('.menu-btn');
  const menu = document.querySelector('.menu-conteudo');
  if(btn && menu){ menu.classList.toggle('aberto'); e.stopPropagation(); }
  else if(menu && !e.target.closest('.menu-conteudo')) menu.classList.remove('aberto');
});

function mostrarSelecionados(input){
  const div = document.getElementById('lista-selecionados');
  if(!div) return;
  if(!input.files.length){ div.innerHTML=''; return; }
  let h = `<strong>${input.files.length} arquivo(s):</strong><br>`;
  for(let f of input.files)
    h += `📎 ${f.name} <small>(${(f.size/1024).toFixed(1)} KB)</small><br>`;
  div.innerHTML = h;
}

document.querySelectorAll('input[type="tel"]').forEach(inp=>{
  inp.addEventListener('input', ()=>{
    let v = inp.value.replace(/\D/g,'').slice(0,9);
    if(v.length>2) v = v.slice(0,2)+' '+v.slice(2,5)+' '+v.slice(5);
    inp.value = v;
  });
});
